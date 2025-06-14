// js/script3/runAllAdvancedTestsS3.mjs (Orquestrador para teste de primitivas)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeAddrofAndFakeObjTest } from './testArrayBufferVictimCrash.mjs';

// Função auxiliar simples para o teste de JIT, pode ser mantida.
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    // ... (lógica do teste de JIT pode ser mantida como antes)
    logS3("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}

// Função principal do orquestrador
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `AddrofFakeobj_Test_Orchestrator`;
    logS3(`==== INICIANDO ${FNAME_ORCHESTRATOR} ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    // await testJITBehavior(); // Pode ser descomentado se necessário
    await PAUSE_S3(500);

    // Chama a nova função de teste focada nas primitivas
    const result = await executeAddrofAndFakeObjTest();

    if (result.success) {
        logS3(`Resultado Final: SUCESSO. Primitivas prontas para o próximo estágio.`, "good", FNAME_ORCHESTRATOR);
    } else {
        logS3(`Resultado Final: FALHA. ${result.errorOccurred}`, "critical", FNAME_ORCHESTRATOR);
    }

    logS3(`\n==== ${FNAME_ORCHESTRATOR} CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
