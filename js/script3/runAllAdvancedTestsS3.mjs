// js/script3/runAllAdvancedTestsS3.mjs (CORRIGIDO)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// CORREÇÃO: Importa a função com o nome correto ('testArbitraryRead') do módulo.
import { testArbitraryRead } from './testMemoryLeakViaJsonTC.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `MainOrchestrator_ArbitraryRead`;
    logS3(`==== INICIANDO ESTRATÉGIA DE EXPLORAÇÃO: CONSTRUÇÃO DE LEITURA ARBITRÁRIA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);

    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // CORREÇÃO: Chama a função com o nome correto.
    await testArbitraryRead();

    logS3(`\n==== ESTRATÉGIA DE EXPLORAÇÃO CONCLUÍDA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
    document.title = `ArbitraryRead: Done`;
}
