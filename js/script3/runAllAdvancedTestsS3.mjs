// js/script3/runAllAdvancedTestsS3.mjs (Atualizado para chamar o teste combinado)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeCombinedAnalysis, // <-- Importa a nova função de teste
    FNAME_MODULE_V29         // <-- Importa o novo nome do módulo
} from './testCombinedAnalysis.mjs'; // <-- Importa do novo arquivo de teste

async function runMainTestStrategy() {
    const FNAME_RUNNER = "runMainTestStrategy";
    logS3(`==== INICIANDO ESTRATÉGIA DE ANÁLISE COMBINADA ====`, 'test', FNAME_RUNNER);

    // Chama a nova função de teste unificada
    await executeCombinedAnalysis();

    logS3(`==== ESTRATÉGIA DE ANÁLISE COMBINADA CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V29}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Análise e Dissecação de Objeto com Tipo Confuso ====`, 'test', FNAME_ORCHESTRATOR);

    await runMainTestStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
