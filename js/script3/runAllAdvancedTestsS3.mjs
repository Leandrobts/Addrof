// js/script3/runAllAdvancedTestsS3.mjs (Final - Orquestrador para o Ataque UAF)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    // ATUALIZADO: Importa a nova função e seu nome de módulo
    executeChainedUAF_R59 as runUltimateExploit, // Renomeado para executeChainedUAF_R59
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

/**
 * Executa a estratégia principal do teste UAF encadeado.
 */
async function runFinalUAFStrategy() {
    const FNAME_RUNNER = "runFinalUAFStrategy";
    const moduleName = FNAME_MODULE_ULTIMATE || 'ChainedUAF_Attack';
    logS3(`==== INICIANDO Estratégia Final (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let result;
    try {
        result = await runUltimateExploit();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        result = { errorOccurred: { name: e.name, message: e.message } };
    }

    if (result && result.success) {
        logS3(`==== SUCESSO PARCIAL DETECTADO: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `${moduleName}: Partial Success!`;
    } else if (result && result.errorOccurred) {
        logS3(`==== ERRO CAPTURADO: ${result.error || result.errorOccurred.message}`, "error", FNAME_RUNNER);
        document.title = `${moduleName}: JS Error!`;
    } else {
        logS3(`==== TESTE CONCLUÍDO SEM CRASH. O navegador parece seguro contra este vetor de ataque.====`, "good", FNAME_RUNNER);
        document.title = `${moduleName}: No Crash Detected.`;
    }
    
    logS3(`O resultado ideal deste teste é um CRASH. Verifique se o navegador fechou inesperadamente.`, "info_major", FNAME_RUNNER);
}

/**
 * Função principal que inicializa e executa os testes
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `UltimateExploit_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalUAFStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
}
