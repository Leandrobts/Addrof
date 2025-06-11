// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeArrayBufferVictimCrashTest, // O nome da função exportada é mantido
    FNAME_MODULE_V28 
} from './final_exploit_chain.mjs'; // APONTA PARA O NOVO ARQUIVO DE EXPLORAÇÃO

async function runHeisenbugReproStrategy_ABVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_ABVictim";
    const moduleName = FNAME_MODULE_V28 || 'FinalExploitChain';
    logS3(`==== INICIANDO Estratégia de Teste (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let result;
    try {
        result = await executeArrayBufferVictimCrashTest();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        result = { arb_read_success: false, message: e.message };
    }
    
    let finalLogMessage = result.message;
    let finalLogType = "info";
    let finalDocumentTitle = `${moduleName} Concluído`;

    if (result.arb_read_success) {
        finalLogType = "vuln";
        finalDocumentTitle = `${moduleName}: SUCESSO TOTAL!`;
    } else if (result.addrof) {
        finalLogType = "warn";
        finalDocumentTitle = `${moduleName}: Addrof OK, Read Fail`;
    } else {
        finalLogType = "error";
        finalDocumentTitle = `${moduleName}: FALHA`;
    }

    logS3(`==== RESULTADO FINAL (${moduleName}): ${finalLogMessage}`, finalLogType, FNAME_RUNNER);
    document.title = finalDocumentTitle;
    logS3(`==== Estratégia de Teste (${moduleName}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export function initializeAdvancedTestRunner() {
    const FNAME_ORCHESTRATOR = `AdvancedTestOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    if (!runBtn) return;

    runBtn.addEventListener('click', async () => {
        if (runBtn.disabled) return;
        
        const outputDiv = getOutputAdvancedS3();
        runBtn.disabled = true;
        if (outputDiv) outputDiv.innerHTML = '';
        
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
        await runHeisenbugReproStrategy_ABVictim();
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        
        runBtn.disabled = false;
    });

    logS3("Runner de Testes Avançados pronto.", "info", FNAME_ORCHESTRATOR);
}

// Inicializa o runner automaticamente se desejado, ou chame de main.mjs
// initializeAdvancedTestRunner();
