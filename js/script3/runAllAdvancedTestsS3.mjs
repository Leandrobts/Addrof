// js/script3/runAllAdvancedTestsS3.mjs (Revisão Final - Orquestrador de Bypass)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import { run_webkit_base_leak } from './FinalWebKitLeak.mjs'; 

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runFinalBypassStrategy"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE BYPASS DE ASLR ====`, 'test', FNAME_RUNNER);
    
    const result = await run_webkit_base_leak();

    if (!result || !result.success) {
        logS3(`  RUNNER: A ESTRATÉGIA DE BYPASS FALHOU.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result?.message || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `Exploit: ASLR Bypass FAIL!`;
    } else {
        logS3(`  RUNNER: BYPASS DE ASLR BEM-SUCEDIDO!`, "good", FNAME_RUNNER);
        logS3(`  > Estratégia Vencedora: ${result.strategy}`, "good", FNAME_RUNNER);
        logS3(`  > Base do WebKit Vazada: ${result.webkit_base}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! Base: ${result.webkit_base}`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ESTRATÉGIA DE BYPASS DE ASLR CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `ASLR_Bypass_Orchestrator_Final`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
