// js/script3/runAllAdvancedTestsS3.mjs (VERSÃO CORRIGIDA)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// ... (a função testJITBehavior permanece a mesma) ...
async function testJITBehavior() { /* ... */ }

// Esta é a nova função runner para a estratégia UAF
async function runUAFExploitStrategy_R50() {
    const FNAME_RUNNER = "runUAFExploitStrategy_R50"; 
    logS3(`==== INICIANDO Estratégia de Exploração UAF (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Chama o módulo de teste UAF
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43(); 
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R50: O teste principal da UAF capturou um ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: UAF Test ERR!`;
    } else if (result && result.final_result) {
        const uafResult = result.final_result;

        logS3(`  RUNNER R50: Módulo de exploração UAF completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R50: Mensagem: ${uafResult.message}`, uafResult.success ? "vuln" : "warn", FNAME_RUNNER);

        if (uafResult.success) {
            logS3(`  RUNNER R50: SUCESSO! Endereço vazado via UAF: ${uafResult.leaked_addr.toString(true)}`, "leak", FNAME_RUNNER);
            document.title = `${module_name_for_title}_R50: UAF SUCCESS!`;
        } else {
            document.title = `${module_name_for_title}_R50: UAF FAIL`;
        }
    } else {
        logS3(`  RUNNER R50: Formato de resultado inválido recebido do módulo de teste.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R50: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Exploração UAF (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

// A função principal agora chama o runner correto
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `UAF_R50_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await testJITBehavior();
    await PAUSE_S3(500);
    
    // CHAMADA CORRIGIDA AQUI
    await runUAFExploitStrategy_R50();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
