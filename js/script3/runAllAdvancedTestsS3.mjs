// js/script3/runAllAdvancedTestsS3.mjs (Runner para R56 - Autoverificação de Leitura/Escrita OOB)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R56 as executeTest,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runStrategy_OOBSelfTest_R56() {
    const FNAME_RUNNER = "runStrategy_OOBSelfTest_R56";
    logS3(`==== INICIANDO Estratégia (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTest();
    const module_name_for_title = FNAME_MODULE;

    if (!result) {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R56(SelfTest): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
        return;
    }

    if (result.self_test_success) {
        logS3(`  --- SUCESSO! ---`, "success_major", FNAME_RUNNER);
        logS3(`    Autoverificação da primitiva de Leitura/Escrita OOB: BEM-SUCEDIDA.`, "good", FNAME_RUNNER);
        logS3(`    Notas: ${result.notes}`, "info", FNAME_RUNNER);
        logS3(`    Próximo passo: Usar esta primitiva R/W confiável para construir addrof e fakeobj.`, "info_emphasis", FNAME_RUNNER);
        document.title = "Primitiva R/W OOB Confirmada!";
    } else {
        logS3(`  --- FALHA NO TESTE ---`, "critical", FNAME_RUNNER);
        logS3(`    Erro reportado: ${result.errorOccurred || 'Erro desconhecido'}`, "error", FNAME_RUNNER);
        logS3(`    A primitiva de Leitura/Escrita OOB não é confiável.`, "warn", FNAME_RUNNER);
        document.title = "Falha no Autoteste da Primitiva R/W";
    }

    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R56_OOBSelfTest (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStrategy_OOBSelfTest_R56();
    
    logS3(`\n==== Script 3 R56_OOBSelfTest (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
