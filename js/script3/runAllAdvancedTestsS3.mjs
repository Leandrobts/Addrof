// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 63)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeInfoleakExploit_R63 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runInfoleakExploit_R63"; 
    logS3(`==== INICIANDO ESTRATÉGia DE EXPLORAÇÃO VIA INFOLEAK (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await runUltimateExploit();

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO!`, "good", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result.message}`, "vuln_major", FNAME_RUNNER);
        document.title = `SUCESSO!`;
    } else {
        logS3(`  RUNNER: FALHA. A cadeia de exploração falhou.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem de Erro: ${result?.error || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_ULTIMATE}: Infoleak Exploit FAIL!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runFinalBypassStrategy();
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
