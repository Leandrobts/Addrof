// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 59)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// CORREÇÃO: Importando o nome exato da função do nosso script R59.
import {
    FNAME_MODULE,
    runExploitChain_Absolute 
} from './UltimateExploit.mjs';

async function testJITBehavior() { /* ...código sem alterações... */ }

async function runFinalOffensiveStrategy() {
    const FNAME_RUNNER = "runFinalOffensiveStrategy (R59)"; 
    logS3(`==== INICIANDO ESTRATÉGIA FINAL (${FNAME_MODULE}) ====`, 'test', FNAME_RUNNER);
    
    // CORREÇÃO: Chamando a nova função principal com a lógica corrigida.
    const result = await runExploitChain_Absolute();

    if (result && result.success) {
        logS3(`  RUNNER: CADEIA DE EXPLORAÇÃO BEM-SUCEDIDA!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER: Mensagem: ${result.message}`, "good", FNAME_RUNNER);
        document.title = "PWNED by " + FNAME_MODULE;
    } else {
        const errorMsg = result ? result.message : "Resultado indefinido do exploit.";
        logS3(`  RUNNER: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = FNAME_MODULE + ": Defenses Held";
    }

    logS3(`==== ESTRATÉGIA FINAL (${FNAME_MODULE}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;
    
    // Removido o teste JIT para focar puramente na execução do exploit principal.
    // await testJITBehavior(); 
    // await PAUSE_S3(500);
    
    await runFinalOffensiveStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
