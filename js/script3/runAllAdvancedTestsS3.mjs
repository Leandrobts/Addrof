// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 57 - Chamador do Ataque JIT)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// CORREÇÃO DEFINITIVA: Importando o nome exato da função do nosso script R57.
import {
    FNAME_MODULE,
    runExploitChain_JIT_Attack // Corrigido para o nome correto da função exportada.
} from './UltimateExploit.mjs';

// Função de teste do JIT como sanity check.
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    // ... (código da função sem alterações)
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let some_obj = { a: 1, b: 2 };
    float_view[0] = some_obj;
    if (new Uint32Array(test_buf)[1] === 0x7ff80000) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN.", 'warn', 'testJITBehavior');
    }
}

// O runner agora chama a função correta do exploit.
async function runJITAttackStrategy() {
    const FNAME_RUNNER = "runJITAttackStrategy (R57)"; 
    logS3(`==== INICIANDO ESTRATÉGIA FINAL (${FNAME_MODULE}) ====`, 'test', FNAME_RUNNER);
    
    // CORREÇÃO DEFINITIVA: Chamando a função com o nome correto.
    const result = await runExploitChain_JIT_Attack();

    if (result && result.success) {
        logS3(`  RUNNER: ATAQUE AO JIT BEM-SUCEDIDO!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER: Mensagem: ${result.message}`, "good", FNAME_RUNNER);
        document.title = "JIT PWNED by " + FNAME_MODULE;
    } else {
        const errorMsg = result ? result.message : "Resultado indefinido do exploit.";
        logS3(`  RUNNER: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = FNAME_MODULE + ": FAIL";
    }

    logS3(`==== ESTRATÉGIA FINAL (${FNAME_MODULE}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;

    await testJITBehavior();
    await PAUSE_S3(500);
    
    await runJITAttackStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
