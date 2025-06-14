// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R52 - Carga Útil Final)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importando a nova função e o nome do módulo
import {
    runFullExploitChain_R52,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

// O teste do JIT permanece o mesmo
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    if (float_view) {
      float_view[0] = { a: 1, b: 2 };
      const uint32_view = new Uint32Array(test_buf);
      const high = uint32_view[1];
      if (high === 0x7ff80000) {
          logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
      } else {
          logS3("INESPERADO: O JIT não converteu para NaN.", 'warn', 'testJITBehavior');
      }
    }
}

// O runner agora chama e interpreta a cadeia de exploração completa R52
async function runFullExploitStrategy_R52() {
    const FNAME_RUNNER = "runFullExploitStrategy_R52";
    logS3(`==== INICIANDO Estratégia de Exploração Completa (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await runFullExploitChain_R52();

    if (result && result.success) {
        logS3(`  RUNNER R52: CADEIA DE EXPLORAÇÃO BEM-SUCEDIDA!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R52: Mensagem: ${result.message}`, "good", FNAME_RUNNER);
        document.title = "PWNED!";
    } else {
        const errorMsg = result ? result.errorOccurred : "Resultado indefinido do exploit.";
        logS3(`  RUNNER R52: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: FAIL`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Exploração Completa (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);

    await testJITBehavior();
    await PAUSE_S3(500);

    await runFullExploitStrategy_R52();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
