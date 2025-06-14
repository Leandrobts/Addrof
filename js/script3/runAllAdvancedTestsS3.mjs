// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R52 - Execução de ROP)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importando a função e o nome do módulo do nosso script R52
import {
    runStableUAFPrimitives_R51 as runROPPoC_R52, // Renomeando o import para maior clareza
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

// O teste do JIT permanece o mesmo, é uma boa verificação de sanidade.
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

// ALTERADO: O runner agora chama e interpreta a nova estratégia R52 de execução de ROP.
async function runROPExecutionStrategy_R52() {
    // ALTERADO: Nome do runner para refletir a nova estratégia.
    const FNAME_RUNNER = "runROPExecutionStrategy_R52";
    logS3(`==== INICIANDO Estratégia de Execução de ROP (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // ALTERADO: Chamando a função importada com seu novo nome claro.
    const result = await runROPPoC_R52();

    if (result.errorOccurred) {
        // ALTERADO: Log para refletir o contexto R52.
        logS3(`  RUNNER R52: O teste capturou um ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: ROP FAIL!`;
    } else if (result && result.final_result) {
        const uafResult = result.final_result;
        // ALTERADO: Log para refletir o contexto R52.
        logS3(`  RUNNER R52: Módulo de execução de ROP completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R52: Mensagem: ${uafResult.message}`, uafResult.success ? "vuln" : "warn", FNAME_RUNNER);
        document.title = uafResult.success ? `${FNAME_MODULE}: ROP READY!` : `${FNAME_MODULE}: ROP PREP FAIL`;
    } else {
        logS3(`  RUNNER R52: Formato de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Execução de ROP (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // FNAME_MODULE é importado e atualizado automaticamente, então o nome do orquestrador estará correto.
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);

    await testJITBehavior();
    await PAUSE_S3(500);

    // ALTERADO: Chamando a nova função runner.
    await runROPExecutionStrategy_R52();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
