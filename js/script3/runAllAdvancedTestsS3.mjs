// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ReplicateV25CircularError,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ReplicateV25CircularError";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ReplicateV25CircularError(); 

    // O total_probe_calls do result será 0 devido ao reset no finally do execute...
    // O log interno do execute... já terá impresso o total real.
    
    if (result.errorOccurred) {
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
             logS3(`     RUNNER: TypeError de estrutura circular CAPTURADO NO TESTE! Isso é ESPERADO se o M2 modificado foi processado.`, "vuln");
             document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: CircularError (EXPECTED)`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: MainTest ERR - ${result.errorOccurred.name}`;
        }
    } else {
        // Este bloco só será atingido se NENHUM erro (incluindo TypeError) ocorrer no try/catch principal do execute...
        logS3(`   RUNNER: Teste completou sem erro no bloco try/catch principal.`, "good", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output (Parseado do Teste): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let logMessageForRunner = "   RUNNER: Detalhes da última sonda relevante (M2 confuso): ";
        let wasM2ConfusedAndModified = false;
        try {
            // Tentamos serializar result.toJSON_details AQUI no runner. É aqui que o TypeError pode ocorrer.
            logMessageForRunner += result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A';
            if (result.toJSON_details && result.toJSON_details.marker_id_v77 === "M2_V77_CircularTarget" &&
                result.toJSON_details.this_type === "[object Object]" && 
                result.toJSON_details.writes_on_M2_attempted) {
                wasM2ConfusedAndModified = true;
            }
        } catch (e_runner_stringify) {
            logMessageForRunner += `ERRO AO SERIALIZAR NO RUNNER: ${e_runner_stringify.name} - ${e_runner_stringify.message}`;
            if (e_runner_stringify.name === 'TypeError' && e_runner_stringify.message.includes("circular structure")) {
                logS3(`     RUNNER: TypeError de estrutura circular ao tentar logar toJSON_details! ISSO É BOM! Significa que M2 modificado foi retornado.`, "vuln");
                wasM2ConfusedAndModified = true; // Consideramos isso uma confirmação
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: CircularStruct (Runner GOOD!)`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: RunnerStringify ERR`;
            }
        }
        logS3(logMessageForRunner, wasM2ConfusedAndModified ? "good" : "warn", FNAME_RUNNER);

        if (result.addrof_A_result) { // As chaves de addrof foram removidas de v77, isso não será logado.
             logS3(`     ADDROF A (do objeto M2): ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        
        if (wasM2ConfusedAndModified && !document.title.includes("CircularStruct (Runner GOOD!)")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: M2 TC&Write OK`;
        } else if (!wasM2ConfusedAndModified && !document.title.includes("ERR")) {
             document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: No M2 TC?`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Fail") && // Addr Fail é um estado válido
            !document.title.includes("ERR") && !document.title.includes("TC") && // TC OK, CircularStruct são estados válidos
            !document.title.includes("No M2 TC?")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE} Concluído`;
        }
    }
}
