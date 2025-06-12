// js/script3/testAdvancedPP.mjs
// ATUALIZADO PARA TESTES MASSIVOS DE STRESS FOCADOS NO GADGET 'CALL'

import { logS3, PAUSE_S3 } from './s3_utils.mjs';

const STRESS_ITERATIONS = 50000; // Aumente para 100.000 ou mais para testes mais intensos

/**
 * STRESS TEST 1: Hijack de 'call' com rápida alocação/desalocação de objetos.
 * Objetivo: Tentar causar um Use-After-Free (UAF) no Garbage Collector.
 */
async function stressTest_CallHijack_With_GC_Churn() {
    const FNAME = 'StressTest_GC_UAF';
    logS3(`--- Stress Test 1: Hijack de 'call' + Churn de Objetos (Tentativa de UAF) ---`, 'test', FNAME);
    logS3(`Iterações: ${STRESS_ITERATIONS}`, 'info', FNAME);
    const originalCallDescriptor = Object.getOwnPropertyDescriptor(Function.prototype, 'call');
    let callCount = 0;

    try {
        const hijackFunction = function() { callCount++; };
        Object.defineProperty(Function.prototype, 'call', { value: hijackFunction, configurable: true });

        logS3("Iniciando loop de alocação/desalocação massiva...", 'warn', FNAME);
        for (let i = 0; i < STRESS_ITERATIONS; i++) {
            let tempObj = { data: new Array(100).fill(i) };
            // Chama uma função no objeto, acionando nosso 'call' sequestrado.
            Object.keys.call(tempObj);
            // Ao final do loop, tempObj se torna elegível para o GC.
            if (i % 10000 === 0) {
                 logS3(`Progresso: ${i}/${STRESS_ITERATIONS}... Chamadas sequestradas: ${callCount}`, 'info', FNAME);
                 await PAUSE_S3(10); // Permite que a UI respire um pouco
            }
        }
        logS3("Loop concluído.", 'good', FNAME);

    } catch (e) {
        logS3(`ERRO durante o Stress Test 1: ${e.message}`, 'error', FNAME);
    } finally {
        logS3("Limpando e restaurando 'call'...", 'info', FNAME);
        if (originalCallDescriptor) {
            Object.defineProperty(Function.prototype, 'call', originalCallDescriptor);
        }
        logS3(`Total de chamadas sequestradas: ${callCount}`, 'info', FNAME);
    }
}

/**
 * STRESS TEST 2: Hijack de 'call' com APIs de DOM complexas.
 * Objetivo: Tentar causar um crash na fronteira entre JavaScript e o código nativo do navegador.
 */
async function stressTest_CallHijack_With_DOM_APIs() {
    const FNAME = 'StressTest_DOM_API';
    logS3(`--- Stress Test 2: Hijack de 'call' + Stress de APIs DOM ---`, 'test', FNAME);
    const originalCallDescriptor = Object.getOwnPropertyDescriptor(Function.prototype, 'call');
    const container = document.createElement('div');
    document.body.appendChild(container);
    let callCount = 0;

    try {
        const hijackFunction = () => { callCount++; };
        Object.defineProperty(Function.prototype, 'call', { value: hijackFunction, configurable: true });
        
        logS3("Iniciando loop de criação/destruição de elementos DOM...", 'warn', FNAME);
        for (let i = 0; i < 500; i++) { // Menos iterações, pois DOM é mais lento
            let el = document.createElement('iframe');
            el.src = "about:blank";
            container.appendChild(el);
            // Força o navegador a processar e talvez chamar callbacks internos
            el.getBoundingClientRect.call(el);
            container.removeChild(el);

             if (i % 100 === 0) {
                 logS3(`Progresso DOM: ${i}/500...`, 'info', FNAME);
                 await PAUSE_S3(10);
            }
        }
        logS3("Loop DOM concluído.", 'good', FNAME);

    } catch (e) {
        logS3(`ERRO durante o Stress Test 2: ${e.message}`, 'error', FNAME);
    } finally {
        logS3("Limpando e restaurando 'call'...", 'info', FNAME);
        document.body.removeChild(container);
        if (originalCallDescriptor) {
            Object.defineProperty(Function.prototype, 'call', originalCallDescriptor);
        }
    }
}


/**
 * Função principal que orquestra a execução dos Testes Massivos de Stress.
 */
export async function runMassiveStressTests() {
    await stressTest_CallHijack_With_GC_Churn();
    await PAUSE_S3(2000); // Pausa longa para o GC estabilizar
    await stressTest_CallHijack_With_DOM_APIs();
}
