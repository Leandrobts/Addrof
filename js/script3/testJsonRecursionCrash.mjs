// NOME DO ARQUIVO: testJsonRecursionCrash.mjs

export const FNAME_MODULE_JSON_RECURSION = "JsonStringifyRecursionCrash_v1";

// --- Variáveis de Estado Globais para o Teste ---
// Usamos variáveis globais para que seus valores possam ser inspecionados
// mesmo que a execução principal seja interrompida por um crash.
let callCount = 0;
let testObjectRef = null;
let lastThisBeforeCrash = null;

/**
 * Sonda toJSON projetada para causar a recursão que leva ao bug.
 * Ela chama Object.keys() em CADA 'this' que encontra e re-empacota
 * o resultado em um novo objeto, alimentando o ciclo.
 */
function recursiveObjectKeysProbe() {
    callCount++;
    lastThisBeforeCrash = this; // Salva a referência ao 'this' atual a cada chamada

    const thisIdentifier = this === testObjectRef ? "ROOT_OBJECT" : (Array.isArray(this) ? "ARRAY" : "NESTED_OBJECT");

    // Log intensivo no CONSOLE, que é mais rápido que atualizar a DIV.
    console.log(`%c[toJSON_Probe] Chamada #${callCount}: 'this' é ${thisIdentifier}`, "color: darkviolet");

    try {
        // PONTO CRÍTICO: Executar Object.keys() em 'this'
        const keys = Object.keys(this);
        console.log(`%c[toJSON_Probe]   ↳ Sucesso em Object.keys(). Chaves: [${keys.join(',')}]`, "color: limegreen");

        // O RETORNO PROBLEMÁTICO: re-empacota o array de chaves em um novo objeto.
        // O JSON.stringify tentará serializar este novo objeto, chamando a sonda
        // novamente no array 'keys', causando a recursão.
        return {
            note: `Resultado da chamada ${callCount}`,
            keys_payload: keys
        };
    } catch (e) {
        console.error(`[toJSON_Probe] ERRO em Object.keys(this) para ${thisIdentifier}:`, e);
        return { "error_in_probe": e.message };
    }
}

/**
 * Função principal que executa a tentativa de crash.
 */
export async function executeJsonRecursionTest() {
    const FNAME_TEST = `${FNAME_MODULE_JSON_RECURSION}.execute`;
    console.log(`--- Iniciando ${FNAME_TEST} ---`);

    // Reseta o estado para cada execução
    callCount = 0;
    testObjectRef = { a_level1: 1, b_level1: "bee" }; // Objeto de teste simples
    lastThisBeforeCrash = null;

    let resultSummary = {
        didComplete: false,
        errorCaptured: null,
        finalCallCount: 0
    };

    const ppKey = 'toJSON';
    const originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

    try {
        // PASSO 1: Poluir o protótipo com nossa sonda recursiva
        Object.defineProperty(Object.prototype, ppKey, {
            value: recursiveObjectKeysProbe,
            writable: true, configurable: true, enumerable: false
        });
        console.log(`[${FNAME_TEST}] Object.prototype.toJSON poluído com a sonda recursiva.`);

        // PASSO 2: Chamar JSON.stringify (ponto esperado do crash/lentidão)
        console.warn(`[${FNAME_TEST}] PRESTES A CHAMAR JSON.stringify. O NAVEGADOR PODE TRAVAR OU FICAR LENTO.`);
        JSON.stringify(testObjectRef);

        // Se o código chegar aqui, significa que não houve crash, o que é inesperado.
        resultSummary.didComplete = true;
        console.log(`[${FNAME_TEST}] INESPERADO: JSON.stringify completou sem erros.`);

    } catch (e) {
        // Captura erros de script, como "Maximum call stack size exceeded"
        console.error(`[${FNAME_TEST}] ERRO CAPTURADO PELO TRY/CATCH: ${e.name} - ${e.message}`);
        resultSummary.errorCaptured = e.message;
    } finally {
        // PASSO 3: Limpeza e diagnóstico final.
        // Este bloco DEVE executar, mesmo que a aba esteja travando.
        console.warn(`[${FNAME_TEST}] Entrou no bloco FINALLY.`);
        console.log(`%c[DIAGNÓSTICO FINAL] Profundidade da recursão atingida: ${callCount} chamadas.`, "background: #333; color: #f0f;");
        console.log("%c[DIAGNÓSTICO FINAL] O último 'this' processado antes do problema foi:", "background: #333; color: #f0f;");
        console.dir(lastThisBeforeCrash); // 'console.dir' é ótimo para inspecionar objetos.

        resultSummary.finalCallCount = callCount;

        // Restaura o protótipo para o estado original
        if (originalToJSONDescriptor) {
            Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
        } else {
            delete Object.prototype[ppKey];
        }
        console.log(`[${FNAME_TEST}] Object.prototype.toJSON restaurado.`);
    }

    return resultSummary;
}
