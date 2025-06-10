// js/script3/testJsonRecursionCrash.mjs

import { logS3 } from './s3_utils.mjs';

export const FNAME_MODULE = "JsonRecursionCrash_v1";

// --- Variáveis de escopo para serem acessíveis pela sonda toJSON ---
let testObject = null;
let callCount = 0;
let originalToJSON_Descriptor = null;
const ppKey = 'toJSON';

// --- Sonda toJSON ---
// Esta função é o coração do teste. Ela será chamada repetidamente por JSON.stringify.
function toJSON_Probe() {
    callCount++;
    const logPrefix = `toJSON_Probe (Call ${callCount})`;

    // Tenta identificar o 'this' para logging
    let thisIdentifier = "unknown";
    if (this === testObject) thisIdentifier = "ROOT_OBJECT";
    else if (Array.isArray(this)) thisIdentifier = "ARRAY";
    else if (this && typeof this === 'object' && this.hasOwnProperty('payload_keys')) thisIdentifier = "PREV_RETURN_OBJ";

    // Loga no console do navegador (mais rápido e confiável em caso de crash)
    console.log(`%c${logPrefix}: Invocada! id='${thisIdentifier}', typeof='${typeof this}', constructor='${this && this.constructor ? this.constructor.name : 'N/A'}'`, "background: #222; color: #bada55");

    // PONTO CRÍTICO: Tenta executar Object.keys em 'this'
    let keys = [];
    try {
        keys = Object.keys(this);
        console.log(`%c${logPrefix}: Object.keys(this) SUCESSO para id='${thisIdentifier}'. Chaves: [${keys.join(',')}]`, "color:lime");

        // O retorno que causa a recursão problemática.
        // Empacota as chaves em um novo objeto, que será processado pelo JSON.stringify,
        // acionando a sonda novamente com 'this' sendo o array de chaves.
        return {
            "payload_keys": keys
        };
    } catch (e) {
        console.error(`${logPrefix}: ERRO em Object.keys(this) para id='${thisIdentifier}':`, e);
        return { "error_in_probe": String(e.message) };
    }
}

// --- Funções de Setup e Cleanup ---
function setupPrototypePollution() {
    callCount = 0;
    originalToJSON_Descriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    Object.defineProperty(Object.prototype, ppKey, {
        value: toJSON_Probe,
        writable: true, configurable: true, enumerable: false
    });
    logS3("Poluição Object.prototype.toJSON APLICADA (com recursão de Object.keys).", 'good', 'setup');
}

function cleanupPrototypePollution() {
    if (originalToJSON_Descriptor) {
        Object.defineProperty(Object.prototype, ppKey, originalToJSON_Descriptor);
    } else {
        delete Object.prototype[ppKey];
    }
    logS3("Object.prototype.toJSON restaurado.", 'good', 'cleanup');
}


// --- Função Principal do Teste ---
export async function executeJsonRecursionCrashTest() {
    const FNAME_TEST = `${FNAME_MODULE}.execute`;
    logS3(`--- Iniciando ${FNAME_TEST}: Tentativa de acionar crash por recursão no JSON.stringify ---`, "test", FNAME_TEST);

    // Objeto de teste simples. A manipulação de suas chaves é o próximo passo.
    testObject = {
        p1: "alpha",
        p2: "beta",
        p3: { nested: true }
    };

    let result = {
        completed: false,
        error: null,
        message: "Teste iniciado. Se o navegador travar, este será o último estado."
    };

    setupPrototypePollution();
    logS3("Tentando JSON.stringify... O navegador pode travar ou ficar lento agora.", 'critical', FNAME_TEST);

    try {
        // Esta é a chamada que deve acionar o bug
        JSON.stringify(testObject);

        // Se o código chegar aqui, o crash não ocorreu como esperado.
        result.completed = true;
        result.message = "JSON.stringify completou sem erros ou travamento (inesperado!). O bug não foi acionado.";
        logS3(result.message, 'warn', FNAME_TEST);

    } catch (e) {
        // Captura erros explícitos como "Maximum call stack size exceeded"
        result.error = e.message;
        result.message = `JSON.stringify capturou um erro: ${e.message}`;
        logS3(result.message, 'error', FNAME_TEST);
        console.error("ERRO CAPTURADO:", e);
    } finally {
        // Este bloco será executado mesmo se o script parar, mas não se o navegador travar completamente.
        logS3("Bloco 'finally' alcançado. Limpando poluição do protótipo.", 'info', FNAME_TEST);
        cleanupPrototypePollution();
    }

    return result;
}
