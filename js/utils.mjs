// js/utils.mjs (VERSÃO FINAL - SIMPLIFICADA PARA 32 BITS)

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

/**
 * Pausa a execução por um determinado número de milissegundos.
 * @param {number} ms - O tempo de pausa em milissegundos.
 * @returns {Promise<void>}
 */
export async function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Converte um valor numérico para uma string hexadecimal formatada.
 * Otimizado para números de 32 bits.
 * @param {number} val - O valor a ser convertido.
 * @param {number} bits - O número de bits para a formatação (padrão: 32).
 * @returns {string} A string hexadecimal.
 */
export function toHex(val, bits = 32) {
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`;
    }
    if (isNaN(val)) {
        return 'ValIsNaN';
    }

    const numChars = Math.ceil(bits / 4);
    
    // O operador >>> 0 lida corretamente com a conversão de números de 32 bits, incluindo negativos.
    if (bits === 32) {
        return '0x' + (val >>> 0).toString(16).padStart(numChars, '0');
    }

    // Para outros tamanhos de bits
    let hexStr = val.toString(16);
    return '0x' + hexStr.padStart(numChars, '0');
}

// Nota: A classe AdvancedInt64 e todas as suas funções de ajuda foram removidas
// pois a estratégia de exploração atual foi otimizada para operar com números
// nativos de 32 bits, tornando a classe de 64 bits obsoleta e uma fonte de erros.
