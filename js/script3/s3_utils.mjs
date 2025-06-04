// js/script3/s3_utils.mjs (R35)

import { logToDiv } from '../logger.mjs';
// <<<< CORRIGIDO: Importar PAUSE_S3 diretamente >>>>
import { PAUSE_S3 as genericPause } from '../utils.mjs'; // Importa PAUSE_S3 como genericPause

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

// PAUSE_S3 em s3_utils.mjs agora usa o genericPause (que é o PAUSE_S3 de utils.mjs)
export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause(ms);
