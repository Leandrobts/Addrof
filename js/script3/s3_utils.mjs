// js/script3/s3_utils.mjs (R37)

import { logToDiv } from '../logger.mjs';
// <<<< R37: Importar PAUSE diretamente de utils.mjs >>>>
import { PAUSE } from '../utils.mjs'; 

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

// <<<< R37: PAUSE_S3 agora usa diretamente a função PAUSE importada de utils.mjs >>>>
export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => PAUSE(ms);
