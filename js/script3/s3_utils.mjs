// js/script3/s3_utils.mjs (R36)

import { logToDiv } from '../logger.mjs';
// <<<< R36: Importar genericPause_R36 de utils.mjs >>>>
import { genericPause_R36 } from '../utils.mjs'; 

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

// <<<< R36: PAUSE_S3 agora usa a genericPause_R36 importada >>>>
export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause_R36(ms);
