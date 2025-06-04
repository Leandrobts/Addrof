// js/script3/s3_utils.mjs (R32)

import { logToDiv } from '../logger.mjs';
// CORRIGIDO: Importa PAUSE_S3 de utils.mjs e usa o alias genericPause
import { PAUSE_S3 as genericPause } from '../utils.mjs'; 

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause(ms);
