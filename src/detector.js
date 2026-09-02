"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// src/detector.ts
const mockData_1 = require("./mockData");
const SECURITY_THRESHOLDS = {
    MAX_DOWNLOADS_PER_MINUTE: 3,
    SUSPICIOUS_IPS: ["198.51.100.12"],
};
class CloudSecurityEngine {
    userRequestTracker = new Map();
    analyzeLogs(logs) {
        console.log("🛡️ [CloudGuard] Iniciando análisis de logs de AWS CloudTrail...\n");
        logs.forEach((log) => {
            this.inspectIAMErrors(log);
            this.detectThreatIntelligenceMatches(log);
            this.detectDataExfiltration(log);
        });
    }
    inspectIAMErrors(log) {
        if (log.errorCode === "AccessDenied" &&
            log.eventName === "PutBucketPolicy") {
            console.error(`🚨 [ALERTA IAM] Intento no autorizado de modificar políticas de S3!`);
            console.error(`   - Usuario: ${log.userIdentity.arn}`);
            console.error(`   - S3 Bucket: ${log.requestParameters.bucketName}`);
            console.error(`   - IP Origen: ${log.sourceIpAddress}\n`);
        }
    }
    detectThreatIntelligenceMatches(log) {
        if (SECURITY_THRESHOLDS.SUSPICIOUS_IPS.includes(log.sourceIpAddress)) {
            console.warn(`⚠️ [THREAT INTEL] Tráfico detectado desde IP maliciosa conocida: ${log.sourceIpAddress}`);
            console.warn(`   - Acción: ${log.eventName} por ${log.userIdentity.arn}\n`);
        }
    }
    detectDataExfiltration(log) {
        if (log.eventName !== "GetObject")
            return;
        const userArn = log.userIdentity.arn;
        const timestamp = new Date(log.eventTime).getTime();
        if (!this.userRequestTracker.has(userArn)) {
            this.userRequestTracker.set(userArn, []);
        }
        const timestamps = this.userRequestTracker.get(userArn);
        timestamps.push(timestamp);
        const oneMinuteAgo = timestamp - 60000;
        const recentRequests = timestamps.filter((t) => t > oneMinuteAgo);
        this.userRequestTracker.set(userArn, recentRequests);
        if (recentRequests.length > SECURITY_THRESHOLDS.MAX_DOWNLOADS_PER_MINUTE) {
            console.error(`🔥 [CRÍTICO] ¡Detección de Exfiltración de Datos en S3!`);
            console.error(`   - Identidad comprometida (IAM): ${userArn}`);
            console.error(`   - Razón: ${recentRequests.length} descargas en menos de un minuto.`);
            console.error(`   - Acción de Mitigación Recomendada: Revocar temporalmente las credenciales IAM del usuario.\n`);
        }
    }
}
const engine = new CloudSecurityEngine();
engine.analyzeLogs(mockData_1.mockCloudTrailLogs);
