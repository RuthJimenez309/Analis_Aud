"use strict";
// src/mockData.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.mockCloudTrailLogs = void 0;
// Simulación de eventos en la nube (Actividad normal + Ataque de exfiltración)
exports.mockCloudTrailLogs = [
    // 1. Actividad legítima del administrador
    {
        eventId: "1",
        eventTime: "2026-09-01T10:00:00Z",
        eventName: "GetBucketPolicy",
        userIdentity: {
            type: "AssumedRole",
            arn: "arn:aws:iam::123456789012:role/AdminRole",
            accountId: "123456789012",
        },
        sourceIpAddress: "192.168.1.50",
        requestParameters: { bucketName: "prod-customer-data" },
    },
    // 2. ERROR IAM: Usuario de marketing intentando modificar políticas
    {
        eventId: "2",
        eventTime: "2026-09-01T10:05:00Z",
        eventName: "PutBucketPolicy",
        userIdentity: {
            type: "IAMUser",
            arn: "arn:aws:iam::123456789012:user/marketing-user",
            accountId: "123456789012",
        },
        sourceIpAddress: "203.0.113.5",
        requestParameters: {
            bucketName: "prod-customer-data",
            policy: "PublicRead",
        },
        errorCode: "AccessDenied",
    },
    // 3. ATACANTE/ANOMALÍA: Descarga masiva y rápida de archivos (Exfiltración)
    {
        eventId: "3",
        eventTime: "2026-09-01T10:10:01Z",
        eventName: "GetObject",
        userIdentity: {
            type: "IAMUser",
            arn: "arn:aws:iam::123456789012:user/app-scrapper-key",
            accountId: "123456789012",
        },
        sourceIpAddress: "198.51.100.12",
        requestParameters: {
            bucketName: "prod-customer-data",
            key: "confidential_01.pdf",
        },
    },
    {
        eventId: "4",
        eventTime: "2026-09-01T10:10:02Z",
        eventName: "GetObject",
        userIdentity: {
            type: "IAMUser",
            arn: "arn:aws:iam::123456789012:user/app-scrapper-key",
            accountId: "123456789012",
        },
        sourceIpAddress: "198.51.100.12",
        requestParameters: {
            bucketName: "prod-customer-data",
            key: "confidential_02.pdf",
        },
    },
    {
        eventId: "5",
        eventTime: "2026-09-01T10:10:03Z",
        eventName: "GetObject",
        userIdentity: {
            type: "IAMUser",
            arn: "arn:aws:iam::123456789012:user/app-scrapper-key",
            accountId: "123456789012",
        },
        sourceIpAddress: "198.51.100.12",
        requestParameters: {
            bucketName: "prod-customer-data",
            key: "confidential_03.pdf",
        },
    },
    {
        eventId: "6",
        eventTime: "2026-09-01T10:10:04Z",
        eventName: "GetObject",
        userIdentity: {
            type: "IAMUser",
            arn: "arn:aws:iam::123456789012:user/app-scrapper-key",
            accountId: "123456789012",
        },
        sourceIpAddress: "198.51.100.12",
        requestParameters: {
            bucketName: "prod-customer-data",
            key: "confidential_04.pdf",
        },
    },
];
