import EventEmitter from 'events';
import { WebContents } from 'electron';
export { NOTIFICATION_RECEIVED, NOTIFICATION_SERVICE_ERROR, NOTIFICATION_SERVICE_STARTED, START_NOTIFICATION_SERVICE, TOKEN_UPDATED } from './electron/consts.cjs';

interface Credentials {
    gcm: {
        androidId: string;
        securityToken: string;
    };
    keys: {
        privateKey: string;
        authSecret: string;
    };
}
interface ClientCredentials {
    gcm: {
        androidId: string;
        securityToken: string;
    };
    keys: {
        privateKey: string;
        authSecret: string;
    };
}
declare class Client extends EventEmitter {
    private _tcpSocket;
    private _credentials;
    private _persistentIds;
    private _socket;
    private _parser;
    private _retryInterval;
    static init(): Promise<void>;
    constructor(credentials: ClientCredentials, persistentIds: string[]);
    connect(): Promise<void>;
    destroy(): void;
    checkConnection(): boolean;
    private _checkIn;
    private _connect;
    private _destroy;
    private _loginBuffer;
    private _onSocketConnect;
    private _onSocketClose;
    private _onSocketError;
    private _onParserError;
    private _retry;
    private _onMessage;
    private _onDataMessage;
}

interface Notification {
    title: string;
    body: string;
    data: Record<string, string>;
}
interface CredentialsWithPersistentIds extends Credentials {
    persistentIds: string[];
}
interface NotificationCallbackParams {
    notification: Notification;
    persistentId: string;
}
declare function listen(credentials: CredentialsWithPersistentIds, notificationCallback: (params: NotificationCallbackParams) => void): Promise<Client>;

interface CheckInOptions {
    androidId: string;
    securityToken: string;
}
interface GCMRegistrationResult extends CheckInOptions {
    token: string;
    appId: string;
}

interface FCMRegistrationResult {
    keys: {
        privateKey: string;
        publicKey: string;
        authSecret: string;
    };
    fcm: {
        token: string;
    };
}

interface RegisterCredentials extends FCMRegistrationResult {
    gcm: GCMRegistrationResult;
    persistentIds?: string[];
}
interface FirebaseCredentials {
    appId: string;
    apiKey: string;
    projectId: string;
    vapidKey?: string;
}
declare function register(credentials: FirebaseCredentials): Promise<RegisterCredentials>;

declare function setup(webContents: WebContents): void;
declare function reset(): void;

export { listen, register, reset, setup };
