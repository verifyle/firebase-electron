import {
  NOTIFICATION_RECEIVED,
  NOTIFICATION_SERVICE_ERROR,
  NOTIFICATION_SERVICE_STARTED,
  START_NOTIFICATION_SERVICE,
  TOKEN_UPDATED
} from "./chunk-YV7TGR5W.js";

// src/core/client.ts
import EventEmitter2 from "events";
import Long2 from "long";
import path3 from "path";
import tls from "tls";
import protobuf3 from "protobufjs";

// src/core/gcm/index.ts
import Long from "long";
import path from "path";
import protobuf from "protobufjs";
import request from "request-promise";

// src/core/fcm/server-key.ts
var serverKey = [
  4,
  51,
  148,
  247,
  223,
  161,
  235,
  177,
  220,
  3,
  162,
  94,
  21,
  113,
  219,
  72,
  211,
  46,
  237,
  237,
  178,
  52,
  219,
  183,
  71,
  58,
  12,
  143,
  196,
  204,
  225,
  111,
  60,
  140,
  132,
  223,
  171,
  182,
  102,
  62,
  242,
  12,
  212,
  139,
  254,
  227,
  249,
  118,
  47,
  20,
  28,
  99,
  8,
  106,
  111,
  45,
  177,
  26,
  149,
  176,
  206,
  55,
  192,
  156,
  110
];
var server_key_default = serverKey;

// src/core/utils/base64.ts
function escape(string) {
  return string.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function toBase64(input) {
  return escape(Buffer.from(input).toString("base64"));
}

// src/core/utils/timeout.ts
function waitFor(timeout) {
  return new Promise((resolve) => setTimeout(resolve, timeout));
}

// src/core/gcm/index.ts
protobuf.util.Long = Long;
protobuf.configure();
var serverKey2 = toBase64(Buffer.from(server_key_default));
var REGISTER_URL = "https://android.clients.google.com/c2dm/register3";
var CHECKIN_URL = "https://android.clients.google.com/checkin";
var root;
var AndroidCheckinResponse;
async function registerGCM(appId) {
  const options = await checkIn();
  const credentials2 = await doRegister(options, appId);
  return credentials2;
}
async function checkIn(androidId, securityToken) {
  await loadProtoFile();
  const buffer = getCheckinRequest(androidId, securityToken);
  const body = await request({
    url: CHECKIN_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-protobuf"
    },
    body: buffer,
    encoding: null
  });
  const message = AndroidCheckinResponse.decode(body);
  const object = AndroidCheckinResponse.toObject(message, {
    longs: String,
    enums: String,
    bytes: String
  });
  return object;
}
async function doRegister({ androidId, securityToken }, appId) {
  const body = {
    app: "org.chromium.linux",
    "X-subtype": appId,
    device: androidId,
    sender: serverKey2
  };
  const response = await postRegister({ androidId, securityToken, body });
  const token = response.split("=")[1];
  return {
    token,
    androidId,
    securityToken,
    appId
  };
}
async function postRegister({ androidId, securityToken, body, retry = 0 }) {
  const response = await request({
    url: REGISTER_URL,
    method: "POST",
    headers: {
      Authorization: `AidLogin ${androidId}:${securityToken}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    form: body
  });
  if (response.includes("Error")) {
    console.warn(`GCM register request has failed with ${response}`);
    if (retry >= 10) throw new Error("GCM register has failed");
    console.warn(`Retry... ${retry + 1}`);
    await waitFor(1e3);
    return postRegister({ androidId, securityToken, body, retry: retry + 1 });
  }
  return response;
}
async function loadProtoFile() {
  if (root) return;
  root = await protobuf.load(path.join(__dirname, "checkin.proto"));
}
function getCheckinRequest(androidId, securityToken) {
  const AndroidCheckinRequest = root.lookupType("checkin_proto.AndroidCheckinRequest");
  AndroidCheckinResponse = root.lookupType("checkin_proto.AndroidCheckinResponse");
  const payload = {
    userSerialNumber: 0,
    checkin: {
      type: 3,
      chromeBuild: {
        platform: 2,
        chromeVersion: "63.0.3234.0",
        channel: 1
      }
    },
    version: 3,
    id: androidId ? Long.fromString(androidId) : void 0,
    securityToken: securityToken ? Long.fromString(securityToken, true) : void 0
  };
  const errMsg = AndroidCheckinRequest.verify(payload);
  if (errMsg) throw Error(errMsg);
  const message = AndroidCheckinRequest.create(payload);
  return AndroidCheckinRequest.encode(message).finish();
}

// src/core/utils/decrypt.ts
import crypto from "crypto";
import ece from "http_ece";
function decrypt(object, keys) {
  const cryptoKey = object.appData.find((item) => item.key === "crypto-key");
  if (!cryptoKey) throw new Error("crypto-key is missing");
  const salt = object.appData.find((item) => item.key === "encryption");
  if (!salt) throw new Error("salt is missing");
  const dh = crypto.createECDH("prime256v1");
  dh.setPrivateKey(keys.privateKey, "base64");
  const params = {
    version: "aesgcm",
    authSecret: keys.authSecret,
    dh: cryptoKey.value.slice(3),
    privateKey: dh,
    salt: salt.value.slice(5)
  };
  const decrypted = ece.decrypt(object.rawData, params);
  return JSON.parse(decrypted.toString());
}

// src/core/utils/constants.ts
var kVersionPacketLen = 1;
var kTagPacketLen = 1;
var kSizePacketLenMin = 1;
var kMCSVersion = 41;

// src/core/utils/parser.ts
import EventEmitter from "events";
import path2 from "path";
import protobuf2 from "protobufjs";
var DEBUG_ENABLED = false;
var DEBUG = DEBUG_ENABLED ? console.log : (log) => {
};
var proto = null;
var Parser = class extends EventEmitter {
  _socket;
  _state;
  _data;
  _sizePacketSoFar;
  _messageTag;
  _messageSize;
  _handshakeComplete;
  _isWaitingForData;
  static async init() {
    if (proto) {
      return;
    }
    proto = await protobuf2.load(path2.resolve(__dirname, "mcs.proto"));
  }
  constructor(socket) {
    super();
    this._socket = socket;
    this._state = 0 /* MCS_VERSION_TAG_AND_SIZE */;
    this._data = Buffer.alloc(0);
    this._sizePacketSoFar = 0;
    this._messageTag = 0;
    this._messageSize = 0;
    this._handshakeComplete = false;
    this._isWaitingForData = true;
    this._socket.on("data", this._onData.bind(this));
  }
  destroy() {
    this._isWaitingForData = false;
    this._socket.removeListener("data", this._onData);
  }
  _emitError(error) {
    this.destroy();
    this.emit("error", error);
  }
  _onData(buffer) {
    DEBUG(`Got data: ${buffer.length}`);
    this._data = Buffer.concat([this._data, buffer]);
    if (this._isWaitingForData) {
      this._isWaitingForData = false;
      this._waitForData();
    }
  }
  _waitForData() {
    DEBUG(`waitForData state: ${this._state}`);
    let minBytesNeeded = 0;
    switch (this._state) {
      case 0 /* MCS_VERSION_TAG_AND_SIZE */:
        minBytesNeeded = kVersionPacketLen + kTagPacketLen + kSizePacketLenMin;
        break;
      case 1 /* MCS_TAG_AND_SIZE */:
        minBytesNeeded = kTagPacketLen + kSizePacketLenMin;
        break;
      case 2 /* MCS_SIZE */:
        minBytesNeeded = this._sizePacketSoFar + 1;
        break;
      case 3 /* MCS_PROTO_BYTES */:
        minBytesNeeded = this._messageSize;
        break;
      default:
        this._emitError(new Error(`Unexpected state: ${this._state}`));
        return;
    }
    if (this._data.length < minBytesNeeded) {
      DEBUG(`Socket read finished prematurely. Waiting for ${minBytesNeeded - this._data.length} more bytes`);
      this._isWaitingForData = true;
      return;
    }
    DEBUG(`Processing MCS data: state == ${this._state}`);
    switch (this._state) {
      case 0 /* MCS_VERSION_TAG_AND_SIZE */:
        this._onGotVersion();
        break;
      case 1 /* MCS_TAG_AND_SIZE */:
        this._onGotMessageTag();
        break;
      case 2 /* MCS_SIZE */:
        this._onGotMessageSize();
        break;
      case 3 /* MCS_PROTO_BYTES */:
        this._onGotMessageBytes();
        break;
      default:
        this._emitError(new Error(`Unexpected state: ${this._state}`));
        return;
    }
  }
  _onGotVersion() {
    const version = this._data.readInt8(0);
    this._data = this._data.slice(1);
    DEBUG(`VERSION IS ${version}`);
    if (version < kMCSVersion && version !== 38) {
      this._emitError(new Error(`Got wrong version: ${version}`));
      return;
    }
    this._onGotMessageTag();
  }
  _onGotMessageTag() {
    this._messageTag = this._data.readInt8(0);
    this._data = this._data.slice(1);
    DEBUG(`RECEIVED PROTO OF TYPE ${this._messageTag}`);
    this._onGotMessageSize();
  }
  _onGotMessageSize() {
    let incompleteSizePacket = false;
    const reader = new protobuf2.BufferReader(this._data);
    try {
      this._messageSize = reader.int32();
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("index out of range:")) {
        incompleteSizePacket = true;
      } else {
        this._emitError(error);
        return;
      }
    }
    if (incompleteSizePacket) {
      this._sizePacketSoFar = reader.pos;
      this._state = 2 /* MCS_SIZE */;
      this._waitForData();
      return;
    }
    this._data = this._data.slice(reader.pos);
    DEBUG(`Proto size: ${this._messageSize}`);
    this._sizePacketSoFar = 0;
    if (this._messageSize > 0) {
      this._state = 3 /* MCS_PROTO_BYTES */;
      this._waitForData();
    } else {
      this._onGotMessageBytes();
    }
  }
  _onGotMessageBytes() {
    const protobuf4 = this._buildProtobufFromTag(this._messageTag);
    if (!protobuf4) {
      this._emitError(new Error("Unknown tag"));
      return;
    }
    if (this._messageSize === 0) {
      this.emit("message", { tag: this._messageTag, object: {} });
      this._getNextMessage();
      return;
    }
    if (this._data.length < this._messageSize) {
      DEBUG(`Continuing data read. Buffer size is ${this._data.length}, expecting ${this._messageSize}`);
      this._state = 3 /* MCS_PROTO_BYTES */;
      this._waitForData();
      return;
    }
    const buffer = this._data.slice(0, this._messageSize);
    this._data = this._data.slice(this._messageSize);
    const message = protobuf4.decode(buffer);
    const object = protobuf4.toObject(message, {
      longs: String,
      enums: String,
      bytes: Buffer
    });
    this.emit("message", { tag: this._messageTag, object });
    if (this._messageTag === 3 /* kLoginResponseTag */) {
      if (this._handshakeComplete) {
        console.error("Unexpected login response");
      } else {
        this._handshakeComplete = true;
        DEBUG("GCM Handshake complete.");
      }
    }
    this._getNextMessage();
  }
  _getNextMessage() {
    this._messageTag = 0;
    this._messageSize = 0;
    this._state = 1 /* MCS_TAG_AND_SIZE */;
    this._waitForData();
  }
  _buildProtobufFromTag(tag) {
    if (!proto) return null;
    switch (tag) {
      case 0 /* kHeartbeatPingTag */:
        return proto.lookupType("mcs_proto.HeartbeatPing");
      case 1 /* kHeartbeatAckTag */:
        return proto.lookupType("mcs_proto.HeartbeatAck");
      case 2 /* kLoginRequestTag */:
        return proto.lookupType("mcs_proto.LoginRequest");
      case 3 /* kLoginResponseTag */:
        return proto.lookupType("mcs_proto.LoginResponse");
      case 4 /* kCloseTag */:
        return proto.lookupType("mcs_proto.Close");
      case 7 /* kIqStanzaTag */:
        return proto.lookupType("mcs_proto.IqStanza");
      case 8 /* kDataMessageStanzaTag */:
        return proto.lookupType("mcs_proto.DataMessageStanza");
      case 10 /* kStreamErrorStanzaTag */:
        return proto.lookupType("mcs_proto.StreamErrorStanza");
      default:
        return null;
    }
  }
};

// src/core/client.ts
var HOST = "mtalk.google.com";
var PORT = 5228;
var RETRY_INTERVAL = 5e3;
var proto2 = null;
var Client = class _Client extends EventEmitter2 {
  _tcpSocket;
  _credentials;
  _persistentIds;
  _socket;
  _parser;
  _retryInterval;
  static async init() {
    if (proto2) {
      return;
    }
    proto2 = await protobuf3.load(path3.resolve(__dirname, "utils", "mcs.proto"));
  }
  constructor(credentials2, persistentIds) {
    super();
    this._credentials = credentials2;
    this._persistentIds = persistentIds;
    this._tcpSocket = null;
    this._socket = null;
    this._parser = null;
    this._retryInterval = null;
  }
  async connect() {
    await _Client.init();
    await this._checkIn();
    this._connect();
    if (!this._socket) {
      return;
    }
    await Parser.init();
    if (!this._socket) {
      return;
    }
    this._parser = new Parser(this._socket);
    this._parser.on("message", this._onMessage);
    this._parser.on("error", this._onParserError);
  }
  destroy() {
    this._destroy();
  }
  checkConnection() {
    if (!this._socket) return false;
    return !this._socket.destroyed && this._socket.writable;
  }
  async _checkIn() {
    return checkIn(this._credentials.gcm.androidId, this._credentials.gcm.securityToken);
  }
  _connect() {
    this._socket = new tls.TLSSocket();
    this._socket.setKeepAlive(true);
    this._socket.on("connect", this._onSocketConnect);
    this._socket.on("close", this._onSocketClose);
    this._socket.on("error", this._onSocketError);
    this._socket.connect({ host: HOST, port: PORT });
    this._socket.write(this._loginBuffer());
  }
  _destroy() {
    if (this._retryInterval) {
      clearInterval(this._retryInterval);
    }
    if (this._socket) {
      this._socket.removeListener("connect", this._onSocketConnect);
      this._socket.removeListener("close", this._onSocketClose);
      this._socket.removeListener("error", this._onSocketError);
      this._socket.destroy();
      this._socket = null;
    }
    if (this._parser) {
      this._parser.removeListener("message", this._onMessage);
      this._parser.removeListener("error", this._onParserError);
      this._parser.destroy();
      this._parser = null;
    }
  }
  _loginBuffer() {
    if (!proto2) {
      throw new Error("Proto is not initialized");
    }
    const LoginRequestType = proto2.lookupType("mcs_proto.LoginRequest");
    const hexAndroidId = Long2.fromString(this._credentials.gcm.androidId).toString(16);
    const loginRequest = {
      adaptiveHeartbeat: false,
      authService: 2,
      authToken: this._credentials.gcm.securityToken,
      id: "chrome-63.0.3234.0",
      domain: "mcs.android.com",
      deviceId: `android-${hexAndroidId}`,
      networkType: 1,
      resource: this._credentials.gcm.androidId,
      user: this._credentials.gcm.androidId,
      useRmq2: true,
      setting: [{ name: "new_vc", value: "1" }],
      // Id of the last notification received
      clientEvent: [],
      receivedPersistentId: this._persistentIds
    };
    const errorMessage = LoginRequestType.verify(loginRequest);
    if (errorMessage) {
      throw new Error(errorMessage);
    }
    const buffer = LoginRequestType.encodeDelimited(loginRequest).finish();
    return Buffer.concat([Buffer.from([kMCSVersion, 2 /* kLoginRequestTag */]), buffer]);
  }
  _onSocketConnect = () => {
    if (this._retryInterval) {
      clearInterval(this._retryInterval);
      this._retryInterval = null;
    }
    this.emit("connect");
  };
  _onSocketClose = () => {
    this.emit("disconnect");
    this._retry();
  };
  _onSocketError = (error) => {
    console.error("Socket error", error);
  };
  _onParserError = (error) => {
    console.error("Parser error", error);
    this._retry();
  };
  _retry() {
    this._destroy();
    this._retryInterval = setInterval(() => {
      console.log("trying to reconnect to mtalk.google.com...");
      this.connect();
    }, RETRY_INTERVAL);
  }
  _onMessage = ({ tag, object }) => {
    if (tag === 3 /* kLoginResponseTag */) {
      this._persistentIds = [];
    } else if (tag === 8 /* kDataMessageStanzaTag */) {
      this._onDataMessage(object);
    }
  };
  _onDataMessage(object) {
    if (this._persistentIds.includes(object.persistentId)) {
      return;
    }
    let message;
    try {
      message = decrypt(object, this._credentials.keys);
    } catch (error) {
      if (error instanceof Error) {
        switch (true) {
          case error.message.includes("Unsupported state or unable to authenticate data"):
          case error.message.includes("crypto-key is missing"):
          case error.message.includes("salt is missing"):
            console.warn("Message dropped as it could not be decrypted: " + error.message);
            this._persistentIds.push(object.persistentId);
            return;
          default: {
            throw error;
          }
        }
      } else {
        throw error;
      }
    }
    this._persistentIds.push(object.persistentId);
    this.emit("ON_NOTIFICATION_RECEIVED" /* ON_NOTIFICATION_RECEIVED */, {
      notification: message,
      // Needs to be saved by the client
      persistentId: object.persistentId
    });
  }
};

// src/core/listen.ts
async function listen(credentials2, notificationCallback) {
  const client2 = new Client({ gcm: credentials2.gcm, keys: credentials2.keys }, credentials2.persistentIds);
  client2.on("ON_NOTIFICATION_RECEIVED" /* ON_NOTIFICATION_RECEIVED */, notificationCallback);
  await client2.connect();
  client2.emit("ON_CLIENT_CONNECTED" /* ON_CLIENT_CONNECTED */);
  return client2;
}

// src/core/register.ts
import { v4 as uuidv4 } from "uuid";

// src/core/fcm/index.ts
import crypto2 from "crypto";
import request2 from "request-promise";
var FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send";
var FCM_REGISTRATION_ENDPOINT = "https://fcmregistrations.googleapis.com/v1";
var FCM_INSTALLATION_ENDPOINT = "https://firebaseinstallations.googleapis.com/v1";
var credentials;
async function registerFCM(gcmToken, firebaseCredentials) {
  credentials = firebaseCredentials;
  const keys = await createKeys();
  const installationAuthToken = await installRequest();
  const fcmToken = await registerRequest(installationAuthToken, gcmToken, keys);
  return {
    keys,
    fcm: {
      token: fcmToken
    }
  };
}
async function createKeys() {
  const dh = crypto2.createECDH("prime256v1");
  dh.generateKeys();
  const buf = crypto2.randomBytes(16);
  return {
    privateKey: escape(dh.getPrivateKey("base64")),
    publicKey: escape(dh.getPublicKey("base64")),
    authSecret: escape(buf.toString("base64"))
  };
}
async function registerRequest(installationAuthToken, gcmToken, keys) {
  const response = await request2({
    url: `${FCM_REGISTRATION_ENDPOINT}/projects/${credentials.projectId}/registrations`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": credentials.apiKey,
      "x-goog-firebase-installations-auth": installationAuthToken
    },
    body: JSON.stringify({
      web: {
        applicationPubKey: credentials.vapidKey || "",
        auth: keys.authSecret.replace(/=/g, "").replace(/\+/g, "").replace(/\//g, ""),
        endpoint: `${FCM_ENDPOINT}/${gcmToken}`,
        p256dh: keys.publicKey.replace(/=/g, "").replace(/\+/g, "").replace(/\//g, "")
      }
    })
  });
  const parsedResponse = JSON.parse(response);
  if (!parsedResponse || !parsedResponse.token) {
    console.error(`Failed to get FCM token: ${parsedResponse}`);
    throw new Error("Failed to get FCM token");
  }
  return parsedResponse.token;
}
async function installRequest() {
  const fid = await generateFirebaseFID();
  const response = await request2({
    url: `${FCM_INSTALLATION_ENDPOINT}/projects/${credentials.projectId}/installations`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-firebase-client": Buffer.from(
        JSON.stringify({
          heartbeats: [],
          version: 2
        })
      ).toString("base64"),
      "x-goog-api-key": credentials.apiKey
    },
    body: JSON.stringify({
      appId: credentials.appId,
      authVersion: "FIS_v2",
      fid,
      sdkVersion: "w:0.6.4"
    })
  });
  const parsedResponse = JSON.parse(response);
  if (!parsedResponse || !parsedResponse.authToken || !parsedResponse.authToken.token) {
    console.error(`Failed to get auth token: ${parsedResponse}`);
    throw new Error("Failed to get auth token");
  }
  return parsedResponse.authToken.token;
}
async function generateFirebaseFID() {
  const buf = crypto2.randomBytes(17);
  buf[0] = 112 | buf[0] & 15;
  return buf.toString("base64").replace(/=/g, "");
}

// src/core/register.ts
async function register(credentials2) {
  const appId = `wp:receiver.push.com#${uuidv4()}`;
  const gcmResult = await registerGCM(appId);
  const fcmResult = await registerFCM(gcmResult.token, credentials2);
  return {
    keys: fcmResult.keys,
    fcm: fcmResult.fcm,
    gcm: gcmResult
  };
}

// src/electron/index.ts
import { ipcMain } from "electron";
import ElectronStore from "electron-config";
var config = new ElectronStore();
var started = false;
var client = null;
function setup(webContents) {
  ipcMain.on(START_NOTIFICATION_SERVICE, async (_, firebaseCredentials) => {
    let credentials2 = config.get("credentials");
    const savedFirebaseCredentials = config.get("firebaseCredentials");
    if (started) {
      webContents.send(NOTIFICATION_SERVICE_STARTED, (credentials2?.fcm || {}).token);
      return;
    }
    started = true;
    try {
      const persistentIds = config.get("persistentIds") || [];
      if (!credentials2 || !savedFirebaseCredentials || savedFirebaseCredentials.appId !== firebaseCredentials.appId || savedFirebaseCredentials.apiKey !== firebaseCredentials.apiKey || savedFirebaseCredentials.projectId !== firebaseCredentials.projectId || savedFirebaseCredentials.vapidKey !== firebaseCredentials.vapidKey) {
        credentials2 = await register(firebaseCredentials);
        config.set("credentials", credentials2);
        config.set("firebaseCredentials", firebaseCredentials);
        webContents.send(TOKEN_UPDATED, credentials2.fcm.token);
      }
      client = await listen({ ...credentials2, persistentIds }, onNotification(webContents));
      webContents.send(NOTIFICATION_SERVICE_STARTED, credentials2.fcm.token);
    } catch (e) {
      console.error("PUSH_RECEIVER:::Error while starting the service", e);
      webContents.send(NOTIFICATION_SERVICE_ERROR, e.message);
    }
  });
}
function reset() {
  config.set("credentials", null);
  config.set("firebaseCredentials", null);
  config.set("persistentIds", null);
  started = false;
  if (client) {
    client.destroy();
  }
}
function onNotification(webContents) {
  return ({ notification, persistentId }) => {
    const persistentIds = config.get("persistentIds") || [];
    config.set("persistentIds", [...persistentIds, persistentId]);
    if (!webContents.isDestroyed()) {
      webContents.send(NOTIFICATION_RECEIVED, notification);
    }
  };
}
export {
  NOTIFICATION_RECEIVED,
  NOTIFICATION_SERVICE_ERROR,
  NOTIFICATION_SERVICE_STARTED,
  START_NOTIFICATION_SERVICE,
  TOKEN_UPDATED,
  listen,
  register,
  reset,
  setup
};
