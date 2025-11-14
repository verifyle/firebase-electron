"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/electron/consts.ts
var consts_exports = {};
__export(consts_exports, {
  NOTIFICATION_RECEIVED: () => NOTIFICATION_RECEIVED,
  NOTIFICATION_SERVICE_ERROR: () => NOTIFICATION_SERVICE_ERROR,
  NOTIFICATION_SERVICE_STARTED: () => NOTIFICATION_SERVICE_STARTED,
  START_NOTIFICATION_SERVICE: () => START_NOTIFICATION_SERVICE,
  TOKEN_UPDATED: () => TOKEN_UPDATED
});
module.exports = __toCommonJS(consts_exports);
var START_NOTIFICATION_SERVICE = "PUSH_RECEIVER:::START_NOTIFICATION_SERVICE";
var NOTIFICATION_SERVICE_STARTED = "PUSH_RECEIVER:::NOTIFICATION_SERVICE_STARTED";
var NOTIFICATION_SERVICE_ERROR = "PUSH_RECEIVER:::NOTIFICATION_SERVICE_ERROR";
var NOTIFICATION_RECEIVED = "PUSH_RECEIVER:::NOTIFICATION_RECEIVED";
var TOKEN_UPDATED = "PUSH_RECEIVER:::TOKEN_UPDATED";
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  NOTIFICATION_RECEIVED,
  NOTIFICATION_SERVICE_ERROR,
  NOTIFICATION_SERVICE_STARTED,
  START_NOTIFICATION_SERVICE,
  TOKEN_UPDATED
});
