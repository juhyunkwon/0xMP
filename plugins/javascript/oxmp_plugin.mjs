// JavaScript plugin entry. The implementation lives in the web client so the
// browser and this plugin can never drift apart.
export {
  FrameType, FrameError, MAGIC, VERSION, MAX_PAYLOAD,
  encodeFrame, decodeFrame, encodeHello, decodeHelloResult, encodeAuth,
  decodeAuthResult, encodeMessageSend, decodeMessageAccepted, decodeMessageIncoming,
  decodeSyncBatch, encodeSyncRequest, encodeSyncAck, encodeDeliveryAck,
  encodeDeleteEvent, decodeDeleteEvent, decodeError, parseFields,
  toHex, fromHex, uuidBytes, signChallenge,
} from "../../clients/web/oxmp.js";
