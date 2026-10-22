/**
 * SOMEIPForge Pro - AUTOSAR SOME/IP & SOME/IP-SD Protocol Engine
 * Standard-compliant encoding, decoding, E2E CRC calculation, and PCAP synthesis.
 * Conforms to AUTOSAR FO R20-11 / R22-11 (PRS_SOMEIP & PRS_SOMEIPSD).
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SOMEIPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var MESSAGE_TYPES = {
    REQUEST: 0x00,
    REQUEST_NO_RETURN: 0x01,
    NOTIFICATION: 0x02,
    RESPONSE: 0x80,
    ERROR: 0x81,
    TP_REQUEST: 0x20,
    TP_REQUEST_NO_RETURN: 0x21,
    TP_NOTIFICATION: 0x22,
    TP_RESPONSE: 0x23,
    TP_ERROR: 0x24
  };

  var MESSAGE_TYPE_NAMES = {
    0x00: 'REQUEST',
    0x01: 'REQUEST_NO_RETURN',
    0x02: 'NOTIFICATION',
    0x80: 'RESPONSE',
    0x81: 'ERROR',
    0x20: 'TP_REQUEST',
    0x21: 'TP_REQUEST_NO_RETURN',
    0x22: 'TP_NOTIFICATION',
    0x23: 'TP_RESPONSE',
    0x24: 'TP_ERROR'
  };

  var RETURN_CODES = {
    E_OK: 0x00,
    E_NOT_OK: 0x01,
    E_UNKNOWN_SERVICE: 0x02,
    E_UNKNOWN_METHOD: 0x03,
    E_NOT_READY: 0x04,
    E_NOT_REACHABLE: 0x05,
    E_TIMEOUT: 0x06,
    E_WRONG_PROTOCOL_VERSION: 0x07,
    E_WRONG_INTERFACE_VERSION: 0x08,
    E_MALFORMED_MESSAGE: 0x09,
    E_WRONG_MESSAGE_TYPE: 0x0A,
    E_E2E_REPEATED: 0x0B,
    E_E2E_WRONG_SEQUENCE: 0x0C,
    E_E2E: 0x0D,
    E_E2E_NOT_AVAILABLE: 0x0E,
    E_E2E_NO_NEW_DATA: 0x0F
  };

  var RETURN_CODE_NAMES = {
    0x00: 'E_OK (No error occurred)',
    0x01: 'E_NOT_OK (Unspecified error)',
    0x02: 'E_UNKNOWN_SERVICE (Service ID unknown)',
    0x03: 'E_UNKNOWN_METHOD (Method/Event ID unknown)',
    0x04: 'E_NOT_READY (Service not ready)',
    0x05: 'E_NOT_REACHABLE (Service not reachable)',
    0x06: 'E_TIMEOUT (Timeout occurred)',
    0x07: 'E_WRONG_PROTOCOL_VERSION (Protocol version mismatch)',
    0x08: 'E_WRONG_INTERFACE_VERSION (Interface version mismatch)',
    0x09: 'E_MALFORMED_MESSAGE (Deserialization failed)',
    0x0A: 'E_WRONG_MESSAGE_TYPE (Unexpected message type)',
    0x0B: 'E_E2E_REPEATED (E2E repeated message)',
    0x0C: 'E_E2E_WRONG_SEQUENCE (E2E sequence error)',
    0x0D: 'E_E2E (E2E unspecified error)',
    0x0E: 'E_E2E_NOT_AVAILABLE (E2E not available)',
    0x0F: 'E_E2E_NO_NEW_DATA (E2E no new data)'
  };

  var SD_ENTRY_TYPES = {
    FIND_SERVICE: 0x00,
    OFFER_SERVICE: 0x01,
    STOP_OFFER_SERVICE: 0x01, // Differentiated by TTL=0
    SUBSCRIBE_EVENTGROUP: 0x06,
    STOP_SUBSCRIBE_EVENTGROUP: 0x06, // Differentiated by TTL=0
    SUBSCRIBE_ACK: 0x07
  };

  function toHex(val, pad) {
    var str = Number(val).toString(16).toUpperCase();
    while (str.length < (pad || 2)) {
      str = '0' + str;
    }
    return str;
  }

  function bytesToHex(bytes) {
    if (!bytes) return '';
    var arr = Array.prototype.slice.call(bytes);
    return arr.map(function (b) { return toHex(b, 2); }).join(' ');
  }

  function hexToBytes(hexStr) {
    if (!hexStr) return new Uint8Array(0);
    var clean = hexStr.replace(/[^0-9A-Fa-f]/g, '');
    if (clean.length % 2 !== 0) clean = '0' + clean;
    var len = clean.length / 2;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * AUTOSAR E2E Profile 1 CRC-8 (SAE J1850 polynomial 0x1D, init 0xFF, xor 0xFF)
   */
  function calculateE2ECrc8(dataBytes, dataId) {
    var crc = 0xFF;
    var poly = 0x1D;

    // Fold Data ID into CRC calculation
    var dIdLow = dataId & 0xFF;
    var dIdHigh = (dataId >> 8) & 0xFF;
    var buffer = new Uint8Array(dataBytes.length + 2);
    buffer.set(dataBytes, 0);
    buffer[dataBytes.length] = dIdLow;
    buffer[dataBytes.length + 1] = dIdHigh;

    for (var i = 0; i < buffer.length; i++) {
      crc ^= buffer[i];
      for (var bit = 0; bit < 8; bit++) {
        if ((crc & 0x80) !== 0) {
          crc = ((crc << 1) ^ poly) & 0xFF;
        } else {
          crc = (crc << 1) & 0xFF;
        }
      }
    }
    return (crc ^ 0xFF) & 0xFF;
  }

  /**
   * AUTOSAR E2E Profile 4 CRC-32 (IEEE 802.3 polynomial 0x04C11DB7, reflected)
   */
  function calculateE2ECrc32(dataBytes) {
    var crc = 0xFFFFFFFF;
    for (var i = 0; i < dataBytes.length; i++) {
      var byte = dataBytes[i];
      crc ^= byte;
      for (var j = 0; j < 8; j++) {
        var mask = -(crc & 1);
        crc = (crc >>> 1) ^ (0xEDB88320 & mask);
      }
    }
    return (~crc) >>> 0;
  }

  /**
   * Builds the 16-byte SOME/IP standard header
   * Length field = 8 (for RequestID, ProtoVer, IfaceVer, MsgType, RetCode) + payload.length
   */
  function buildSomeipHeader(opts) {
    opts = opts || {};
    var serviceId = opts.serviceId !== undefined ? opts.serviceId : 0x1234;
    var methodId = opts.methodId !== undefined ? opts.methodId : 0x0001; // top bit 1 if event
    var clientId = opts.clientId !== undefined ? opts.clientId : 0x0001;
    var sessionId = opts.sessionId !== undefined ? opts.sessionId : 0x0001;
    var protoVer = opts.protocolVersion !== undefined ? opts.protocolVersion : 0x01;
    var ifaceVer = opts.interfaceVersion !== undefined ? opts.interfaceVersion : 0x01;
    var msgType = opts.messageType !== undefined ? opts.messageType : MESSAGE_TYPES.REQUEST;
    var retCode = opts.returnCode !== undefined ? opts.returnCode : RETURN_CODES.E_OK;
    var payloadLen = opts.payloadLength !== undefined ? opts.payloadLength : 0;

    var header = new Uint8Array(16);

    // Message ID (Bytes 0-3): Service ID (16b) + Method/Event ID (16b)
    header[0] = (serviceId >> 8) & 0xFF;
    header[1] = serviceId & 0xFF;
    header[2] = (methodId >> 8) & 0xFF;
    header[3] = methodId & 0xFF;

    // Length (Bytes 4-7): remaining length after Length field (8 + payloadLen)
    var lengthVal = (8 + payloadLen) >>> 0;
    header[4] = (lengthVal >>> 24) & 0xFF;
    header[5] = (lengthVal >>> 16) & 0xFF;
    header[6] = (lengthVal >>> 8) & 0xFF;
    header[7] = lengthVal & 0xFF;

    // Request ID (Bytes 8-11): Client ID (16b) + Session ID (16b)
    header[8] = (clientId >> 8) & 0xFF;
    header[9] = clientId & 0xFF;
    header[10] = (sessionId >> 8) & 0xFF;
    header[11] = sessionId & 0xFF;

    // Protocol Version, Interface Version, Message Type, Return Code (Bytes 12-15)
    header[12] = protoVer & 0xFF;
    header[13] = ifaceVer & 0xFF;
    header[14] = msgType & 0xFF;
    header[15] = retCode & 0xFF;

    return header;
  }

  /**
   * Assembles a standard SOME/IP frame with header and user payload
   */
  function assembleSomeipMessage(headerOpts, payloadBytes) {
    var payload = payloadBytes || new Uint8Array(0);
    var opts = Object.assign({}, headerOpts);
    opts.payloadLength = payload.length;
    var header = buildSomeipHeader(opts);

    var packet = new Uint8Array(header.length + payload.length);
    packet.set(header, 0);
    packet.set(payload, header.length);
    return packet;
  }

  /**
   * SOME/IP-SD (Service Discovery) Message Builder
   */
  function buildServiceDiscoveryMessage(opts) {
    opts = opts || {};
    var flags = opts.flags !== undefined ? opts.flags : 0xC0; // Reboot (0x80) + Unicast (0x40)
    var sessionId = opts.sessionId !== undefined ? opts.sessionId : 0x0001;

    var entryType = opts.entryType !== undefined ? opts.entryType : 0x01; // OfferService
    var serviceId = opts.serviceId !== undefined ? opts.serviceId : 0x1234;
    var instanceId = opts.instanceId !== undefined ? opts.instanceId : 0x0001;
    var majorVersion = opts.majorVersion !== undefined ? opts.majorVersion : 0x01;
    var ttl = opts.ttl !== undefined ? opts.ttl : 0x000005; // 5 seconds
    var minorVersion = opts.minorVersion !== undefined ? opts.minorVersion : 0x00000000;

    // Build 16-byte Entry
    var entry = new Uint8Array(16);
    entry[0] = entryType & 0xFF;
    entry[1] = 0x00; // Index 1st options
    entry[2] = 0x00; // Index 2nd options
    entry[3] = 0x10; // Number of options (1 option in run 1)
    entry[4] = (serviceId >> 8) & 0xFF;
    entry[5] = serviceId & 0xFF;
    entry[6] = (instanceId >> 8) & 0xFF;
    entry[7] = instanceId & 0xFF;
    entry[8] = majorVersion & 0xFF;
    entry[9] = (ttl >> 16) & 0xFF;
    entry[10] = (ttl >> 8) & 0xFF;
    entry[11] = ttl & 0xFF;
    entry[12] = (minorVersion >>> 24) & 0xFF;
    entry[13] = (minorVersion >>> 16) & 0xFF;
    entry[14] = (minorVersion >>> 8) & 0xFF;
    entry[15] = minorVersion & 0xFF;

    // Build IPv4 Endpoint Option (Type 0x04, Length 0x0009): 12 bytes
    var port = opts.port !== undefined ? opts.port : 30501;
    var proto = (opts.transport === 'TCP') ? 0x06 : 0x11; // TCP=6, UDP=17
    var ipStr = opts.ip || '192.168.1.20';
    var ipParts = ipStr.split('.').map(function (x) { return parseInt(x, 10); });

    var option = new Uint8Array(12);
    option[0] = 0x00; option[1] = 0x09; // Length 9 bytes following
    option[2] = 0x04; // Type IPv4 Endpoint
    option[3] = 0x00; // Reserved
    option[4] = ipParts[0] & 0xFF;
    option[5] = ipParts[1] & 0xFF;
    option[6] = ipParts[2] & 0xFF;
    option[7] = ipParts[3] & 0xFF;
    option[8] = 0x00; // Reserved
    option[9] = proto; // L4 Protocol
    option[10] = (port >> 8) & 0xFF;
    option[11] = port & 0xFF;

    // Assemble SD Payload: Flags (4B) + Entries Len (4B) + Entry (16B) + Options Len (4B) + Option (12B)
    var entriesLen = entry.length;
    var optionsLen = option.length;
    var sdPayloadLen = 4 + 4 + entriesLen + 4 + optionsLen;
    var sdPayload = new Uint8Array(sdPayloadLen);

    sdPayload[0] = flags & 0xFF;
    sdPayload[1] = 0x00; sdPayload[2] = 0x00; sdPayload[3] = 0x00; // Reserved

    sdPayload[4] = (entriesLen >>> 24) & 0xFF;
    sdPayload[5] = (entriesLen >>> 16) & 0xFF;
    sdPayload[6] = (entriesLen >>> 8) & 0xFF;
    sdPayload[7] = entriesLen & 0xFF;
    sdPayload.set(entry, 8);

    var optOffset = 8 + entriesLen;
    sdPayload[optOffset] = (optionsLen >>> 24) & 0xFF;
    sdPayload[optOffset + 1] = (optionsLen >>> 16) & 0xFF;
    sdPayload[optOffset + 2] = (optionsLen >>> 8) & 0xFF;
    sdPayload[optOffset + 3] = optionsLen & 0xFF;
    sdPayload.set(option, optOffset + 4);

    // Package in SOME/IP header (Service ID 0xFFFF, Method ID 0x8100, Client ID 0x0000)
    return assembleSomeipMessage({
      serviceId: 0xFFFF,
      methodId: 0x8100,
      clientId: 0x0000,
      sessionId: sessionId,
      protocolVersion: 0x01,
      interfaceVersion: 0x01,
      messageType: MESSAGE_TYPES.NOTIFICATION,
      returnCode: RETURN_CODES.E_OK
    }, sdPayload);
  }

  /**
   * Dissects and validates a raw SOME/IP byte stream
   */
  function dissectSomeipPacket(rawBytes) {
    if (!rawBytes || rawBytes.length < 16) {
      return {
        valid: false,
        error: 'Packet smaller than 16-byte mandatory SOME/IP header (' + (rawBytes ? rawBytes.length : 0) + 'B)'
      };
    }

    var serviceId = (rawBytes[0] << 8) | rawBytes[1];
    var methodOrEventId = (rawBytes[2] << 8) | rawBytes[3];
    var isEvent = (methodOrEventId & 0x8000) !== 0;
    var lengthField = ((rawBytes[4] << 24) | (rawBytes[5] << 16) | (rawBytes[6] << 8) | rawBytes[7]) >>> 0;
    var clientId = (rawBytes[8] << 8) | rawBytes[9];
    var sessionId = (rawBytes[10] << 8) | rawBytes[11];
    var protoVer = rawBytes[12];
    var ifaceVer = rawBytes[13];
    var msgType = rawBytes[14];
    var returnCode = rawBytes[15];

    var remainingBytes = rawBytes.length - 8; // length counted from byte 8 onwards
    var lengthMatches = (remainingBytes === lengthField);

    var payload = rawBytes.subarray(16);

    var res = {
      valid: lengthMatches && (protoVer === 0x01 || protoVer === 0x02),
      header: {
        serviceId: serviceId,
        serviceIdHex: '0x' + toHex(serviceId, 4),
        methodOrEventId: methodOrEventId,
        methodOrEventIdHex: '0x' + toHex(methodOrEventId, 4),
        isEvent: isEvent,
        idType: isEvent ? 'Event / Field ID' : 'Method ID',
        length: lengthField,
        actualRemainingLength: remainingBytes,
        lengthMatches: lengthMatches,
        clientId: clientId,
        clientIdHex: '0x' + toHex(clientId, 4),
        sessionId: sessionId,
        sessionIdHex: '0x' + toHex(sessionId, 4),
        protocolVersion: protoVer,
        interfaceVersion: ifaceVer,
        messageType: msgType,
        messageTypeHex: '0x' + toHex(msgType, 2),
        messageTypeName: MESSAGE_TYPE_NAMES[msgType] || 'UNKNOWN_TYPE',
        returnCode: returnCode,
        returnCodeHex: '0x' + toHex(returnCode, 2),
        returnCodeName: RETURN_CODE_NAMES[returnCode] || 'UNKNOWN_CODE'
      },
      isServiceDiscovery: (serviceId === 0xFFFF && methodOrEventId === 0x8100),
      payloadBytes: payload,
      payloadHex: bytesToHex(payload),
      details: {}
    };

    if (!lengthMatches) {
      res.error = 'Length field mismatch: Header states ' + lengthField + ' bytes, but buffer has ' + remainingBytes + ' bytes.';
    } else if (protoVer !== 0x01 && protoVer !== 0x02) {
      res.error = 'Invalid protocol version: ' + protoVer + ' (Expected 0x01 or 0x02).';
    }

    // Parse Service Discovery if applicable
    if (res.isServiceDiscovery && payload.length >= 8) {
      res.details.sdFlags = payload[0];
      res.details.sdFlagsHex = '0x' + toHex(payload[0], 2);
      res.details.rebootFlag = (payload[0] & 0x80) !== 0;
      res.details.unicastFlag = (payload[0] & 0x40) !== 0;

      var entriesLen = ((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]) >>> 0;
      res.details.entriesLength = entriesLen;

      if (payload.length >= 8 + entriesLen && entriesLen >= 16) {
        var entryBytes = payload.subarray(8, 8 + 16);
        var eType = entryBytes[0];
        res.details.entryType = eType;
        if (eType === 0x00) res.details.entryTypeName = 'FindService';
        else if (eType === 0x01) res.details.entryTypeName = (entryBytes[9] === 0 && entryBytes[10] === 0 && entryBytes[11] === 0) ? 'StopOfferService' : 'OfferService';
        else if (eType === 0x06) res.details.entryTypeName = 'SubscribeEventgroup';
        else if (eType === 0x07) res.details.entryTypeName = 'SubscribeEventgroupAck';

        res.details.targetServiceId = (entryBytes[4] << 8) | entryBytes[5];
        res.details.targetServiceIdHex = '0x' + toHex(res.details.targetServiceId, 4);
        res.details.instanceId = (entryBytes[6] << 8) | entryBytes[7];
        res.details.instanceIdHex = '0x' + toHex(res.details.instanceId, 4);
        res.details.majorVersion = entryBytes[8];
        res.details.ttlSeconds = (entryBytes[9] << 16) | (entryBytes[10] << 8) | entryBytes[11];
      }
    }

    return res;
  }

  /**
   * Generates a Libpcap Wireshark capture for SOME/IP packets
   */
  function exportPcap(packets, isMulticast) {
    var globalHeader = new Uint8Array([
      0xD4, 0xC3, 0xB2, 0xA1, // Magic (0xA1B2C3D4)
      0x02, 0x00,             // Major 2
      0x04, 0x00,             // Minor 4
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, // Snaplen 65535
      0x01, 0x00, 0x00, 0x00  // Ethernet
    ]);

    var packetBuffers = [];
    var totalLen = globalHeader.length;
    var baseTsSec = 1791198000;

    var srcMac = new Uint8Array([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    var dstMac = isMulticast ? new Uint8Array([0x01, 0x00, 0x5E, 0x00, 0x00, 0x11]) : new Uint8Array([0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C]);
    var srcIp = new Uint8Array([192, 168, 1, 10]);
    var dstIp = isMulticast ? new Uint8Array([224, 0, 0, 17]) : new Uint8Array([192, 168, 1, 20]);
    var port = isMulticast ? 30490 : 30501;

    for (var i = 0; i < packets.length; i++) {
      var rawPayload = packets[i];

      var ethHeader = new Uint8Array(14);
      ethHeader.set(dstMac, 0);
      ethHeader.set(srcMac, 6);
      ethHeader[12] = 0x08; ethHeader[13] = 0x00; // IPv4

      var ipLen = 20 + 8 + rawPayload.length;
      var ipHeader = new Uint8Array(20);
      ipHeader[0] = 0x45;
      ipHeader[1] = 0x00;
      ipHeader[2] = (ipLen >> 8) & 0xFF;
      ipHeader[3] = ipLen & 0xFF;
      ipHeader[4] = (i >> 8) & 0xFF;
      ipHeader[5] = i & 0xFF;
      ipHeader[6] = 0x40; ipHeader[7] = 0x00;
      ipHeader[8] = 0x40; // TTL
      ipHeader[9] = 17;   // Protocol UDP
      ipHeader.set(srcIp, 12);
      ipHeader.set(dstIp, 16);

      // IP Checksum
      var csum = 0;
      for (var c = 0; c < 20; c += 2) {
        csum += (ipHeader[c] << 8) | ipHeader[c + 1];
      }
      while (csum > 0xFFFF) csum = (csum & 0xFFFF) + (csum >>> 16);
      csum = (~csum) & 0xFFFF;
      ipHeader[10] = (csum >> 8) & 0xFF;
      ipHeader[11] = csum & 0xFF;

      // UDP Header (8B)
      var udpHeader = new Uint8Array(8);
      var srcPort = 30501 + i;
      udpHeader[0] = (srcPort >> 8) & 0xFF;
      udpHeader[1] = srcPort & 0xFF;
      udpHeader[2] = (port >> 8) & 0xFF;
      udpHeader[3] = port & 0xFF;
      var udpLen = 8 + rawPayload.length;
      udpHeader[4] = (udpLen >> 8) & 0xFF;
      udpHeader[5] = udpLen & 0xFF;
      udpHeader[6] = 0x00; udpHeader[7] = 0x00; // Checksum optional

      var frameLen = ethHeader.length + ipHeader.length + udpHeader.length + rawPayload.length;
      var fullFrame = new Uint8Array(frameLen);
      var offset = 0;
      fullFrame.set(ethHeader, offset); offset += ethHeader.length;
      fullFrame.set(ipHeader, offset); offset += ipHeader.length;
      fullFrame.set(udpHeader, offset); offset += udpHeader.length;
      fullFrame.set(rawPayload, offset);

      var pcapPktHeader = new Uint8Array(16);
      var tsSec = baseTsSec + Math.floor(i / 10);
      var tsUsec = (i % 10) * 100000;
      pcapPktHeader[0] = tsSec & 0xFF;
      pcapPktHeader[1] = (tsSec >> 8) & 0xFF;
      pcapPktHeader[2] = (tsSec >> 16) & 0xFF;
      pcapPktHeader[3] = (tsSec >> 24) & 0xFF;
      pcapPktHeader[4] = tsUsec & 0xFF;
      pcapPktHeader[5] = (tsUsec >> 8) & 0xFF;
      pcapPktHeader[6] = (tsUsec >> 16) & 0xFF;
      pcapPktHeader[7] = (tsUsec >> 24) & 0xFF;
      pcapPktHeader[8] = frameLen & 0xFF;
      pcapPktHeader[9] = (frameLen >> 8) & 0xFF;
      pcapPktHeader[10] = (frameLen >> 16) & 0xFF;
      pcapPktHeader[11] = (frameLen >> 24) & 0xFF;
      pcapPktHeader[12] = frameLen & 0xFF;
      pcapPktHeader[13] = (frameLen >> 8) & 0xFF;
      pcapPktHeader[14] = (frameLen >> 16) & 0xFF;
      pcapPktHeader[15] = (frameLen >> 24) & 0xFF;

      packetBuffers.push(pcapPktHeader);
      packetBuffers.push(fullFrame);
      totalLen += pcapPktHeader.length + fullFrame.length;
    }

    var result = new Uint8Array(totalLen);
    var writePos = 0;
    result.set(globalHeader, writePos); writePos += globalHeader.length;
    for (var b = 0; b < packetBuffers.length; b++) {
      result.set(packetBuffers[b], writePos);
      writePos += packetBuffers[b].length;
    }

    return result;
  }

  return {
    MESSAGE_TYPES: MESSAGE_TYPES,
    MESSAGE_TYPE_NAMES: MESSAGE_TYPE_NAMES,
    RETURN_CODES: RETURN_CODES,
    RETURN_CODE_NAMES: RETURN_CODE_NAMES,
    SD_ENTRY_TYPES: SD_ENTRY_TYPES,
    buildSomeipHeader: buildSomeipHeader,
    assembleSomeipMessage: assembleSomeipMessage,
    buildServiceDiscoveryMessage: buildServiceDiscoveryMessage,
    dissectSomeipPacket: dissectSomeipPacket,
    calculateE2ECrc8: calculateE2ECrc8,
    calculateE2ECrc32: calculateE2ECrc32,
    exportPcap: exportPcap,
    toHex: toHex,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes
  };
}));
