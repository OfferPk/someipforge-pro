/**
 * SOMEIPForge Pro - Web Application Interactive Controller
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  var Engine = window.SOMEIPProtocolEngine;
  var Auditor = window.SOMEIPSecurityAuditor;
  var Synthesizer = window.SOMEIPConfigSynthesizer;

  var currentPacketBytes = null;
  var currentSdBytes = null;

  // Tab Navigation
  var tabButtons = document.querySelectorAll('.tab-btn');
  var tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      tabButtons.forEach(function (b) { b.classList.remove('active'); });
      tabContents.forEach(function (c) { c.classList.remove('active'); });
      btn.classList.add('active');
      var targetId = btn.getAttribute('data-tab');
      var targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  // Tab 1: Protocol Studio Controls
  var sIdInput = document.getElementById('builder-service-id');
  var mIdInput = document.getElementById('builder-method-id');
  var cIdInput = document.getElementById('builder-client-id');
  var sessIdInput = document.getElementById('builder-session-id');
  var protoVerInput = document.getElementById('builder-proto-ver');
  var ifaceVerInput = document.getElementById('builder-iface-ver');
  var msgTypeSelect = document.getElementById('builder-msg-type');
  var retCodeSelect = document.getElementById('builder-return-code');
  var payloadHexInput = document.getElementById('builder-payload-hex');

  var btnGenerate = document.getElementById('btn-generate-someip');
  var btnExportPcap = document.getElementById('btn-export-pcap');
  var btnPresetBrakeRpc = document.getElementById('btn-preset-brake-rpc');
  var btnCalcCrc8 = document.getElementById('btn-calc-e2e-crc8');
  var btnCalcCrc32 = document.getElementById('btn-calc-e2e-crc32');

  var rawHexInput = document.getElementById('raw-hex-input');
  var btnDissectHex = document.getElementById('btn-dissect-hex');
  var dissectionTree = document.getElementById('dissection-tree');
  var packetLengthBadge = document.getElementById('packet-length-badge');
  var dissectionValidityBadge = document.getElementById('dissection-validity-badge');

  function synthesizeSomeipPacket() {
    var sId = parseInt(sIdInput.value, 16) || 0x1234;
    var mId = parseInt(mIdInput.value, 16) || 0x0001;
    var cId = parseInt(cIdInput.value, 16) || 0x0001;
    var sessId = parseInt(sessIdInput.value, 16) || 0x0001;
    var pVer = parseInt(protoVerInput.value, 10) || 1;
    var iVer = parseInt(ifaceVerInput.value, 10) || 1;
    var mType = parseInt(msgTypeSelect.value, 16);
    var rCode = parseInt(retCodeSelect.value, 16);
    var payloadBytes = Engine.hexToBytes(payloadHexInput.value);

    var packet = Engine.assembleSomeipMessage({
      serviceId: sId,
      methodId: mId,
      clientId: cId,
      sessionId: sessId,
      protocolVersion: pVer,
      interfaceVersion: iVer,
      messageType: mType,
      returnCode: rCode
    }, payloadBytes);

    currentPacketBytes = packet;
    updateDissection(packet);
  }

  function updateDissection(bytes) {
    if (!bytes) return;
    rawHexInput.value = Engine.bytesToHex(bytes);
    packetLengthBadge.textContent = bytes.length + ' Bytes';

    var res = Engine.dissectSomeipPacket(bytes);

    if (res.valid) {
      dissectionValidityBadge.className = 'badge badge-pass';
      dissectionValidityBadge.textContent = 'VALID AUTOSAR SOME/IP';
    } else {
      dissectionValidityBadge.className = 'badge badge-fail';
      dissectionValidityBadge.textContent = 'MALFORMED / ERROR';
    }

    var treeHtml = '';
    if (res.header) {
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Service ID:</span><span class="dissection-value">' + res.header.serviceIdHex + '</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">' + res.header.idType + ':</span><span class="dissection-value">' + res.header.methodOrEventIdHex + '</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Length Field:</span><span class="dissection-value">' + res.header.length + ' Bytes (Actual: ' + res.header.actualRemainingLength + 'B)</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Client ID:</span><span class="dissection-value">' + res.header.clientIdHex + '</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Session ID:</span><span class="dissection-value">' + res.header.sessionIdHex + '</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Protocol / Interface Version:</span><span class="dissection-value">v' + res.header.protocolVersion + ' / v' + res.header.interfaceVersion + '</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Message Type:</span><span class="dissection-value">' + res.header.messageTypeHex + ' (' + res.header.messageTypeName + ')</span></div>';
      treeHtml += '<div class="dissection-item"><span class="dissection-label">Return Code:</span><span class="dissection-value">' + res.header.returnCodeHex + ' (' + res.header.returnCodeName + ')</span></div>';
    }

    if (res.payloadBytes && res.payloadBytes.length > 0) {
      treeHtml += '<div class="dissection-item" style="background: rgba(56,189,248,0.05);"><span class="dissection-label">Payload (' + res.payloadBytes.length + 'B):</span><span class="dissection-value">' + res.payloadHex + '</span></div>';
    }

    if (res.error) {
      treeHtml += '<div class="dissection-item" style="color: var(--accent-red);"><span class="dissection-label">Dissection Error:</span><span>' + res.error + '</span></div>';
    }

    dissectionTree.innerHTML = treeHtml;
  }

  btnGenerate.addEventListener('click', synthesizeSomeipPacket);

  btnDissectHex.addEventListener('click', function () {
    var raw = Engine.hexToBytes(rawHexInput.value);
    currentPacketBytes = raw;
    updateDissection(raw);
  });

  btnExportPcap.addEventListener('click', function () {
    if (!currentPacketBytes) synthesizeSomeipPacket();
    var pcapBytes = Engine.exportPcap([currentPacketBytes], false);
    var blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'someip-method-capture.pcap';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  btnPresetBrakeRpc.addEventListener('click', function () {
    sIdInput.value = '0x1000'; // Braking Service
    mIdInput.value = '0x0001'; // RequestEmergencyBrake
    cIdInput.value = '0x0042'; // ADAS Planner Client ID
    sessIdInput.value = '0x0001';
    msgTypeSelect.value = '0x00'; // REQUEST
    retCodeSelect.value = '0x00'; // E_OK
    payloadHexInput.value = '01 FF 00 00'; // Deceleration 100%
    synthesizeSomeipPacket();
  });

  btnCalcCrc8.addEventListener('click', function () {
    var payload = Engine.hexToBytes(payloadHexInput.value);
    var sId = parseInt(sIdInput.value, 16) || 0x1234;
    var crc = Engine.calculateE2ECrc8(payload, sId);
    payloadHexInput.value = payloadHexInput.value.trim() + ' ' + Engine.toHex(crc, 2);
    synthesizeSomeipPacket();
  });

  btnCalcCrc32.addEventListener('click', function () {
    var payload = Engine.hexToBytes(payloadHexInput.value);
    var crc = Engine.calculateE2ECrc32(payload);
    var crcBytes = new Uint8Array([
      (crc >>> 24) & 0xFF,
      (crc >>> 16) & 0xFF,
      (crc >>> 8) & 0xFF,
      crc & 0xFF
    ]);
    payloadHexInput.value = payloadHexInput.value.trim() + ' ' + Engine.bytesToHex(crcBytes);
    synthesizeSomeipPacket();
  });

  // Tab 2: SOME/IP-SD Controls
  var sdEntryType = document.getElementById('sd-entry-type');
  var sdServiceId = document.getElementById('sd-service-id');
  var sdInstanceId = document.getElementById('sd-instance-id');
  var sdTtl = document.getElementById('sd-ttl');
  var sdMajorVer = document.getElementById('sd-major-ver');
  var sdEndpointIp = document.getElementById('sd-endpoint-ip');
  var sdEndpointProto = document.getElementById('sd-endpoint-proto');
  var sdEndpointPort = document.getElementById('sd-endpoint-port');
  var btnGenerateSd = document.getElementById('btn-generate-sd');
  var btnExportSdPcap = document.getElementById('btn-export-sd-pcap');
  var sdDissectionBox = document.getElementById('sd-dissection-box');

  function synthesizeSdMessage() {
    var eType = parseInt(sdEntryType.value, 16);
    var sId = parseInt(sdServiceId.value, 16) || 0x1234;
    var instId = parseInt(sdInstanceId.value, 16) || 0x0001;
    var ttlVal = parseInt(sdTtl.value, 10) || 5;
    var majVer = parseInt(sdMajorVer.value, 10) || 1;
    var ip = sdEndpointIp.value || '192.168.1.20';
    var proto = sdEndpointProto.value;
    var port = parseInt(sdEndpointPort.value, 10) || 30501;

    var sdPacket = Engine.buildServiceDiscoveryMessage({
      entryType: eType,
      serviceId: sId,
      instanceId: instId,
      ttl: ttlVal,
      majorVersion: majVer,
      ip: ip,
      transport: proto,
      port: port
    });

    currentSdBytes = sdPacket;
    var dissect = Engine.dissectSomeipPacket(sdPacket);

    var text = '=== SOME/IP-SD WIRE PACKET (' + sdPacket.length + ' Bytes) ===\n';
    text += 'Raw Hex:\n' + Engine.bytesToHex(sdPacket) + '\n\n';
    text += '=== DISSECTION DETAILS ===\n';
    text += 'Service ID: ' + dissect.header.serviceIdHex + ' (0xFFFF SOME/IP-SD)\n';
    text += 'Method/Event ID: ' + dissect.header.methodOrEventIdHex + ' (0x8100 SD)\n';
    text += 'Message Type: ' + dissect.header.messageTypeName + '\n';
    text += 'SD Flags: Reboot=' + dissect.details.rebootFlag + ', Unicast=' + dissect.details.unicastFlag + '\n';
    text += 'Entry Type: ' + dissect.details.entryTypeName + ' (' + Engine.toHex(dissect.details.entryType, 2) + ')\n';
    text += 'Target Service ID: ' + dissect.details.targetServiceIdHex + '\n';
    text += 'Instance ID: ' + dissect.details.instanceIdHex + '\n';
    text += 'TTL: ' + dissect.details.ttlSeconds + 's\n';
    text += 'Endpoint: ' + proto + ' ' + ip + ':' + port + '\n';

    sdDissectionBox.textContent = text;
  }

  btnGenerateSd.addEventListener('click', synthesizeSdMessage);

  btnExportSdPcap.addEventListener('click', function () {
    if (!currentSdBytes) synthesizeSdMessage();
    var pcapBytes = Engine.exportPcap([currentSdBytes], true);
    var blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'someip-sd-service-discovery.pcap';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Tab 3: Security Auditor Controls
  var auditScoreValue = document.getElementById('audit-score-value');
  var auditGradeValue = document.getElementById('audit-grade-value');
  var auditCriticalCount = document.getElementById('audit-critical-count');
  var auditResultsTbody = document.getElementById('audit-results-tbody');
  var btnRunAudit = document.getElementById('btn-run-audit');
  var btnLoadSecureProfile = document.getElementById('btn-load-secure-profile');
  var btnLoadVulnerableProfile = document.getElementById('btn-load-vulnerable-profile');

  function getAuditorProfileFromInputs() {
    var sdWhitelisting = document.getElementById('audit-param-sd-whitelist').value === 'strict';
    var secocVal = document.getElementById('audit-param-secoc').value;
    var e2eVal = document.getElementById('audit-param-e2e').value;
    var vlanVal = document.getElementById('audit-param-vlan').value;
    var methodAclVal = document.getElementById('audit-param-method-acl').value === 'enforced';

    return {
      sdWhitelistingEnabled: sdWhitelisting,
      dropUnauthorizedOffers: sdWhitelisting,
      sdRateLimiting: true,
      maxSdPacketsPerSec: 10,
      secocEnabled: secocVal !== 'none',
      macAlgorithm: secocVal === 'none' ? '' : secocVal,
      macTruncatedBits: 64,
      e2eProfile: e2eVal === 'none' ? '' : e2eVal,
      e2eAliveCounterCheck: e2eVal !== 'none',
      vlanIsolation: vlanVal === 'isolated',
      infotainmentVlanId: 200,
      adasVlanId: 300,
      methodAclEnabled: methodAclVal,
      rejectUnauthorizedClients: methodAclVal,
      tpGuardEnabled: true,
      tpReassemblyTimeoutMs: 500,
      tpMaxBufferBytes: 65536,
      sessionIdTracking: true,
      dropNonMonotonicSessions: true,
      nftablesFirewallActive: true,
      blockUntrustedEndpoints: true,
      idsLoggingEnabled: true,
      dpiSuricataSignaturesActive: true
    };
  }

  function executeAudit() {
    var profile = getAuditorProfileFromInputs();
    var res = Auditor.auditDeployment(profile);

    auditScoreValue.textContent = res.score + '%';
    auditGradeValue.textContent = 'Grade: ' + res.grade + ' (' + res.complianceStatus + ')';
    auditCriticalCount.textContent = res.summary.criticalVulnerabilities;

    if (res.score >= 90) {
      auditScoreValue.style.color = 'var(--accent-green)';
    } else if (res.score >= 70) {
      auditScoreValue.style.color = 'var(--accent-amber)';
    } else {
      auditScoreValue.style.color = 'var(--accent-red)';
    }

    var tbodyHtml = '';
    res.findings.forEach(function (f) {
      var badgeClass = f.pass ? 'badge-pass' : 'badge-fail';
      tbodyHtml += '<tr>';
      tbodyHtml += '<td style="font-family: var(--font-mono); font-weight: 600;">' + f.id + '</td>';
      tbodyHtml += '<td><strong>' + f.title + '</strong><br><span style="font-size: 11px; color: var(--text-secondary);">' + f.detail + '</span></td>';
      tbodyHtml += '<td><span class="badge ' + badgeClass + '">' + (f.pass ? 'PASS' : f.severity) + '</span></td>';
      tbodyHtml += '</tr>';
    });

    auditResultsTbody.innerHTML = tbodyHtml;
  }

  btnRunAudit.addEventListener('click', executeAudit);

  btnLoadSecureProfile.addEventListener('click', function () {
    document.getElementById('audit-param-sd-whitelist').value = 'strict';
    document.getElementById('audit-param-secoc').value = 'AES-128-CMAC';
    document.getElementById('audit-param-e2e').value = 'Profile 4';
    document.getElementById('audit-param-vlan').value = 'isolated';
    document.getElementById('audit-param-method-acl').value = 'enforced';
    executeAudit();
  });

  btnLoadVulnerableProfile.addEventListener('click', function () {
    document.getElementById('audit-param-sd-whitelist').value = 'open';
    document.getElementById('audit-param-secoc').value = 'none';
    document.getElementById('audit-param-e2e').value = 'none';
    document.getElementById('audit-param-vlan').value = 'flat';
    document.getElementById('audit-param-method-acl').value = 'disabled';
    executeAudit();
  });

  // Tab 4: Synthesizer Outputs
  var nftablesBox = document.getElementById('nftables-output');
  var suricataBox = document.getElementById('suricata-output');

  function updateSynthesizerOutputs() {
    nftablesBox.textContent = Synthesizer.generateNftablesRules({
      sdPort: 30490,
      servicePort: 30501,
      iviInterface: 'eth0.200',
      adasInterface: 'eth1.300',
      maxSdRate: '10/second'
    });

    suricataBox.textContent = Synthesizer.generateSuricataRules({});
  }

  document.getElementById('btn-copy-nftables').addEventListener('click', function () {
    navigator.clipboard.writeText(nftablesBox.textContent);
    alert('Copied nftables rules to clipboard.');
  });

  document.getElementById('btn-copy-suricata').addEventListener('click', function () {
    navigator.clipboard.writeText(suricataBox.textContent);
    alert('Copied Suricata signatures to clipboard.');
  });

  // Tab 5: Simulator Controls
  var timelineDiv = document.getElementById('sim-timeline');

  function addTimelineEvent(time, title, desc, isErr) {
    var item = document.createElement('div');
    item.className = 'timeline-event' + (isErr ? ' err' : '');
    item.innerHTML = '<div class="timeline-time">' + time + '</div><div class="timeline-body"><h4>' + title + '</h4><p>' + desc + '</p></div>';
    timelineDiv.appendChild(item);
    timelineDiv.scrollTop = timelineDiv.scrollHeight;
  }

  document.getElementById('btn-sim-soa-handshake').addEventListener('click', function () {
    timelineDiv.innerHTML = '';
    addTimelineEvent('T+0.000s', 'SOME/IP-SD OfferService (Multicast 224.0.0.17)', 'Braking ECU (192.168.1.20) announces Service 0x1000, Instance 0x0001, TTL=5s on UDP 30501.');
    setTimeout(function () {
      addTimelineEvent('T+0.015s', 'SOME/IP-SD FindService', 'ADAS Central Compute (192.168.1.10) discovers Service 0x1000.');
    }, 200);
    setTimeout(function () {
      addTimelineEvent('T+0.040s', 'SOME/IP-SD SubscribeEventgroup (0x0001)', 'ADAS Compute subscribes to Brake Pressure status events.');
    }, 400);
    setTimeout(function () {
      addTimelineEvent('T+0.055s', 'SOME/IP-SD SubscribeEventgroupAck', 'Braking ECU confirms eventgroup subscription.');
    }, 600);
    setTimeout(function () {
      addTimelineEvent('T+0.080s', 'SOME/IP Method Request (0x1000 0x0001)', 'ADAS invokes RequestEmergencyBrake with Client ID 0x0042, Session 0x0001.');
    }, 800);
    setTimeout(function () {
      addTimelineEvent('T+0.095s', 'SOME/IP Method Response (0x80 E_OK)', 'Braking ECU executes emergency deceleration and acknowledges RPC.');
    }, 1000);
  });

  document.getElementById('btn-sim-e2e-event').addEventListener('click', function () {
    timelineDiv.innerHTML = '';
    addTimelineEvent('T+0.000s', 'E2E Event Publication (Seq 0)', 'Brake Pressure = 120 bar | E2E Profile 4 CRC-32 = 0x9B2C41A0.');
    setTimeout(function () {
      addTimelineEvent('T+0.020s', 'E2E Event Publication (Seq 1)', 'Brake Pressure = 122 bar | Alive Counter verified monotonic.');
    }, 250);
    setTimeout(function () {
      addTimelineEvent('T+0.040s', 'E2E Event Publication (Seq 2)', 'Brake Pressure = 121 bar | CRC matched on receiver.');
    }, 500);
  });

  document.getElementById('btn-sim-rogue-offer').addEventListener('click', function () {
    timelineDiv.innerHTML = '';
    addTimelineEvent('T+0.000s', 'Rogue Service Offer Injected', 'Malicious infotainment app sends OfferService for Braking Service 0x1000 from untrusted MAC.', true);
    setTimeout(function () {
      addTimelineEvent('T+0.008s', 'Linux nftables Drop Triggered', 'Domain filter chain drops packet on eth0.200 (SOMEIP_IVI_INJECT_BLOCKED).', true);
    }, 200);
    setTimeout(function () {
      addTimelineEvent('T+0.018s', 'Suricata Signature Alert SID 90014202', 'IDS flags unauthorized offer broadcast for Safety Service ID 0x1000.', true);
    }, 400);
    setTimeout(function () {
      addTimelineEvent('T+0.035s', 'Zero-Trust Gateway Action', 'Central Gateway blacklists rogue endpoint and alerts vehicle telemetry SOC.', true);
    }, 600);
  });

  document.getElementById('btn-sim-clear').addEventListener('click', function () {
    timelineDiv.innerHTML = '';
  });

  // Initial runs
  synthesizeSomeipPacket();
  synthesizeSdMessage();
  executeAudit();
  updateSynthesizerOutputs();
});
