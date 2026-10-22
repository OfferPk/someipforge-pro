/**
 * SOMEIPForge Pro - ISO 21434 & AUTOSAR SecOC Automotive Cybersecurity Auditor
 * 10-Point Zero-Trust Compliance and Hardening Engine for Automotive SOA & SOME/IP
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SOMEIPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var AUDIT_CATEGORIES = {
    SERVICE_DISCOVERY: 'Service Discovery & Identity Validation',
    AUTHENTICATION: 'SecOC & Cryptographic Message Authentication',
    DATA_INTEGRITY: 'E2E Protection & Sequence Anti-Replay',
    NETWORK_SEGMENTATION: 'IEEE 802.1Q VLAN & Access Control',
    RESILIENCE: 'DoS Mitigation & Buffer Exhaustion Defense',
    INSPECTION: 'L7 Deep Packet Inspection & SIEM Telemetry'
  };

  /**
   * Evaluates an automotive SOME/IP deployment profile
   * Returns a score (0-100), letter grade (A+ to F), compliance status, and remediation roadmap.
   */
  function auditDeployment(profile) {
    profile = profile || {};

    var rules = [
      {
        id: 'SOMEIP-SEC-01',
        title: 'SOME/IP-SD Service Offer Whitelisting & Rogue Offer Protection',
        standard: 'ISO 21434 Sec 9 / AUTOSAR Adaptive SOA Security',
        category: AUDIT_CATEGORIES.SERVICE_DISCOVERY,
        weight: 12,
        check: function (p) {
          if (p.sdWhitelistingEnabled && p.dropUnauthorizedOffers) {
            return { pass: true, detail: 'Strict SD Service ID & Instance ID authorization matrix active. Rogue OfferService frames immediately dropped and logged.' };
          }
          return { pass: false, severity: 'CRITICAL', detail: 'Unauthenticated Service Discovery. Malicious nodes can publish rogue OfferService frames to hijack vehicle RPC routing.' };
        }
      },
      {
        id: 'SOMEIP-SEC-02',
        title: 'SOME/IP-SD Multicast Rate Limiting & DoS Storm Throttling',
        standard: 'ISO 21434 DoS Protection / AUTOSAR PRS_SOMEIPSD',
        category: AUDIT_CATEGORIES.RESILIENCE,
        weight: 8,
        check: function (p) {
          if (p.sdRateLimiting && p.maxSdPacketsPerSec && p.maxSdPacketsPerSec <= 20) {
            return { pass: true, detail: 'Multicast 224.0.0.17 (Port 30490) rate-limited to ' + p.maxSdPacketsPerSec + ' pps. Broadcast storm amplification mitigated.' };
          }
          return { pass: false, severity: 'HIGH', detail: 'Unthrottled SD multicast listener. Vulnerable to CPU starvation and buffer exhaustion on central domain gateways.' };
        }
      },
      {
        id: 'SOMEIP-SEC-03',
        title: 'AUTOSAR SecOC Cryptographic Message Authentication (AES-128 CMAC)',
        standard: 'AUTOSAR SWS_SecOC / UNECE WP.29 R155',
        category: AUDIT_CATEGORIES.AUTHENTICATION,
        weight: 15,
        check: function (p) {
          if (p.secocEnabled && p.macAlgorithm && p.macAlgorithm.match(/AES-128-CMAC|HMAC-SHA256/i)) {
            var macBits = p.macTruncatedBits || 64;
            if (macBits >= 32) {
              return { pass: true, detail: 'SecOC active with ' + p.macAlgorithm + ' (' + macBits + '-bit MAC) and monotonic Freshness Value Manager (FVM).' };
            }
          }
          return { pass: false, severity: 'CRITICAL', detail: 'Unauthenticated SOME/IP RPC calls. Safety-critical control methods (brakes, steering) lack cryptographic MAC verification.' };
        }
      },
      {
        id: 'SOMEIP-SEC-04',
        title: 'AUTOSAR E2E (End-to-End) Protection & Sequence Validation',
        standard: 'ISO 26262 ASIL-D / AUTOSAR CP/AP E2E Profile',
        category: AUDIT_CATEGORIES.DATA_INTEGRITY,
        weight: 12,
        check: function (p) {
          if (p.e2eProfile && (p.e2eProfile === 'Profile 1' || p.e2eProfile === 'Profile 4' || p.e2eProfile === 'Profile 11') && p.e2eAliveCounterCheck) {
            return { pass: true, detail: 'E2E ' + p.e2eProfile + ' CRC and alive counter sequence verification active for all critical eventgroups.' };
          }
          return { pass: false, severity: 'HIGH', detail: 'Incomplete or absent E2E protection. Silent packet corruption, replay, and sequence gaps go undetected.' };
        }
      },
      {
        id: 'SOMEIP-SEC-05',
        title: 'Automotive Ethernet VLAN (IEEE 802.1Q) Domain Segmentation',
        standard: 'AUTOSAR Adaptive / ISO 21434 Sec 10',
        category: AUDIT_CATEGORIES.NETWORK_SEGMENTATION,
        weight: 12,
        check: function (p) {
          if (p.vlanIsolation && p.infotainmentVlanId && p.adasVlanId && p.infotainmentVlanId !== p.adasVlanId) {
            return { pass: true, detail: 'Infotainment SOME/IP isolated on VLAN ' + p.infotainmentVlanId + '; Autonomous ADAS domain isolated on VLAN ' + p.adasVlanId + '.' };
          }
          return { pass: false, severity: 'CRITICAL', detail: 'Flat automotive Ethernet switch topology. Compromised Android Automotive head unit can inject SOME/IP packets into ADAS.' };
        }
      },
      {
        id: 'SOMEIP-SEC-06',
        title: 'Client ID & Method-Level Authorization Access Control Lists',
        standard: 'NIST SP 800-207 Zero-Trust / AUTOSAR AP IAM',
        category: AUDIT_CATEGORIES.NETWORK_SEGMENTATION,
        weight: 10,
        check: function (p) {
          if (p.methodAclEnabled && p.rejectUnauthorizedClients) {
            return { pass: true, detail: 'Granular Identity & Access Management (IAM) maps authorized Client IDs strictly to designated Service and Method IDs.' };
          }
          return { pass: false, severity: 'HIGH', detail: 'Open RPC invocation. Any connected client can call arbitrary Service/Method IDs without permission validation.' };
        }
      },
      {
        id: 'SOMEIP-SEC-07',
        title: 'SOME/IP-TP Large Payload Reassembly Buffer Exhaustion Guard',
        standard: 'AUTOSAR PRS_SOMEIPTP / ISO 21434 DoS Guard',
        category: AUDIT_CATEGORIES.RESILIENCE,
        weight: 8,
        check: function (p) {
          var timeoutMs = p.tpReassemblyTimeoutMs || 5000;
          var maxBuf = p.tpMaxBufferBytes || 65536;
          if (p.tpGuardEnabled && timeoutMs <= 1000 && maxBuf <= 131072) {
            return { pass: true, detail: 'SOME/IP-TP fragment timeout capped at ' + timeoutMs + 'ms with strict ' + maxBuf + 'B reassembly buffer limit.' };
          }
          return { pass: false, severity: 'MEDIUM', detail: 'Excessive TP reassembly timeout. Fragment flood attacks can exhaust ECU dynamic RAM.' };
        }
      },
      {
        id: 'SOMEIP-SEC-08',
        title: 'Session ID Monotonic Tracking & Anti-Replay Guard',
        standard: 'AUTOSAR PRS_SOMEIP / ISO 21434 Sec 9',
        category: AUDIT_CATEGORIES.DATA_INTEGRITY,
        weight: 8,
        check: function (p) {
          if (p.sessionIdTracking && p.dropNonMonotonicSessions) {
            return { pass: true, detail: 'Strict Session ID monotonic increment verification active. Replayed requests with stale session IDs rejected.' };
          }
          return { pass: false, severity: 'MEDIUM', detail: 'Stateless Session ID handling. Susceptible to diagnostic and RPC replay attacks.' };
        }
      },
      {
        id: 'SOMEIP-SEC-09',
        title: 'Linux nftables Gateway Ingress Filtering & Port Containment',
        standard: 'NIST SP 800-41 / ISO 21434 Gateway Defense',
        category: AUDIT_CATEGORIES.NETWORK_SEGMENTATION,
        weight: 8,
        check: function (p) {
          if (p.nftablesFirewallActive && p.blockUntrustedEndpoints) {
            return { pass: true, detail: 'Linux nftables packet filtering enforced on gateway. Non-whitelisted IP/MAC endpoints blocked from ports 30490/30501.' };
          }
          return { pass: false, severity: 'HIGH', detail: 'No gateway packet filtering. Malicious Ethernet taps can reach internal SOME/IP listening sockets directly.' };
        }
      },
      {
        id: 'SOMEIP-SEC-10',
        title: 'Suricata / Zeek Layer 7 SOME/IP Deep Packet Inspection (DPI)',
        standard: 'UNECE WP.29 R155 CSMS / AUTOSAR IDS',
        category: AUDIT_CATEGORIES.INSPECTION,
        weight: 7,
        check: function (p) {
          if (p.idsLoggingEnabled && p.dpiSuricataSignaturesActive) {
            return { pass: true, detail: 'Suricata L7 SOME/IP parser active with real-time alerting on malformed headers, rogue SD offers, and SecOC MAC failures.' };
          }
          return { pass: false, severity: 'MEDIUM', detail: 'No real-time IDS/IPS inspection for vehicle SOA traffic. Zero-day RPC exploit attempts operate invisibly.' };
        }
      }
    ];

    var totalScore = 0;
    var maxScore = 0;
    var findings = [];
    var criticalCount = 0;
    var highCount = 0;
    var mediumCount = 0;
    var lowCount = 0;

    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      maxScore += r.weight;
      var outcome = r.check(profile);

      if (outcome.pass) {
        totalScore += r.weight;
      } else {
        if (outcome.severity === 'CRITICAL') criticalCount++;
        else if (outcome.severity === 'HIGH') highCount++;
        else if (outcome.severity === 'MEDIUM') mediumCount++;
        else if (outcome.severity === 'LOW') lowCount++;
      }

      findings.push({
        id: r.id,
        title: r.title,
        standard: r.standard,
        category: r.category,
        weight: r.weight,
        pass: outcome.pass,
        severity: outcome.severity || 'NONE',
        detail: outcome.detail
      });
    }

    var percentage = Math.round((totalScore / maxScore) * 100);
    var grade = 'F';
    if (percentage >= 95) grade = 'A+';
    else if (percentage >= 90) grade = 'A';
    else if (percentage >= 80) grade = 'B';
    else if (percentage >= 70) grade = 'C';
    else if (percentage >= 60) grade = 'D';

    var complianceStatus = (percentage >= 85 && criticalCount === 0) ? 'COMPLIANT' : 'NON_COMPLIANT';

    return {
      score: percentage,
      grade: grade,
      complianceStatus: complianceStatus,
      summary: {
        totalRules: rules.length,
        passedRules: rules.length - (criticalCount + highCount + mediumCount + lowCount),
        criticalVulnerabilities: criticalCount,
        highVulnerabilities: highCount,
        mediumVulnerabilities: mediumCount,
        lowVulnerabilities: lowCount
      },
      findings: findings,
      remediationSteps: generateRemediationRoadmap(findings)
    };
  }

  function generateRemediationRoadmap(findings) {
    var roadmap = [];
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      if (!f.pass) {
        var fix = 'Apply standard automotive hardening.';
        if (f.id === 'SOMEIP-SEC-01') fix = 'Enforce SOME/IP-SD static service authorization table in central gateway AUTOSAR configuration.';
        else if (f.id === 'SOMEIP-SEC-02') fix = 'Configure token-bucket rate limiting on multicast address 224.0.0.17 UDP 30490 (max 10 pps) on switch.';
        else if (f.id === 'SOMEIP-SEC-03') fix = 'Integrate AUTOSAR SecOC module using AES-128-CMAC with 64-bit truncated MAC and Freshness Value Manager (FVM).';
        else if (f.id === 'SOMEIP-SEC-04') fix = 'Configure E2E Profile 4/11 for all safety-relevant eventgroups with CRC-32 and alive counter monitoring.';
        else if (f.id === 'SOMEIP-SEC-05') fix = 'Map Infotainment (IVI) to VLAN 200 and Autonomous Drive / Braking to VLAN 300 with ACL inter-VLAN routing drop.';
        else if (f.id === 'SOMEIP-SEC-06') fix = 'Implement IAM access control checking Client ID before dispatching incoming SOME/IP method handlers.';
        else if (f.id === 'SOMEIP-SEC-07') fix = 'Set SOME/IP-TP fragment reassembly timer to 500ms and cap concurrent reassembly buffers to 64KB.';
        else if (f.id === 'SOMEIP-SEC-08') fix = 'Enable stateful session tracking on RPC server instances; discard requests with non-increasing Session IDs.';
        else if (f.id === 'SOMEIP-SEC-09') fix = 'Deploy nftables rules dropping all unauthorized L4 traffic to ports 30490 and 30501.';
        else if (f.id === 'SOMEIP-SEC-10') fix = 'Install Suricata SOME/IP L7 signatures on vehicle intrusion detection gateway.';

        roadmap.push({
          ruleId: f.id,
          severity: f.severity,
          action: fix
        });
      }
    }
    return roadmap;
  }

  return {
    AUDIT_CATEGORIES: AUDIT_CATEGORIES,
    auditDeployment: auditDeployment
  };
}));
