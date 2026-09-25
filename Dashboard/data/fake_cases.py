# --------------------------------------------------
# Fake case data
# --------------------------------------------------

FAKE_CASES = [
    {
        "id": "CASE-001",
        "type": "Port Scanning",
        "source_ip": "192.168.1.20",
        "priority": "High",
        "status": "Open",
    
        "description": (
            "Multiple connection attempts were detected from the same "
            "source IP against several destination ports within a short "
            "period of time."
        ),
    
        "attack_mapping": {
            "technique": "Network Service Scanning",
            "technique_id": "T1046",
            "tactic": "Discovery",
            "confidence": "High",
            "status": "Supported",
            "reason": (
                "The observed behaviour is consistent with repeated "
                "attempts to identify available network services."
            )
        },
    
        "events": [
            {
                "timestamp": "2026-06-20 10:02:14",
                "type": "Connection Attempt",
                "source_ip": "192.168.1.20",
                "destination_ip": "10.0.0.15",
                "destination_port": 22,
                "protocol": "TCP",
                "evidence": "EVE-000142"
            },
            {
                "timestamp": "2026-06-20 10:02:18",
                "type": "Connection Attempt",
                "source_ip": "192.168.1.20",
                "destination_ip": "10.0.0.15",
                "destination_port": 80,
                "protocol": "TCP",
                "evidence": "EVE-000143"
            },
            {
                "timestamp": "2026-06-20 10:02:21",
                "type": "Connection Attempt",
                "source_ip": "192.168.1.20",
                "destination_ip": "10.0.0.15",
                "destination_port": 443,
                "protocol": "TCP",
                "evidence": "EVE-000144"
            },
            {
                "timestamp": "2026-06-20 10:02:25",
                "type": "Connection Attempt",
                "source_ip": "192.168.1.20",
                "destination_ip": "10.0.0.15",
                "destination_port": 8080,
                "protocol": "TCP",
                "evidence": "EVE-000145"
            }
        ],
    
        "evidence": {
            "eve_id": "EVE-000142",
            "pcap_file": "capture_2026-06-20.pcapng",
            "packet_reference": "Packet 1842",
            "timestamp": "2026-06-20 10:02:14",
            "source": "192.168.1.20:42132",
            "destination": "10.0.0.15:22",
            "protocol": "TCP"
        }
    },
    
    {
        "id": "CASE-002",
        "type": "Failed Authentication",
        "source_ip": "192.168.1.45",
        "priority": "High",
        "status": "Reviewing",
    
        "description": (
            "Repeated failed authentication attempts were detected "
            "from the same source address."
        ),
    
        "attack_mapping": {
            "technique": "Brute Force",
            "technique_id": "T1110",
            "tactic": "Credential Access",
            "confidence": "Medium",
            "status": "Tentative",
            "reason": (
                "The repeated authentication failures may be consistent "
                "with a brute-force authentication attempt."
            )
        },
    
        "events": [
            {
                "timestamp": "2026-06-21 14:15:02",
                "type": "Failed Authentication",
                "source_ip": "192.168.1.45",
                "destination_ip": "10.0.0.20",
                "destination_port": 22,
                "protocol": "TCP",
                "evidence": "EVE-000821"
            },
            {
                "timestamp": "2026-06-21 14:15:06",
                "type": "Failed Authentication",
                "source_ip": "192.168.1.45",
                "destination_ip": "10.0.0.20",
                "destination_port": 22,
                "protocol": "TCP",
                "evidence": "EVE-000822"
            },
            {
                "timestamp": "2026-06-21 14:15:10",
                "type": "Failed Authentication",
                "source_ip": "192.168.1.45",
                "destination_ip": "10.0.0.20",
                "destination_port": 22,
                "protocol": "TCP",
                "evidence": "EVE-000823"
            }
        ],
    
        "evidence": {
            "eve_id": "EVE-000821",
            "pcap_file": "capture_2026-06-21.pcapng",
            "packet_reference": "Packet 5321",
            "timestamp": "2026-06-21 14:15:02",
            "source": "192.168.1.45:49321",
            "destination": "10.0.0.20:22",
            "protocol": "TCP"
        }
    },
    
        {
            "id": "CASE-003",
            "type": "High Connection Frequency",
            "source_ip": "192.168.1.73",
            "priority": "Medium",
            "status": "Open",
    
            "description": (
                "An unusually high number of connections from the same "
                "source address was observed during a limited time period."
            ),
    
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Medium",
                "status": "Tentative",
                "reason": (
                    "The high connection frequency may indicate network "
                    "discovery activity, but additional evidence is required."
                )
            },
    
            "events": [
                {
                    "timestamp": "2026-06-22 09:20:11",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.73",
                    "destination_ip": "10.0.0.30",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-001102"
                },
                {
                    "timestamp": "2026-06-22 09:20:18",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.73",
                    "destination_ip": "10.0.0.31",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-001103"
                },
                {
                    "timestamp": "2026-06-22 09:20:25",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.73",
                    "destination_ip": "10.0.0.32",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-001104"
                }
            ],
    
            "evidence": {
                "eve_id": "EVE-001102",
                "pcap_file": "capture_2026-06-22.pcapng",
                "packet_reference": "Packet 7412",
                "timestamp": "2026-06-22 09:20:11",
                "source": "192.168.1.73:51234",
                "destination": "10.0.0.30:80",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-004",
            "type": "Protocol Anomaly",
            "source_ip": "192.168.1.91",
            "priority": "Medium",
            "status": "Reviewing",
    
            "description": (
                "Network traffic was observed using a protocol combination "
                "that differs from the expected behaviour for the destination."
            ),
    
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "The behaviour may indicate service discovery, but the "
                    "available evidence is currently insufficient."
                )
            },
    
            "events": [
                {
                    "timestamp": "2026-06-23 16:42:08",
                    "type": "Protocol Anomaly",
                    "source_ip": "192.168.1.91",
                    "destination_ip": "10.0.0.40",
                    "destination_port": 161,
                    "protocol": "UDP",
                    "evidence": "EVE-001451"
                }
            ],
    
            "evidence": {
                "eve_id": "EVE-001451",
                "pcap_file": "capture_2026-06-23.pcapng",
                "packet_reference": "Packet 9214",
                "timestamp": "2026-06-23 16:42:08",
                "source": "192.168.1.91:51201",
                "destination": "10.0.0.40:161",
                "protocol": "UDP"
            }
        },
    
        {
            "id": "CASE-005",
            "type": "Repeated Connections",
            "source_ip": "192.168.1.112",
            "priority": "High",
            "status": "Open",
    
            "description": (
                "Repeated connections to the same destination were observed "
                "over an extended period."
            ),
    
            "attack_mapping": {
                "technique": "Application Layer Protocol",
                "technique_id": "T1071",
                "tactic": "Command and Control",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "Repeated communication may be consistent with periodic "
                    "command-and-control activity, but further evidence is required."
                )
            },
    
            "events": [
                {
                    "timestamp": "2026-06-24 11:03:10",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.112",
                    "destination_ip": "10.0.0.50",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-002001"
                },
                {
                    "timestamp": "2026-06-24 11:08:10",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.112",
                    "destination_ip": "10.0.0.50",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-002002"
                },
                {
                    "timestamp": "2026-06-24 11:13:10",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.112",
                    "destination_ip": "10.0.0.50",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-002003"
                }
            ],
    
            "evidence": {
                "eve_id": "EVE-002001",
                "pcap_file": "capture_2026-06-24.pcapng",
                "packet_reference": "Packet 12031",
                "timestamp": "2026-06-24 11:03:10",
                "source": "192.168.1.112:52144",
                "destination": "10.0.0.50:443",
                "protocol": "TCP"
            }
        },
        {
            "id": "CASE-006",
            "type": "Port Scanning",
            "source_ip": "192.168.1.134",
            "priority": "Low",
            "status": "Closed",
            "description": (
                "A small number of connection attempts were observed "
                "against several destination ports."
            ),
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "The observed connections may indicate service discovery, "
                    "but the number of attempts is limited."
                )
            },
            "events": [
                {
                    "timestamp": "2026-06-25 08:14:22",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.134",
                    "destination_ip": "10.0.0.60",
                    "destination_port": 21,
                    "protocol": "TCP",
                    "evidence": "EVE-002401"
                },
                {
                    "timestamp": "2026-06-25 08:14:27",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.134",
                    "destination_ip": "10.0.0.60",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002402"
                }
            ],
            "evidence": {
                "eve_id": "EVE-002401",
                "pcap_file": "capture_2026-06-25.pcapng",
                "packet_reference": "Packet 13421",
                "timestamp": "2026-06-25 08:14:22",
                "source": "192.168.1.134:43012",
                "destination": "10.0.0.60:21",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-007",
            "type": "Failed Authentication",
            "source_ip": "192.168.1.151",
            "priority": "High",
            "status": "Open",
            "description": (
                "Repeated authentication failures were detected over "
                "several minutes against the same destination."
            ),
            "attack_mapping": {
                "technique": "Brute Force",
                "technique_id": "T1110",
                "tactic": "Credential Access",
                "confidence": "High",
                "status": "Supported",
                "reason": (
                    "Repeated authentication failures against the same "
                    "service provide supporting evidence for brute-force activity."
                )
            },
            "events": [
                {
                    "timestamp": "2026-06-26 17:42:03",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.151",
                    "destination_ip": "10.0.0.70",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002601"
                },
                {
                    "timestamp": "2026-06-26 17:42:09",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.151",
                    "destination_ip": "10.0.0.70",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002602"
                },
                {
                    "timestamp": "2026-06-26 17:42:16",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.151",
                    "destination_ip": "10.0.0.70",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002603"
                },
                {
                    "timestamp": "2026-06-26 17:43:01",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.151",
                    "destination_ip": "10.0.0.70",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002604"
                },
                {
                    "timestamp": "2026-06-26 17:43:12",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.151",
                    "destination_ip": "10.0.0.70",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-002605"
                }
            ],
            "evidence": {
                "eve_id": "EVE-002601",
                "pcap_file": "capture_2026-06-26.pcapng",
                "packet_reference": "Packet 15102",
                "timestamp": "2026-06-26 17:42:03",
                "source": "192.168.1.151:50122",
                "destination": "10.0.0.70:22",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-008",
            "type": "Protocol Anomaly",
            "source_ip": "192.168.1.166",
            "priority": "Medium",
            "status": "Reviewing",
            "description": (
                "Several UDP communications were observed using a protocol "
                "combination that differs from the expected traffic pattern."
            ),
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "The traffic differs from the expected pattern and may "
                    "represent service discovery activity."
                )
            },
            "events": [
                {
                    "timestamp": "2026-06-27 06:21:44",
                    "type": "Protocol Anomaly",
                    "source_ip": "192.168.1.166",
                    "destination_ip": "10.0.0.80",
                    "destination_port": 161,
                    "protocol": "UDP",
                    "evidence": "EVE-002801"
                },
                {
                    "timestamp": "2026-06-27 06:22:03",
                    "type": "Protocol Anomaly",
                    "source_ip": "192.168.1.166",
                    "destination_ip": "10.0.0.81",
                    "destination_port": 161,
                    "protocol": "UDP",
                    "evidence": "EVE-002802"
                }
            ],
            "evidence": {
                "eve_id": "EVE-002801",
                "pcap_file": "capture_2026-06-27.pcapng",
                "packet_reference": "Packet 17201",
                "timestamp": "2026-06-27 06:21:44",
                "source": "192.168.1.166:51822",
                "destination": "10.0.0.80:161",
                "protocol": "UDP"
            }
        },
    
        {
            "id": "CASE-009",
            "type": "High Connection Frequency",
            "source_ip": "192.168.1.177",
            "priority": "Medium",
            "status": "Open",
            "description": (
                "A high number of connections to multiple destinations "
                "was observed within a short period."
            ),
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Medium",
                "status": "Tentative",
                "reason": (
                    "The number and distribution of connections may indicate "
                    "network discovery activity."
                )
            },
            "events": [
                {
                    "timestamp": "2026-06-28 09:05:11",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.177",
                    "destination_ip": "10.0.0.90",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-003001"
                },
                {
                    "timestamp": "2026-06-28 09:05:17",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.177",
                    "destination_ip": "10.0.0.91",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-003002"
                },
                {
                    "timestamp": "2026-06-28 09:05:23",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.177",
                    "destination_ip": "10.0.0.92",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-003003"
                },
                {
                    "timestamp": "2026-06-28 09:05:31",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.177",
                    "destination_ip": "10.0.0.93",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-003004"
                },
                {
                    "timestamp": "2026-06-28 09:05:39",
                    "type": "High Connection Frequency",
                    "source_ip": "192.168.1.177",
                    "destination_ip": "10.0.0.94",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-003005"
                }
            ],
            "evidence": {
                "eve_id": "EVE-003001",
                "pcap_file": "capture_2026-06-28.pcapng",
                "packet_reference": "Packet 19432",
                "timestamp": "2026-06-28 09:05:11",
                "source": "192.168.1.177:53211",
                "destination": "10.0.0.90:80",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-010",
            "type": "Repeated Connections",
            "source_ip": "192.168.1.188",
            "priority": "Low",
            "status": "Closed",
            "description": (
                "Periodic connections to the same destination were observed "
                "over a short period."
            ),
            "attack_mapping": {
                "technique": "Application Layer Protocol",
                "technique_id": "T1071",
                "tactic": "Command and Control",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "The repeated communication pattern may be relevant, "
                    "but the available evidence is insufficient to confirm "
                    "command-and-control activity."
                )
            },
            "events": [
                {
                    "timestamp": "2025-11-03 12:00:00",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.188",
                    "destination_ip": "10.0.0.100",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-004001"
                },
                {
                    "timestamp": "2025-11-03 12:05:00",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.188",
                    "destination_ip": "10.0.0.100",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-004002"
                },
                {
                    "timestamp": "2025-11-03 12:10:00",
                    "type": "Repeated Connection",
                    "source_ip": "192.168.1.188",
                    "destination_ip": "10.0.0.100",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-004003"
                }
            ],
            "evidence": {
                "eve_id": "EVE-004001",
                "pcap_file": "capture_2025-11-03.pcapng",
                "packet_reference": "Packet 22011",
                "timestamp": "2025-11-03 12:00:00",
                "source": "192.168.1.188:54001",
                "destination": "10.0.0.100:443",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-011",
            "type": "Failed Authentication",
            "source_ip": "192.168.1.201",
            "priority": "High",
            "status": "Reviewing",
            "description": (
                "Multiple authentication failures were recorded against "
                "a remote service."
            ),
            "attack_mapping": {
                "technique": "Brute Force",
                "technique_id": "T1110",
                "tactic": "Credential Access",
                "confidence": "Medium",
                "status": "Tentative",
                "reason": (
                    "The repeated failures are consistent with possible "
                    "credential guessing activity."
                )
            },
            "events": [
                {
                    "timestamp": "2025-07-14 21:32:10",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.201",
                    "destination_ip": "10.0.0.110",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-005001"
                },
                {
                    "timestamp": "2025-07-14 21:32:16",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.201",
                    "destination_ip": "10.0.0.110",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-005002"
                },
                {
                    "timestamp": "2025-07-14 21:32:22",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.201",
                    "destination_ip": "10.0.0.110",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-005003"
                },
                {
                    "timestamp": "2025-07-14 21:33:04",
                    "type": "Failed Authentication",
                    "source_ip": "192.168.1.201",
                    "destination_ip": "10.0.0.110",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-005004"
                }
            ],
            "evidence": {
                "eve_id": "EVE-005001",
                "pcap_file": "capture_2025-07-14.pcapng",
                "packet_reference": "Packet 28103",
                "timestamp": "2025-07-14 21:32:10",
                "source": "192.168.1.201:55021",
                "destination": "10.0.0.110:22",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-012",
            "type": "Port Scanning",
            "source_ip": "192.168.1.215",
            "priority": "High",
            "status": "Open",
            "description": (
                "A broad set of connection attempts was observed against "
                "multiple ports on the same destination."
            ),
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "High",
                "status": "Supported",
                "reason": (
                    "The source attempted connections to several common "
                    "network service ports within a short period."
                )
            },
            "events": [
                {
                    "timestamp": "2024-04-18 03:12:04",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.215",
                    "destination_ip": "10.0.0.120",
                    "destination_port": 21,
                    "protocol": "TCP",
                    "evidence": "EVE-006001"
                },
                {
                    "timestamp": "2024-04-18 03:12:09",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.215",
                    "destination_ip": "10.0.0.120",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "evidence": "EVE-006002"
                },
                {
                    "timestamp": "2024-04-18 03:12:15",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.215",
                    "destination_ip": "10.0.0.120",
                    "destination_port": 23,
                    "protocol": "TCP",
                    "evidence": "EVE-006003"
                },
                {
                    "timestamp": "2024-04-18 03:12:21",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.215",
                    "destination_ip": "10.0.0.120",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "evidence": "EVE-006004"
                },
                {
                    "timestamp": "2024-04-18 03:12:28",
                    "type": "Connection Attempt",
                    "source_ip": "192.168.1.215",
                    "destination_ip": "10.0.0.120",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "evidence": "EVE-006005"
                }
            ],
            "evidence": {
                "eve_id": "EVE-006001",
                "pcap_file": "capture_2024-04-18.pcapng",
                "packet_reference": "Packet 31002",
                "timestamp": "2024-04-18 03:12:04",
                "source": "192.168.1.215:56001",
                "destination": "10.0.0.120:21",
                "protocol": "TCP"
            }
        },
    
        {
            "id": "CASE-013",
            "type": "Protocol Anomaly",
            "source_ip": "192.168.1.229",
            "priority": "Medium",
            "status": "Closed",
            "description": (
                "Unusual UDP traffic was detected between a source and "
                "destination that normally communicate using another protocol."
            ),
            "attack_mapping": {
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "tactic": "Discovery",
                "confidence": "Low",
                "status": "Tentative",
                "reason": (
                    "The unusual protocol usage may represent service "
                    "discovery, although the evidence is inconclusive."
                )
            },
            "events": [
                {
                    "timestamp": "2024-09-07 18:21:33",
                    "type": "Protocol Anomaly",
                    "source_ip": "192.168.1.229",
                    "destination_ip": "10.0.0.130",
                    "destination_port": 161,
                    "protocol": "UDP",
                    "evidence": "EVE-007001"
                },
                {
                    "timestamp": "2024-09-07 18:23:41",
                    "type": "Protocol Anomaly",
                    "source_ip": "192.168.1.229",
                    "destination_ip": "10.0.0.130",
                    "destination_port": 162,
                    "protocol": "UDP",
                    "evidence": "EVE-007002"
                }
            ],
            "evidence": {
                "eve_id": "EVE-007001",
                "pcap_file": "capture_2024-09-07.pcapng",
                "packet_reference": "Packet 36210",
                "timestamp": "2024-09-07 18:21:33",
                "source": "192.168.1.229:57122",
                "destination": "10.0.0.130:161",
                "protocol": "UDP"
            }
        }
]