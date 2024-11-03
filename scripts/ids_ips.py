def detect_intrusions(network_data):
    ids_alerts = []
    signature_patterns = ['exploit', 'brute force', 'ddos']

    for entry in network_data:
        # Detect signature-based alerts
        if any(pattern in entry['behavior_details'].lower() for pattern in signature_patterns):
            ids_alerts.append({
                "ip_address": entry['ip_address'],
                "behavior_details": "Intrusion detected (signature-based)",
                "is_anomaly": True
            })
        
        # Detect anomaly-based alerts (open_ports check)
        open_ports = entry.get('open_ports', None)  # Safely get 'open_ports'
        if open_ports and len(open_ports) > 10:  # Arbitrary rule for open ports
            ids_alerts.append({
                "ip_address": entry['ip_address'],
                "behavior_details": "Potential port scan or intrusion",
                "is_anomaly": True
            })
    
    return ids_alerts
