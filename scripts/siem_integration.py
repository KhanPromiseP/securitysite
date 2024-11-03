def correlate_events(network_data):
    correlated_events = []
    critical_ips = set()

    for entry in network_data:
        # Check if 'is_anomaly' is present and is True
        if entry.get('is_anomaly', False):
            critical_ips.add(entry['ip_address'])

    for ip in critical_ips:
        correlated_events.append({
            "ip_address": ip,
            "correlation_details": f"Anomalous events correlated for IP: {ip}",
            "severity": "Critical"
        })

    return correlated_events

