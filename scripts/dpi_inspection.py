import re

def dpi_scan(network_range):
    """
    Perform Deep Packet Inspection on the given network range.
    Example implementation with dummy packet data.
    """

    # Placeholder for packet data results (mock example)
    packet_data_list = [
        {'ip_address': '192.168.1.10', 'behavior_details': 'Normal HTTP traffic'},
        {'ip_address': '192.168.1.12', 'behavior_details': 'Suspicious SSH traffic'},
        'This is an incorrect string',  # Incorrect data type example
    ]
    
    detected_anomalies = []
    
    # Define suspicious patterns
    suspicious_patterns = ['suspicious', 'malicious', 'attack']

    # Analyze each packet's behavior details
    for packet_data in packet_data_list:
        if isinstance(packet_data, dict):  # Ensure it's a dictionary
            for pattern in suspicious_patterns:
                if re.search(pattern, packet_data.get('behavior_details', ''), re.IGNORECASE):
                    packet_data['anomalous'] = True
                    detected_anomalies.append(packet_data)
                else:
                    packet_data['anomalous'] = False
        else:
            print(f"Skipping invalid packet data: {packet_data}")

    return detected_anomalies
