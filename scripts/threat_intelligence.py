import requests

def fetch_threat_intelligence():
    # Fetching updated threat list from an external source (simulated)
    threat_list_url = 'https://example.com/threat_list'
    response = requests.get(threat_list_url)
    if response.status_code == 200:
        return response.json()  # Assuming the data is in JSON format
    return []

def check_threat_intelligence(ip_address):
    known_threats = fetch_threat_intelligence()
    if ip_address in known_threats:
        return "High"
    return "Low"
