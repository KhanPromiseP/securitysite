import requests

def monitor_website(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Basic content inspection for common vulnerabilities
        if 'error' in response.text.lower() or 'sql' in response.text.lower():
            vulnerability_detected = True
        else:
            vulnerability_detected = False

        ip_address = response.headers.get('X-Forwarded-For', 'Unknown')
        return {
            "ip_address": ip_address,
            "behavior_details": "Website login accessed",
            "vulnerability_detected": vulnerability_detected
        }
    except requests.exceptions.Timeout:
        return {"error": f"Request to {url} timed out."}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
