import numpy as np
from sklearn.ensemble import IsolationForest

def detect_anomalies(network_data):
    # Assuming network_data contains network-related features like packet size, duration, etc.
    features = []  # Collect relevant features from network_data

    for entry in network_data:
        # Example: Append some features (you can replace these with actual network data attributes)
        if 'packet_size' in entry and 'duration' in entry:
            features.append([entry['packet_size'], entry['duration']])
        # Ensure each entry has 'is_anomaly' key set to False by default
        entry['is_anomaly'] = False

    # Convert features to 2D array if it's not already
    if len(features) > 0:
        features = np.array(features).reshape(-1, len(features[0]))  # Ensure 2D shape

        iso_forest = IsolationForest(contamination=0.1)
        predictions = iso_forest.fit_predict(features)
        
        # Adding predictions back to the network_data entries
        for i, entry in enumerate(network_data):
            entry['is_anomaly'] = predictions[i] == -1  # -1 indicates anomaly
    else:
        print("No valid features for anomaly detection.")
    
    return network_data
