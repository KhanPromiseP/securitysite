def behavioral_analytics(network_data, user_profile_history):
    for entry in network_data:
        ip_address = entry['ip_address']
        behavior = entry['behavior_details']

        if ip_address in user_profile_history:
            profile = user_profile_history[ip_address]

            # Flag unusual behavior compared to historical data
            if behavior != profile['last_behavior']:
                entry['is_anomaly'] = True
                profile['last_behavior'] = behavior  # Update the behavior
        else:
            user_profile_history[ip_address] = {'last_behavior': behavior}
    return network_data
