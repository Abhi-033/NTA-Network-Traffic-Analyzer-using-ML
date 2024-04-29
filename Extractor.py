from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *
import pandas as pd

# Function to extract features from packets
def extract_features(packet, connection_stats):
    features = {}
    
    # Extract source bytes
    if TCP in packet and 'len' in packet[TCP].fields:
        features['src_bytes'] = packet[TCP].len
    elif UDP in packet:
        features['src_bytes'] = len(packet[UDP].payload)
    else:
        features['src_bytes'] = 0
    
    # Extract same service rate
    features['same_srv_rate'] = connection_stats['same_service'] / connection_stats['total']
    
    # Extract destination host service count
    features['dst_host_srv_count'] = connection_stats['dst_host_srv_count']
    
    # Extract logged in
    features['logged_in'] = 1 if 'Raw' in packet else 0
    
    # Extract destination bytes
    if IP in packets:
        if TCP in packets:
            features['dst_bytes'] = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
        else:
            features['dst_bytes'] = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
    else:
        features['dst_bytes'] = 0
        
    # Extract flag
    features['flag'] = packet[TCP].flags if TCP in packet else ''
    
    # Extract difference service rate
    features['diff_srv_rate'] = 1 - (connection_stats['same_service'] / connection_stats['total'])
    
    # Extract destination host same source port rate
    features['dst_host_same_src_port_rate'] = connection_stats['dst_host_same_src_port_count'] / connection_stats['total']
    
    # Extract destination host same service rate
    features['dst_host_same_srv_rate'] = connection_stats['dst_host_same_srv_count'] / connection_stats['total']
    
    # Increment count for this specific connection
    if IP in packet:
        if TCP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[TCP].dport)
        elif UDP in packet:
            connection_key = (packet[IP].src, packet[IP].dst, packet[UDP].dport)
        else:
            connection_key = (packet[IP].src, packet[IP].dst, None)
    else:
        connection_key = (None, None, None)

    # Increment count for this specific connection
    connection_counts[connection_key] = connection_counts.get(connection_key, 0) + 1
    features['count'] = connection_counts.get(connection_key, 0)
    
    # Extract destination host serror rate
    features['dst_host_serror_rate'] = connection_stats['dst_host_serror_count'] / connection_stats['total']
    
    # Extract service
    features['service'] = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
    
    # Extract protocol type
    features['protocol_type'] = 'TCP' if TCP in packet else 'UDP'
    
    # Extract service count
    features['srv_count'] = connection_stats['srv_count']
    
    # Extract destination host service different host rate
    features['dst_host_srv_diff_host_rate'] = connection_stats['dst_host_srv_diff_host_count'] / connection_stats['total']
    
    # Extract service serror rate
    features['srv_serror_rate'] = connection_stats['srv_serror_count'] / connection_stats['total']
    
    # Extract hot (Number of times a destination host has been contacted)
    features['hot'] = connection_stats['dst_host_count']
    
    # Extract destination host count
    features['dst_host_count'] = connection_stats['dst_host_count']
    
    # Extract destination host rerror rate
    features['dst_host_rerror_rate'] = connection_stats['dst_host_rerror_count'] / connection_stats['total']
    
    # Extract destination host different service rate
    features['dst_host_diff_srv_rate'] = connection_stats['dst_host_diff_srv_count'] / connection_stats['total']

    return features

# Read packets from the pcap file
pcap_file = "demo.pcap"
packets = rdpcap(pcap_file)

# Initialize previous variables
previous_dst = None
previous_service = None
previous_src_port = None
previous_src = None

# Connection statistics
connection_stats = {
    'total': 0,
    'same_service': 0,
    'dst_host_srv_count': 0,
    'dst_host_same_src_port_count': 0,
    'dst_host_same_srv_count': 0,
    'dst_host_serror_count': 0,
    'srv_count': 0,
    'dst_host_srv_diff_host_count': 0,
    'srv_serror_count': 0,
    'dst_host_count': 0,
    'dst_host_rerror_count': 0,
    'dst_host_diff_srv_count': 0
}

# Initialize connection counts dictionary
connection_counts = {}

# List to store extracted features
all_features = []

# Extract features from each packet
for packet in packets:
    # Check if packet contains IP layer
    if IP in packet:
        connection_stats['total'] += 1
        # Here you should implement the logic to update connection_stats
        # For example, if the packet has the same service as the previous one, increment 'same_service'
        # You need to adjust this logic based on how you define 'same service' in your context.
        # This is just an example logic.

        if previous_dst and previous_service and packet[IP].dst == previous_dst and TCP in packet and packet[TCP].dport == previous_service:
            connection_stats['same_service'] += 1
        
        # Increment dst_host_srv_count if the packet has the same destination host and service as the previous one
        if previous_dst and previous_service and packet[IP].dst == previous_dst and TCP in packet and packet[TCP].dport == previous_service:
            connection_stats['dst_host_srv_count'] += 1
        
        # Increment dst_host_same_src_port_count if the packet has the same destination host and source port as the previous one
        if previous_dst and previous_src_port and packet[IP].dst == previous_dst and TCP in packet and packet[TCP].sport == previous_src_port:
            connection_stats['dst_host_same_src_port_count'] += 1
        
        # Increment dst_host_same_srv_count if the packet has the same destination host and service as the previous one
        if previous_dst and previous_service and packet[IP].dst == previous_dst and TCP in packet and packet[TCP].dport == previous_service:
            connection_stats['dst_host_same_srv_count'] += 1
        
        # Increment dst_host_serror_count if the packet has an error response from the destination host
        if 'ICMP' in packet and packet[ICMP].type == 3:
            connection_stats['dst_host_serror_count'] += 1
        
        # Increment srv_count to count the number of services
        connection_stats['srv_count'] += 1
        
        # Increment dst_host_srv_diff_host_count if the packet has the same destination host but different source host
        if previous_dst and previous_src and packet[IP].dst == previous_dst and packet[IP].src != previous_src:
            connection_stats['dst_host_srv_diff_host_count'] += 1
        
        # Increment srv_serror_count if the packet has an error response for the service
        if 'ICMP' in packet and packet[ICMP].type == 3:
            connection_stats['srv_serror_count'] += 1
        
        # Update destination host count
        if IP in packets:
            connection_stats['dst_host_count'] = len(set([pkt[IP].dst for pkt in packets]))
        else:
            connection_stats['dst_host_count'] = 0
        # Increment dst_host_rerror_count if the packet has an error response from the destination host
        if 'ICMP' in packet and packet[ICMP].type == 3:
            connection_stats['dst_host_rerror_count'] += 1
        
        # Update destination host count of different services
        if IP in packets:
            connection_stats['dst_host_diff_srv_count'] = len(set([pkt[TCP].dport for pkt in packets if TCP in pkt]))
        else:
            connection_stats['dst_host_diff_srv_count'] = 0

        features = extract_features(packet, connection_stats)
        all_features.append(features)  # Or do something else with the extracted features

        # Convert list of dictionaries to DataFrame
        df = pd.DataFrame(all_features)
    
        # Write DataFrame to CSV file
        df.to_csv('extracted_features.csv', index=False)

        # Update previous destination host, service, source port, and source host
        previous_dst = packet[IP].dst
        if TCP in packet:
            previous_service = packet[TCP].dport
            previous_src_port = packet[TCP].sport
            previous_src = packet[IP].src
