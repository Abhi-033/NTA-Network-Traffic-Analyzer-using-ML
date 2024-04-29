import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from tkinter import ttk,filedialog, messagebox



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

def encode_and_save_features(input_df, output_csv):
    # Encode categorical features
    for col in input_df.columns:
        if input_df[col].dtype == 'object':
            label_encoder = LabelEncoder()
            input_df[col] = label_encoder.fit_transform(input_df[col])
    
    # Save the encoded DataFrame to CSV
    input_df.to_csv(output_csv, index=False)

def predict(input_csv, results_text):
    # Step 1: Load the pre-trained model
    model = joblib.load('trained_model.joblib')
    
    # Step 2: Load input CSV
    input_data = pd.read_csv(input_csv)

    # Step 3: Encode categorical variables
    for col in input_data.columns:
        if input_data[col].dtype == 'object':
            label_encoder = LabelEncoder()
            input_data[col] = label_encoder.fit_transform(input_data[col])

    # Step 4: Predict using the loaded model
    input_data_top20 = input_data[['src_bytes', 'same_srv_rate', 'dst_host_srv_count', 'logged_in', 'dst_bytes', 'flag', 'diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_same_srv_rate', 'count', 'dst_host_serror_rate', 'service', 'protocol_type', 'srv_count', 'dst_host_srv_diff_host_rate', 'srv_serror_rate', 'hot', 'dst_host_count', 'dst_host_rerror_rate', 'dst_host_diff_srv_rate']]
    predictions = model.predict(input_data_top20)

    # Step 5: Display predictions
    results_text.config(state=tk.NORMAL)
    results_text.delete(1.0, tk.END)
    for i, prediction in enumerate(predictions):
        result = f'Packet {i + 1}: '
        if prediction == 0:
            result += 'Normal\n'
            results_text.insert(tk.END, result, 'normal_tag')
        else:
            result += 'Abnormal\n'
            results_text.insert(tk.END, result, 'abnormal_tag')
    results_text.config(state=tk.DISABLED)

    # Step 6: Tag configuration for text color
    results_text.tag_configure('normal_tag', foreground='green')
    results_text.tag_configure('abnormal_tag', foreground='red')

    show_results()



def browse_file(entry_widget):
    global filename
    filename = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, filename)

def convert_to_csv(pcap_file_entry, output_csv):
    global previous_dst, previous_service, previous_src_port, previous_src
    global filename
    global packets 
    pcap_file = filename
    output_csv = "C:/Users/scer/Downloads/NTA-main/NTA/OUPUTS/extracted_features.csv" # Change output path here
    if not pcap_file:
        messagebox.showerror("Error", "Please select a valid PCAP file.")
        return
    packets = rdpcap(pcap_file)
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

        # Update previous destination host, service, source port, and source host
            previous_dst = packet[IP].dst
            if TCP in packet:
                previous_service = packet[TCP].dport
                previous_src_port = packet[TCP].sport
                previous_src = packet[IP].src
    
    df = pd.DataFrame(all_features)
    df.to_csv(output_csv, index=False)
    messagebox.showinfo("Success", "Features extracted and saved to CSV successfully.")

def browse(entry):
    global filename2
    filename2 = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    entry.delete(0, tk.END)
    entry.insert(0, filename2)

def encode_and_save(input_entry, output_csv):
    input_csv = filename2
    output_csv = "C:/Users/scer/Downloads/NTA-main/NTA/OUPUTS/encoded_features.csv" # Change output path here
    if not input_csv:
        messagebox.showerror("Error", "Please select a valid input CSV file.")
        return
    input_df = pd.read_csv(input_csv)
    encode_and_save_features(input_df, output_csv)
    messagebox.showinfo("Success", "Features encoded and saved to CSV successfully.")


# GUI setup
root = tk.Tk()
root.title("Packet Feature Extraction and Prediction")

def show_home():
    # Show components for the home page
    label_pcap_file.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    label_input_csv.grid(row=3, column=0, padx=5, pady=5, sticky="w")
    pcap_file_entry.grid(row=0, column=1, padx=5, pady=5)
    input_entry.grid(row=3, column=1, padx=5, pady=5)
    browse_button.grid(row=0, column=2, padx=5, pady=5)
    extract_button.grid(row=2, column=1, padx=5, pady=5)
    encode_button.grid(row=4, column=1, padx=5, pady=5)
    predict_button.grid(row=5, column=1, padx=5, pady=5)
    browse1_button.grid(row=3, column=2, padx=5, pady=5)
    results_text.grid_forget()  # Hide results text

def show_results():
    # Show components for the results page
    label_pcap_file.grid_forget()  # Hide label for PCAP File
    label_input_csv.grid_forget()  # Hide label for Input CSV
    tk.Label(root, text="Result:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
    results_text.grid(row=5, columnspan=3, padx=5, pady=5)
    pcap_file_entry.grid_forget()  # Hide file entry
    input_entry.grid_forget()  # Hide input entry
    browse_button.grid_forget()  # Hide browse button
    extract_button.grid_forget()  # Hide extract button
    encode_button.grid_forget()  # Hide encode button
    predict_button.grid_forget()  # Hide predict button'
    browse1_button.grid_forget()

# Create menu bar
menubar = tk.Menu(root)
menubar.add_command(label="Home", command=show_home)
menubar.add_command(label="Result", command=show_results)
root.config(menu=menubar)

# Create entry widgets for file paths with curved appearance
pcap_file_entry = ttk.Entry(root, width=50, style='My.TEntry')
output_csv = ttk.Entry(root, width=50, style='My.TEntry')
input_entry = ttk.Entry(root, width=50, style='My.TEntry')

# Create labels for entry widgets
label_pcap_file = tk.Label(root, text="PCAP File:")
label_pcap_file.grid(row=0, column=0, padx=5, pady=5, sticky="w")
label_input_csv = tk.Label(root, text="Input CSV:")
label_input_csv.grid(row=3, column=0, padx=5, pady=5, sticky="w")

# Create a custom style to give the entry widgets a curved appearance
s = ttk.Style(root)
s.theme_use('clam')
s.configure('flat.TEntry', borderwidth=0)

# Place entry widgets
pcap_file_entry.grid(row=0, column=1, padx=5, pady=5)
input_entry.grid(row=3, column=1, padx=5, pady=5)

# Create buttons for actions
browse_button = ttk.Button(root, text="Browse", command=lambda: browse_file(pcap_file_entry))
browse_button.grid(row=0, column=2, padx=5, pady=5)
extract_button = ttk.Button(root, text="Extract Features", command=lambda: convert_to_csv(pcap_file_entry, output_csv))
extract_button.grid(row=2, column=1, padx=5, pady=5)
encode_button = ttk.Button(root, text="Encode and Save", command=lambda: encode_and_save(input_entry, output_csv))
encode_button.grid(row=4, column=1, padx=5, pady=5)
browse1_button = ttk.Button(root, text="Browse", command=lambda: browse(input_entry))
browse1_button.grid(row=3, column=2, padx=5, pady=5)

# Create a text widget to display predictions
results_text = tk.Text(root, height=10, width=50, state=tk.DISABLED)
results_text.grid(row=5, columnspan=3, padx=5, pady=5)

# Create Predict button
predict_button = ttk.Button(root, text="Predict", command=lambda: predict(input_entry.get(), results_text))
predict_button.grid(row=4, column=1, padx=5, pady=5)

show_home()
# Start GUI main loop
root.mainloop()
