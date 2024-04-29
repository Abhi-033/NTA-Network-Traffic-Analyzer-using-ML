import tkinter as tk
from tkinter import ttk

def on_enter(event):
    event.widget.config(bg="#7b91c7", fg="white", relief="sunken")

def on_leave(event):
    event.widget.config(bg="SystemButtonFace", fg="black", relief="raised")

root = tk.Tk()
root.title("Packet Feature Extraction and Prediction")

# Custom style for buttons
s = ttk.Style()
s.theme_use('clam')
s.configure('My.TButton', borderwidth=0, bordercolor="#2254d4", foreground="white", background="#1a367d", relief="raised", padding=5)
s.map('My.TButton', background=[('active', '#7b91c7')])

def show_home():
    # Show components for the home page
    label_pcap_file.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    label_input_csv.grid(row=3, column=0, padx=5, pady=5, sticky="w")
    pcap_file_entry.grid(row=0, column=1, padx=5, pady=5)
    input_entry.grid(row=3, column=1, padx=5, pady=5)
    browse_button.grid(row=0, column=2, padx=5, pady=5)
    extract_button.grid(row=2, column=1, padx=5, pady=5)
    encode_button.grid(row=3, column=2, padx=5, pady=5)
    predict_button.grid(row=4, column=1, padx=5, pady=5)
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

# Place entry widgets
pcap_file_entry.grid(row=0, column=1, padx=5, pady=5)
input_entry.grid(row=3, column=1, padx=5, pady=5)

# Create buttons for actions
browse_button = ttk.Button(root, text="Browse", style='My.TButton')
browse_button.grid(row=0, column=2, padx=5, pady=5)
browse_button.bind("<Enter>", on_enter)
browse_button.bind("<Leave>", on_leave)

extract_button = ttk.Button(root, text="Extract Features", style='My.TButton')
extract_button.grid(row=2, column=1, padx=5, pady=5)
extract_button.bind("<Enter>", on_enter)
extract_button.bind("<Leave>", on_leave)

encode_button = ttk.Button(root, text="Encode and Save", style='My.TButton')
encode_button.grid(row=3, column=2, padx=5, pady=5)
encode_button.bind("<Enter>", on_enter)
encode_button.bind("<Leave>", on_leave)

# Create a text widget to display predictions
results_text = tk.Text(root, height=10, width=50, state=tk.DISABLED)
results_text.grid(row=5, columnspan=3, padx=5, pady=5)

# Create Predict button
predict_button = ttk.Button(root, text="Predict", style='My.TButton')
predict_button.grid(row=4, column=1, padx=5, pady=5)
predict_button.bind("<Enter>", on_enter)
predict_button.bind("<Leave>", on_leave)

show_home()

root.mainloop()
