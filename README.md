# Packet Feature Extraction and Prediction

## Overview

This project is designed to extract features from network packets captured in PCAP files and use a machine learning model to predict whether the packets are normal or abnormal. The tool provides a graphical user interface (GUI) for user interaction, built using the Tkinter library in Python.

## Features

- **PCAP File Browsing**: Select PCAP files from your file system.
- **Feature Extraction**: Extract relevant features from network packets.
- **Feature Encoding**: Encode categorical features for machine learning.
- **Prediction**: Use a pre-trained machine learning model to classify network packets as normal or abnormal.
- **Results Display**: View prediction results in a user-friendly format.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/packet-feature-extraction.git
    cd packet-feature-extraction
    ```

2. **Install the required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the application**:
    ```bash
    python main.py
    ```

2. **GUI Operations**:
    - **Browse PCAP File**: Click "Browse" to select a PCAP file.
    - **Extract Features**: Click "Extract Features" to extract features from the selected PCAP file.
    - **Browse CSV File**: Click "Browse" to select a CSV file containing extracted features.
    - **Encode and Save**: Click "Encode and Save" to encode categorical features and save them to a new CSV file.
    - **Predict**: Click "Predict" to use the pre-trained model to classify packets based on the encoded features.
    - **View Results**: Click "Result" in the menu to view the prediction results.

## File Structure

- **main.py**: The main script to run the GUI application.
- **requirements.txt**: The list of required Python packages.
- **trained_model.joblib**: The pre-trained machine learning model used for predictions.

## Dependencies

- Python 3.x
- Tkinter
- Scapy
- Pandas
- Scikit-learn
- Joblib

## Example

1. **Select a PCAP File**:
    - Click "Browse" to select a PCAP file.
    - The selected file path will be displayed in the entry widget.

2. **Extract Features**:
    - Click "Extract Features" to process the PCAP file and extract features.
    - A success message will be displayed upon completion.

3. **Encode and Save**:
    - Click "Browse" to select a CSV file containing extracted features.
    - Click "Encode and Save" to encode categorical features and save them to a new CSV file.
    - A success message will be displayed upon completion.

4. **Predict**:
    - Click "Predict" to classify the packets based on the encoded features.
    - The results will be displayed in the text widget, indicating whether each packet is normal or abnormal.

## Notes

- Ensure that the PCAP file is valid and contains network packets.
- The pre-trained model should be present in the same directory as the script (`trained_model.joblib`).

