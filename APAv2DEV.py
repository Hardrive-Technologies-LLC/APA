import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import numpy as np
import tensorflow as tf
from transformers import BertTokenizer, TFBertForSequenceClassification
import pyshark
from web3 import Web3
import boto3
import speech_recognition as sr
import pyttsx3
from statsmodels.tsa.arima.model import ARIMA
from scapy.all import *
import pybotx
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import cv2
import numpy as np
from PIL import Image, ImageTk
import json
import requests
import time
from datetime import datetime
import threading
import sys
import configparser
import os
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import queue
import warnings
import cryptography
from cryptography.utils import CryptographyDeprecationWarning
from botocore.exceptions import NoCredentialsError, ClientError
import re
import networkx as nx
import schedule

## Developer Mode ##
IN_MAIN_THREAD = threading.current_thread() is threading.main_thread()


#Warning Suppression
warnings.filterwarnings("ignore", category=DeprecationWarning)
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
warnings.filterwarnings("ignore", category=cryptography.utils.CryptographyDeprecationWarning)

# Placeholder for federated learning simulator
class FederatedLearningSimulator:
    def simulate_client_updates(self, num_clients):
        # Placeholder implementation
        return [{"accuracy": np.random.random()} for _ in range(num_clients)]

    def aggregate_models(self, client_updates):
        # Placeholder implementation
        return {"accuracy": np.mean([update["accuracy"] for update in client_updates])}

def initialize_aws_config():
        # Set AWS credentials and region
        # Replace these with your actual AWS credentials and preferred region
        os.environ['AWS_ACCESS_KEY_ID'] = 'your_access_key'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'your_secret_key'
        os.environ['AWS_DEFAULT_REGION'] = 'us-west-2'  # or any other region you prefer

        # Verify AWS configuration
        try:
            boto3.client('sts').get_caller_identity()
            print("AWS configuration successful")
        except NoCredentialsError:
            print("AWS credentials not found or incorrect")
        except ClientError as e:
            print(f"AWS configuration error: {e}")

class IntegrationConfigDialog(simpledialog.Dialog):
    def __init__(self, parent, title, initial_values=None):
        self.initial_values = initial_values or {}
        super().__init__(parent, title)

    def body(self, master):
        self.integrations = ['None','Splunk', 'ELK', 'Custom Webhook']
        self.integration_var = tk.StringVar(value=self.initial_values.get('integration', 'None'))
        
        tk.Label(master, text="Select Integration:").grid(row=0)
        self.integration_menu = ttk.Combobox(master, textvariable=self.integration_var, values=self.integrations)
        self.integration_menu.grid(row=0, column=1)
        
        self.integration_menu.bind('<<ComboboxSelected>>', self.on_integration_change)
        
        self.config_frame = ttk.Frame(master)
        self.config_frame.grid(row=1, column=0, columnspan=2)
        
        self.on_integration_change()
        
        return self.integration_menu

    def on_integration_change(self, event=None):
        for widget in self.config_frame.winfo_children():
            widget.destroy()
        
        integration = self.integration_var.get()
        if integration == 'Splunk':
            self.create_splunk_config()
        elif integration == 'ELK':
            self.create_elk_config()
        elif integration == 'Custom Webhook':
            self.create_webhook_config()

    def create_splunk_config(self):
        tk.Label(self.config_frame, text="Splunk Host:").grid(row=0)
        tk.Label(self.config_frame, text="Splunk Port:").grid(row=1)
        tk.Label(self.config_frame, text="Splunk Token:").grid(row=2)
        tk.Label(self.config_frame, text="Splunk Index:").grid(row=3)

        self.host_entry = tk.Entry(self.config_frame)
        self.port_entry = tk.Entry(self.config_frame)
        self.token_entry = tk.Entry(self.config_frame, show="*")
        self.index_entry = tk.Entry(self.config_frame)

        self.host_entry.grid(row=0, column=1)
        self.port_entry.grid(row=1, column=1)
        self.token_entry.grid(row=2, column=1)
        self.index_entry.grid(row=3, column=1)

    def create_elk_config(self):
        tk.Label(self.config_frame, text="ELK Host:").grid(row=0)
        tk.Label(self.config_frame, text="ELK Port:").grid(row=1)
        tk.Label(self.config_frame, text="ELK Index:").grid(row=2)

        self.elk_host_entry = tk.Entry(self.config_frame)
        self.elk_port_entry = tk.Entry(self.config_frame)
        self.elk_index_entry = tk.Entry(self.config_frame)

        self.elk_host_entry.grid(row=0, column=1)
        self.elk_port_entry.grid(row=1, column=1)
        self.elk_index_entry.grid(row=2, column=1)

    def create_webhook_config(self):
        tk.Label(self.config_frame, text="Webhook URL:").grid(row=0)
        self.webhook_url_entry = tk.Entry(self.config_frame)
        self.webhook_url_entry.grid(row=0, column=1)

    def apply(self):
        integration = self.integration_var.get()
        self.result = {'integration': integration}
        
        if integration == 'Splunk':
            self.result.update({
                'host': self.host_entry.get(),
                'port': self.port_entry.get(),
                'token': self.token_entry.get(),
                'index': self.index_entry.get()
            })
        elif integration == 'ELK':
            self.result.update({
                'elk_host': self.elk_host_entry.get(),
                'elk_port': self.elk_port_entry.get(),
                'elk_index': self.elk_index_entry.get()
            })
        elif integration == 'Custom Webhook':
            self.result.update({
                'webhook_url': self.webhook_url_entry.get()
            })

#initialize_aws_config()
    

class PacketAnalyzerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Packet Analyzer")
        self.master.geometry("1000x700")
        self.last_map_update = 0
        self.map_update_cooldown = 5  # 5 seconds cooldown
        try:
            self.packet_queue = queue.Queue()
            self.master.after(100, self.process_packet_queue)
            self.log_queue = queue.Queue()
            self.master.after(100, self.process_log_queue)
            self.captured_packets = []
            self.protocol_stats = {'TCP': 0, 'UDP': 0, 'Other': 0}
            self.gui_queue = queue.Queue()
            self.master.after(100, self.process_gui_queue)

            self.notebook = ttk.Notebook(master)
            self.notebook.pack(expand=True, fill='both')

            self.main_frame = ttk.Frame(self.notebook)
            self.stats_frame = ttk.Frame(self.notebook)
            self.rules_frame = ttk.Frame(self.notebook)
            self.network_map_frame = ttk.Frame(self.notebook)
            self.alerts_frame = ttk.Frame(self.notebook)
            self.ml_frame = ttk.Frame(self.notebook)
            self.schedule_frame = ttk.Frame(self.notebook)
            self.report_frame = ttk.Frame(self.notebook)
            self.about_frame = ttk.Frame(self.notebook)
            
            self.notebook.add(self.main_frame, text='Main')
            self.notebook.add(self.stats_frame, text='Statistics')
            self.notebook.add(self.rules_frame, text='Rules')
            self.notebook.add(self.network_map_frame, text='Network Map')
            self.notebook.add(self.alerts_frame, text='Alerts')
            self.notebook.add(self.ml_frame, text='Machine Learning')
            self.notebook.add(self.schedule_frame, text='Schedule')
            self.notebook.add(self.report_frame, text='Reports')
            self.notebook.add(self.about_frame, text='About')
            
            self.setup_main_frame()
            self.setup_stats_frame()
            self.setup_rules_frame()
            self.setup_network_map_frame()
            self.setup_alerts_frame()
            self.setup_ml_frame()
            self.setup_schedule_frame()
            self.setup_report_frame()
            self.setup_about_frame()

            self.config = configparser.ConfigParser()
            self.config_file = 'packet_analyzer_config.ini'
            self.load_config()

            self.capture_thread = None
            self.stop_capture_flag = threading.Event()

            self.network_map_canvas = None

            self.app_layer_stats = {}
            self.packet_count_history = []
            self.packet_count = 0
            self.captured_packets = []
        
            self.protocol_stats = {'TCP': 0, 'UDP': 0, 'Other': 0}
            self.connection_graph = nx.Graph()

            self.MALICIOUS_PATTERNS = [
                re.compile(r'(?i)malware'),
                re.compile(r'(?i)virus'),
                re.compile(r'(?i)trojan'),
                re.compile(r'(?i)botnet'),
                re.compile(r'(?i)exploit'),
                # Add more patterns as needed
                re.compile(r'(?i)(?:(?:eval|exec)\s*\()', re.IGNORECASE),
                re.compile(r'(?i)(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\s+', re.IGNORECASE),
                re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'(?:/\*(?:.|[\r\n])*?\*/|(?://|--)[^\r\n]*)', re.IGNORECASE),
            ]

            # Initialize advanced components
            self.init_dpi()
            self.init_ai_threat_detection()
            self.init_blockchain()
            self.init_cloud_integration()
            self.init_nlp()
            self.init_predictive_analytics()
            self.init_automated_remediation()
            self.init_iot_fingerprinting()
            self.init_speech_recognition()
            self.init_quantum_resistant_crypto()
            self.init_federated_learning()
        except Exception as e:
            print(f"Error during initialization: {e}")
            messagebox.showerror("Initialization Error", f"An error occurred during initialization: {e}")
        
    def setup_main_frame(self):
        self.start_button = tk.Button(self.main_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.main_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.settings_button = tk.Button(self.main_frame, text="Integration Settings", command=self.open_settings)
        self.settings_button.pack(pady=10)

        self.export_button = tk.Button(self.main_frame, text="Export Logs", command=self.export_logs)
        self.export_button.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=80, height=20)
        self.log_area.pack(padx=10, pady=10)

    def setup_stats_frame(self):
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def setup_rules_frame(self):
        self.rules_text = scrolledtext.ScrolledText(self.rules_frame, wrap=tk.WORD, width=80, height=20)
        self.rules_text.pack(padx=10, pady=10)
        self.rules_text.insert(tk.END, "# Enter custom rules here, one per line\n# Format: regex_pattern\n")

        save_rules_button = tk.Button(self.rules_frame, text="Save Rules", command=self.save_rules)
        save_rules_button.pack(pady=10)

    def setup_network_map_frame(self):
        self.network_fig, self.network_ax = plt.subplots(figsize=(5, 4))
        self.network_canvas = FigureCanvasTkAgg(self.network_fig, master=self.network_map_frame)
        self.network_canvas.draw()
        self.network_canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        #testing
        update_button = ttk.Button(self.network_map_frame, text="Update Network Map", command=self.update_network_map)
        update_button.pack(pady=10)

    def setup_alerts_frame(self):
        self.alert_text = scrolledtext.ScrolledText(self.alerts_frame, wrap=tk.WORD, width=80, height=15)
        self.alert_text.pack(padx=10, pady=10)

        tk.Label(self.alerts_frame, text="Alert Email:").pack()
        self.alert_email = tk.Entry(self.alerts_frame, width=40)
        self.alert_email.pack(pady=5)

        tk.Label(self.alerts_frame, text="Alert Threshold (packets/min):").pack()
        self.alert_threshold = tk.Entry(self.alerts_frame, width=10)
        self.alert_threshold.pack(pady=5)

        save_alert_settings = tk.Button(self.alerts_frame, text="Save Alert Settings", command=self.save_alert_settings)
        save_alert_settings.pack(pady=10)

    def setup_ml_frame(self):
        tk.Label(self.ml_frame, text="Anomaly Detection").pack(pady=10)
        self.train_ml_button = tk.Button(self.ml_frame, text="Train Model", command=self.train_anomaly_detector)
        self.train_ml_button.pack(pady=10)
        self.anomaly_results = scrolledtext.ScrolledText(self.ml_frame, wrap=tk.WORD, width=80, height=15)
        self.anomaly_results.pack(padx=10, pady=10)

    def setup_schedule_frame(self):
        tk.Label(self.schedule_frame, text="Schedule Capture").pack(pady=10)
        tk.Label(self.schedule_frame, text="Start Time (HH:MM):").pack()
        self.schedule_start = tk.Entry(self.schedule_frame, width=10)
        self.schedule_start.pack(pady=5)
        tk.Label(self.schedule_frame, text="Duration (minutes):").pack()
        self.schedule_duration = tk.Entry(self.schedule_frame, width=10)
        self.schedule_duration.pack(pady=5)
        schedule_button = tk.Button(self.schedule_frame, text="Schedule Capture", command=self.schedule_capture)
        schedule_button.pack(pady=10)
        self.scheduled_tasks_list = tk.Listbox(self.schedule_frame, width=50, height=5)
        self.scheduled_tasks_list.pack(pady=10)

    def setup_report_frame(self):
        tk.Label(self.report_frame, text="Generate Report").pack(pady=10)
        self.generate_report_button = tk.Button(self.report_frame, text="Generate Report", command=self.generate_report)
        self.generate_report_button.pack(pady=10)
        self.report_area = scrolledtext.ScrolledText(self.report_frame, wrap=tk.WORD, width=80, height=20)
        self.report_area.pack(padx=10, pady=10)

    def setup_about_frame(self):
        about_text = """
        Advanced Packet Analyzer
        Version 2.0

        Developed by: Hardrive Technologies LLC
        Email: THardisky@hardrivetech.net
        GitHub: https://github.com/Hardrive-Technologies-LLC/APA

        This application is an advanced packet analyzer with features including:
        - Deep Packet Inspection
        - AI-powered Threat Detection
        - Blockchain Integration
        - Cloud Integration
        - Natural Language Processing for Log Analysis
        - Augmented Reality Network Visualization
        - Predictive Analytics
        - Automated Remediation
        - IoT Device Fingerprinting
        - Voice Control
        - Quantum-Resistant Cryptography
        - Federated Learning for Collaborative Threat Intelligence

        © 2024 Hardrive Technologies LLC. All rights reserved.
        """

        about_label = tk.Label(self.about_frame, text=about_text, justify=tk.LEFT, padx=10, pady=10)
        about_label.pack(expand=True, fill='both')

        # You can add your photo here if you want
        # photo = tk.PhotoImage(file="path_to_your_photo.png")
        # photo_label = tk.Label(self.about_frame, image=photo)
        # photo_label.image = photo  # keep a reference!
        # photo_label.pack(pady=10)

    def init_dpi(self):
        self.dpi_capture = pyshark.LiveCapture(interface='eth0')

    def init_nlp(self):
        try:
            model_path = 'path/to/your/nlp_model'  # Update this with the correct path
            if os.path.exists(model_path):
                self.nlp_model = tf.keras.models.load_model(model_path)
            else:
                print(f"NLP model not found at {model_path}. Skipping NLP initialization.")
                self.nlp_model = None
        except Exception as e:
            print(f"Error initializing NLP model: {str(e)}")
            self.nlp_model = None

    def init_ai_threat_detection(self):
        self.threat_model = TFBertForSequenceClassification.from_pretrained('bert-base-uncased')
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased', clean_up_tokenization_spaces=True)

    def init_blockchain(self):
        self.w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        # Comment out or remove the following line if you don't have a specific contract
        # self.threat_log_contract = self.w3.eth.contract(address='CONTRACT_ADDRESS', abi=ABI)

    def init_cloud_integration(self):
        try:
            self.ec2_client = boto3.client('ec2', region_name='us-west-2')
        except Exception as e:
            print(f"Error initializing EC2 client: {e}")

    def init_nlp(self):
        # Initialize NLP model for log analysis
        self.nlp_model = tf.keras.models.load_model('path_to_nlp_model')

    def init_predictive_analytics(self):
        self.packet_count_history = []

    def init_automated_remediation(self):
        try:
            # Define collectors and bot_accounts properly
            collectors = []  # Define your collectors here
            bot_accounts = []  # Define your bot accounts here
            
            if not collectors or not bot_accounts:
                print("Warning: collectors or bot_accounts are empty. Automated remediation may not work properly.")
            
            self.botx_client = pybotx.Bot(collectors=collectors, bot_accounts=bot_accounts)
            # Set token if needed
            # self.botx_client.set_token('YOUR_BOTX_TOKEN')
        except Exception as e:
            print(f"Error initializing automated remediation: {e}")
            self.botx_client = None

    def init_iot_fingerprinting(self):
        try:
            model_path = 'actual/path/to/your/iot_model'  # Update this path
            if os.path.exists(model_path):
                self.iot_model = tf.keras.models.load_model(model_path)
            else:
                print(f"IoT model not found at {model_path}. IoT fingerprinting will be disabled.")
                self.iot_model = None
        except Exception as e:
            print(f"Error initializing IoT fingerprinting: {e}")
            self.iot_model = None
            
    def init_speech_recognition(self):
        try:
            self.recognizer = sr.Recognizer()
            print("Speech recognition initialized successfully")
        except ImportError:
            print("Speech recognition library not found. Speech recognition features will be disabled.")
            self.recognizer = None
        except AttributeError:
            print("Error: speech_recognition module doesn't have expected attributes. Check your installation.")
            self.recognizer = None
        except Exception as e:
            print(f"Unexpected error initializing speech recognition: {e}")
            self.recognizer = None


    def init_quantum_resistant_crypto(self):
        self.quantum_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

    def init_federated_learning(self):
        self.fl_simulator = FederatedLearningSimulator()

    def save_rules(self):
        rules = self.rules_text.get("1.0", tk.END).strip().split('\n')
        self.MALICIOUS_PATTERNS = [re.compile(rule) for rule in rules if rule and not rule.startswith('#')]
        messagebox.showinfo("Rules Saved", "Custom rules have been saved and applied.")

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config['Integration'] = {
                'type': 'None',
                'host': '',
                'port': '',
                'token': '',
                'index': ''
            }
            self.config['Alerts'] = {
                'email': '',
                'threshold': '100'
            }

    def save_config(self):
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

    def open_settings(self):
        initial_values = dict(self.config['Integration'])
        dialog = IntegrationConfigDialog(self.master, "Integration Settings", initial_values=initial_values)
        if dialog.result:
            self.config['Integration'] = dialog.result
            self.save_config()
            self.log("Integration settings updated.")

    def start_capture(self):
        self.captured_packets.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_capture_flag = threading.Event()
        self.capture_thread = threading.Thread(target=self.packet_capture)
        self.capture_thread.start()
        self.log("Packet capture started")

    def packet_capture(self):
        self.log("Starting packet capture...")
        try:
            sniff(prn=self.analyze_packet, store=0, stop_filter=lambda _: self.stop_capture_flag.is_set())
        except Exception as e:
            self.log(f"Error in packet capture: {str(e)}")
        finally:
            self.log("Packet capture stopped.")

    def queue_packet(self, packet):
        self.packet_queue.put(packet)

    def process_packet_queue(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if isinstance(item, str):
                    self.log(item)
                elif isinstance(item, scapy.packet.Packet):
                    self.analyze_packet(item)
                else:
                    self.log(f"Unknown item in queue: {item}")
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_packet_queue)

    def queue_packet(self, packet):
        self.packet_queue.put(("packet", packet))

    def stop_capture(self):
        if hasattr(self, 'stop_capture_flag'):
            self.stop_capture_flag.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.packet_queue.put("Stopping packet capture...")

    def log(self, message):
        if hasattr(self, 'log_queue'):
            self.log_queue.put(message)
        else:
            print(f"Log queue not initialized: {message}")

    def process_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_area.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
                self.log_area.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_log_queue)
     
    def send_to_integration(self, event_data):
        integration = self.integration_var.get()
        
        if integration == "None":
            # Do nothing if "None" is selected
            return
        
        elif integration == "Splunk":
            try:
                splunk_host = self.splunk_host_var.get()
                splunk_port = int(self.splunk_port_var.get())
                splunk_token = self.splunk_token_var.get()
                splunk_index = self.splunk_index_var.get()

                hec = SplunkHecHandler(splunk_host, splunk_token, port=splunk_port, index=splunk_index, verify=False)
                hec.pushEvent(event_data)
                self.log("Event sent to Splunk successfully")
            except Exception as e:
                self.log(f"Error sending event to Splunk: {str(e)}")

        elif integration == "ELK":
            try:
                elk_host = self.elk_host_var.get()
                elk_port = int(self.elk_port_var.get())
                elk_index = self.elk_index_var.get()

                es = Elasticsearch([{'host': elk_host, 'port': elk_port}])
                es.index(index=elk_index, body=event_data)
                self.log("Event sent to ELK successfully")
            except Exception as e:
                self.log(f"Error sending event to ELK: {str(e)}")

        elif integration == "Custom Webhook":
            try:
                webhook_url = self.webhook_url_var.get()
                response = requests.post(webhook_url, json=event_data)
                response.raise_for_status()
                self.log("Event sent to Custom Webhook successfully")
            except Exception as e:
                self.log(f"Error sending event to Custom Webhook: {str(e)}")

    def analyze_packet(self, packet):
        try:
            if not hasattr(self, 'packet_count'):
                self.packet_count = 0
                self.packet_count += 1
            if self.packet_count % 10 == 0:  # Update every 10 packets
                self.gui_queue.put(("update_stats", None))
                self.gui_queue.put(("update_network_map", None))
               

            protocol = "Unknown"
            src = "Unknown"
            dst = "Unknown"
            src_port = "Unknown"
            dst_port = "Unknown"
            payload = b""

            if IP in packet:
                protocol = "IP"
                src = packet[IP].src
                dst = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    payload = bytes(packet[TCP].payload)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    payload = bytes(packet[UDP].payload)
                else:
                    payload = bytes(packet[IP].payload)
            elif Ether in packet:
                protocol = "Ethernet"
                src = packet[Ether].src
                dst = packet[Ether].dst
                payload = bytes(packet[Ether].payload)
            elif Dot3 in packet:
                protocol = "Dot3"
                src = packet[Dot3].src
                dst = packet[Dot3].dst
                payload = bytes(packet[Dot3].payload)
            elif ARP in packet:
                protocol = "ARP"
                src = packet[ARP].psrc
                dst = packet[ARP].pdst
                payload = bytes(packet[ARP])
            else:
                protocol = packet.__class__.__name__
                payload = bytes(packet.payload)

            self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1

            # Add this near the beginning of the method
            packet_info = {
                'src': src,
                'dst': dst,
                'protocol': protocol
            }
            self.captured_packets.append(packet_info)
            
            # Queue log message
            log_message = f"Packet {self.packet_count}: {protocol} {src}:{src_port} -> {dst}:{dst_port}"
            self.gui_queue.put(("log", f"Captured packet: {packet_info}"))

            # Store packet for machine learning
            self.captured_packets.append({
                'src': src,
                'dst': dst,
                'protocol': protocol,
                'length': len(packet)
            })

            # Check for malicious patterns
            payload_str = payload.decode('utf-8', 'ignore')
            if hasattr(self, 'MALICIOUS_PATTERNS'):
                for pattern in self.MALICIOUS_PATTERNS:
                    if pattern.search(payload_str):
                        event_data = {
                            "timestamp": datetime.now().isoformat(),
                            "alert": "Potential malicious packet detected",
                            "protocol": protocol,
                            "src": src,
                            "src_port": src_port,
                            "dst": dst,
                            "dst_port": dst_port,
                            "payload_sample": payload_str[:100]
                        }
                        self.gui_queue.put(("log", f"Potential malicious packet detected: {pattern.pattern}"))
                        self.gui_queue.put(("log", json.dumps(event_data, indent=2)))
                        self.send_to_integration(event_data)
                        self.check_alerts(event_data)
                        break
            else:
                self.gui_queue.put(("log", "Warning: MALICIOUS_PATTERNS not defined"))

            if self.packet_count % 10 == 0:  # Update stats every 10 packets
                self.gui_queue.put(("update_stats", None))
                self.gui_queue.put(("update_network_map", None))
                self.update_network_map()

            self.analyze_packet_dpi(packet)
            self.ai_threat_detection(str(packet))
            self.packet_count_history.append(self.packet_count)
            
            # Periodically perform other analyses
            if self.packet_count % 100 == 0:
                self.gui_queue.put(("update_ar_visualization", None))
                self.gui_queue.put(("scan_iot_devices", None))

            if not hasattr(self, 'analyze_packet_dpi'):
                self.analyze_packet_dpi = lambda x: None  # No-op function if method doesn't exist

                self.analyze_packet_dpi(packet)
                self.ai_threat_detection(str(packet))

            if not hasattr(self, 'packet_count_history'):
                self.packet_count_history = []
                self.packet_count_history.append(self.packet_count)
            
        except Exception as e:
            error_msg = f"Error in analyze_packet: {str(e)}\n{traceback.format_exc()}"
            self.gui_queue.put(("log", error_msg))

    def process_gui_queue(self):
        try:
            while True:
                message = self.gui_queue.get_nowait()
                action = message[0]
                data = message[1] if len(message) > 1 else None
                if message[0] == "log":
                    self.log_area.insert(tk.END, message[1] + "\n")
                    self.log_area.see(tk.END)
                elif message[0] == "update_stats":
                    self.update_stats()
                elif message[0] == "update_network_map":
                     self.update_network_map()
                elif action == "analyze_logs_nlp":
                    self.analyze_logs_nlp(data)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_gui_queue)


    def update_stats(self):
        self.ax.clear()
        protocols = list(self.protocol_stats.keys())
        values = list(self.protocol_stats.values())
        self.ax.bar(protocols, values)
        self.ax.set_title('Protocol Distribution')
        self.ax.set_ylabel('Packet Count')
        self.canvas.draw()

    def clear_network_map(self):
        if not self.master.winfo_exists():
            return
        for widget in self.network_map_frame.winfo_children():
            widget.destroy()

    def display_no_data_message(self):
        if not self.master.winfo_exists():
            return
        message = tk.Label(self.network_map_frame, text="No network data to display")
        message.pack(expand=True)
        
    def draw_network_map(self, G):
        if not self.master.winfo_exists():
            print("Window no longer exists. Skipping network map update.")
            return

        def _draw():
            try:
                print("Starting to draw network map")
                self.clear_network_map()
                print("Network map cleared")

                loading_label = tk.Label(self.network_map_frame, text="Loading network map...")
                loading_label.pack(pady=10)
                self.master.update()

                # Create a frame for the map and controls
                map_frame = ttk.Frame(self.network_map_frame)
                map_frame.pack(fill=tk.BOTH, expand=True)

                fig = Figure(figsize=(8, 6), dpi=100)
                ax = fig.add_subplot(111)
                print("Figure and axes created")
                
                pos = nx.spring_layout(G)
                print("Spring layout calculated")
                nx.draw(G, pos, ax=ax, with_labels=True, node_color='lightblue', 
                        node_size=500, font_size=8, font_weight='bold')
                print("Network drawn")
                
                edge_labels = {(u, v): '' for (u, v) in G.edges()}
                nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax)
                print("Edge labels drawn")

                canvas = FigureCanvasTkAgg(fig, master=map_frame)
                print("Canvas created")
                canvas.draw()
                print("Canvas drawn")
                canvas_widget = canvas.get_tk_widget()
                canvas_widget.pack(fill=tk.BOTH, expand=True)
                print("Canvas packed")

                # Add navigation toolbar
                toolbar = NavigationToolbar2Tk(canvas, map_frame)
                toolbar.update()
                print("Toolbar added")

                # Add focus controls
                focus_frame = ttk.Frame(map_frame)
                focus_frame.pack(pady=10)
                
                self.focus_entry = ttk.Entry(focus_frame)
                self.focus_entry.pack(side=tk.LEFT, padx=5)
                
                focus_button = ttk.Button(focus_frame, text="Focus on Node", command=self.focus_on_entered_node)
                focus_button.pack(side=tk.LEFT)
                print("Focus controls added")

                loading_label.destroy()

                # Store current graph and positions for later use
                self.current_graph = G
                self.current_pos = pos

                # Enable zoom
                fig.canvas.mpl_connect('scroll_event', self.on_scroll)

            except Exception as e:
                print(f"Error drawing network map: {e}")
                print(traceback.format_exc())
                self.display_no_data_message()

        self.safe_after(0, _draw)

    def focus_on_entered_node(self):
        target = self.focus_entry.get()
        if target:
            self.focus_on_target(target)
        else:
            print("Please enter a node to focus on")

    def on_scroll(self, event):
        ax = event.inaxes
        if ax is None:
            return
        
        # get the current x and y limits
        cur_xlim = ax.get_xlim()
        cur_ylim = ax.get_ylim()
        
        # set the range
        cur_xrange = (cur_xlim[1] - cur_xlim[0])*.5
        cur_yrange = (cur_ylim[1] - cur_ylim[0])*.5
        
        xdata = event.xdata # get event x location
        ydata = event.ydata # get event y location
        
        if event.button == 'up':
            # deal with zoom in
            scale_factor = 0.9
        elif event.button == 'down':
            # deal with zoom out
            scale_factor = 1.1
        else:
            # deal with something that should never happen
            scale_factor = 1
        
        # set new limits
        ax.set_xlim([xdata - cur_xrange*scale_factor,
                     xdata + cur_xrange*scale_factor])
        ax.set_ylim([ydata - cur_yrange*scale_factor,
                     ydata + cur_yrange*scale_factor])
        
        event.canvas.draw() # force re-draw

    def focus_on_target(self, target_node):
        if not hasattr(self, 'current_graph') or not hasattr(self, 'current_pos'):
            print("No current graph or position data available")
            return

        if target_node not in self.current_graph.nodes():
            print(f"Target node {target_node} not found in the graph")
            return

        # Find the FigureCanvasTkAgg widget
        for widget in self.network_map_frame.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, FigureCanvasTkAgg):
                        canvas = child
                        break
                break
        else:
            print("Canvas not found")
            return

        fig = canvas.figure
        ax = fig.axes[0]

        # Get the position of the target node
        target_pos = self.current_pos[target_node]

        # Set the view to focus on the target node
        ax.set_xlim(target_pos[0] - 0.5, target_pos[0] + 0.5)
        ax.set_ylim(target_pos[1] - 0.5, target_pos[1] + 0.5)

        fig.canvas.draw()
    
    def update_network_map(self):
        current_time = time.time()
        if current_time - self.last_map_update < self.map_update_cooldown:
            print("Skipping map update due to cooldown")
            return

        try:
            print("Updating network map")
            G = nx.Graph()
            for packet in self.captured_packets:
                src = packet.get('src')
                dst = packet.get('dst')
                if src and dst:
                    G.add_edge(src, dst)

            print(f"Graph created with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")

            if G.number_of_nodes() > 0:
                self.safe_after(0, self.draw_network_map, G)
            else:
                self.safe_after(0, self.display_no_data_message)

            self.last_map_update = current_time
        except Exception as e:
            print(f"Error updating network map: {e}")
            print(traceback.format_exc())

    def update_gui(self):
        try:
            while True:
                message = self.gui_queue.get_nowait()
                if message[0] == "log":
                    self.log_area.insert(tk.END, message[1] + "\n")
                    self.log_area.see(tk.END)
                elif message[0] == "update_stats":
                    self.update_stats()
                elif message[0] == "update_network_map":
                    self.update_network_map()
                elif message[0] == "update_network_map":
                    G = self.update_network_map()
                    self.draw_network_map(G)
                elif message[0] == "custom":
                    message[1]()  # Execute the custom function
                elif message[0] == "analyze_logs_nlp":
                    self.analyze_logs_nlp(self.log_area.get("1.0", tk.END))
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.update_gui)

    def export_logs(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(['Timestamp', 'Message'])
                log_content = self.log_area.get("1.0", tk.END).split('\n')
                for line in log_content:
                    if line.strip():
                        timestamp, message = line.split(' - ', 1)
                        csvwriter.writerow([timestamp, message])
            messagebox.showinfo("Export Complete", f"Logs exported to {file_path}")

    def save_alert_settings(self):
        self.config['Alerts']['email'] = self.alert_email.get()
        self.config['Alerts']['threshold'] = self.alert_threshold.get()
        self.save_config()
        messagebox.showinfo("Settings Saved", "Alert settings have been saved.")

    def check_alerts(self, event_data):
        current_time = time.time()
        self.alert_rules.append(current_time)
        self.alert_rules = [t for t in self.alert_rules if current_time - t <= 60]  # Keep only last minute

        if len(self.alert_rules) >= int(self.config['Alerts']['threshold']):
            self.send_alert_email(event_data)

    def send_alert_email(self, event_data):
        email = self.config['Alerts']['email']
        if not email:
            self.log("Alert triggered, but no email configured.")
            return

        subject = "Packet Analyzer Alert"
        body = f"Alert triggered:\n\n{json.dumps(event_data, indent=2)}"

        msg = MIMEMultipart()
        msg['From'] = "your_email@example.com"
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login("your_email@gmail.com", "your_password")
            text = msg.as_string()
            server.sendmail("your_email@gmail.com", email, text)
            server.quit()
            self.log(f"Alert email sent to {email}")
        except Exception as e:
            self.log(f"Failed to send alert email: {str(e)}")

    def train_anomaly_detector(self):
        if len(self.captured_packets) < 100:
            messagebox.showwarning("Insufficient Data", "Capture more packets before training the model.")
            return

        features = []
        for p in self.captured_packets:
            try:
                length = p.get('length', 0)  # Use 0 if 'length' is not present
                protocol = p.get('protocol', 'Unknown')
                if isinstance(protocol, str) and protocol:
                    protocol_value = ord(protocol[0])
                else:
                    protocol_value = 0
                    features.append([length, protocol_value])
            except Exception as e:
                print(f"Error processing packet: {e}")
                print(f"Problematic packet: {p}")

        if not features:
            print("No valid features extracted. Cannot train anomaly detector.")
            return
        self.anomaly_detector.fit(features)
        self.log("Anomaly detection model trained.")

        # Detect anomalies in the captured packets
        anomalies = self.anomaly_detector.predict(features)
        anomaly_indices = [i for i, a in enumerate(anomalies) if a == -1]

        self.anomaly_results.delete('1.0', tk.END)
        self.anomaly_results.insert(tk.END, "Detected Anomalies:\n\n")
        for idx in anomaly_indices:
            self.anomaly_results.insert(tk.END, f"Anomaly in packet {idx}: {self.captured_packets[idx]}\n")

    def schedule_capture(self):
        try:
            duration_str = self.schedule_duration.get().strip()
            if not duration_str:
                raise ValueError("Duration cannot be empty")
            
            duration = int(duration_str)
            if duration <= 0:
                raise ValueError("Duration must be a positive integer")
            
            start_time_str = self.schedule_start_time.get().strip()
            if not start_time_str:
                raise ValueError("Start time cannot be empty")
            
            start_time = datetime.strptime(start_time_str, "%H:%M")
            current_time = datetime.now()
            scheduled_time = current_time.replace(hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0)
            
            if scheduled_time <= current_time:
                scheduled_time += timedelta(days=1)
            
            delay = (scheduled_time - current_time).total_seconds()
            
            self.master.after(int(delay * 1000), self.start_scheduled_capture, duration)
            
            message = f"Capture scheduled for {scheduled_time.strftime('%Y-%m-%d %H:%M')} with duration of {duration} seconds"
            self.log_area.insert(tk.END, message + "\n")
            self.log_area.see(tk.END)
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while scheduling the capture: {str(e)}")

    def start_scheduled_capture(self, duration):
        self.start_capture()
        self.master.after(duration * 1000, self.stop_capture)

    def update_scheduled_tasks_list(self):
        self.scheduled_tasks_list.delete(0, tk.END)
        for task in self.scheduled_tasks:
            self.scheduled_tasks_list.insert(tk.END, task)

    def generate_report(self):
        report = f"Packet Analyzer Report\n"
        report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        report += "Packet Statistics:\n"
        for protocol, count in self.protocol_stats.items():
            report += f"{protocol}: {count}\n"

        report += f"\nTotal Packets Captured: {self.packet_count}\n"

        report += "\nTop 10 Connections:\n"
        connections = self.connection_graph.edges()
        connection_counts = {}
        for src, dst in connections:
            key = f"{src} -> {dst}"
            connection_counts[key] = connection_counts.get(key, 0) + 1
        top_connections = sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for conn, count in top_connections:
            report += f"{conn}: {count}\n"

        self.report_area.delete('1.0', tk.END)
        self.report_area.insert(tk.END, report)

    def analyze_packet_dpi(self, packet):
        try:
            if not hasattr(self, 'app_layer_stats'):
                self.app_layer_stats = {}

            app = "Unknown"
            if IP in packet:
                if TCP in packet:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        app = "HTTP"
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        app = "HTTPS"
                    # Add more application layer protocols as needed
                elif UDP in packet:
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        app = "DNS"
                    # Add more UDP-based protocols as needed
            elif ARP in packet:
                app = "ARP"
            elif Ether in packet:
                app = "Ethernet"
            
            # Update application layer statistics
            self.app_layer_stats[app] = self.app_layer_stats.get(app, 0) + 1
            
            # Perform additional DPI analysis here if needed
            
        except Exception as e:
            self.gui_queue.put(("log", f"Error in analyze_packet_dpi: {str(e)}"))

    def ai_threat_detection(self, packet_data):
        try:
            if not hasattr(self, 'tokenizer') or not hasattr(self, 'model'):
                self.gui_queue.put(("log", "AI threat detection not initialized. Skipping."))
                return

            inputs = self.tokenizer(packet_data, return_tensors="tf", truncation=True, padding=True, max_length=128)
            outputs = self.model(inputs)
            predictions = tf.nn.softmax(outputs.logits, axis=-1)
            label = tf.argmax(predictions, axis=1)
            confidence = tf.reduce_max(predictions, axis=1)

            if label == 1 and confidence > 0.8:
                self.gui_queue.put(("log", f"Potential threat detected with {confidence.numpy()[0]:.2f} confidence"))
        except Exception as e:
            self.gui_queue.put(("log", f"Error in AI threat detection: {str(e)}"))

    def log_threat_to_blockchain(self, threat_data):
        tx_hash = self.threat_log_contract.functions.logThreat(threat_data).transact()
        self.w3.eth.wait_for_transaction_receipt(tx_hash)
        self.log(f"Blockchain: Threat logged to blockchain. Transaction: {tx_hash.hex()}")

    def distribute_capture(self):
        instances = self.ec2_client.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # Start packet capture on each EC2 instance
                instance_id = instance['InstanceId']
                self.log(f"Cloud: Starting capture on EC2 instance {instance_id}")

    def analyze_logs_nlp(self, log_data):
        # Use NLP to generate summary of log data
        summary = self.nlp_model.predict(log_data)
        self.log(f"NLP Log Analysis: {summary}")

    def predict_traffic(self):
        if len(self.packet_count_history) < 10:
            messagebox.showwarning("Insufficient Data", "Need more data for prediction")
            return
        model = ARIMA(self.packet_count_history, order=(1, 1, 1))
        results = model.fit()
        forecast = results.forecast(steps=10)  # Predict next 10 time periods
        self.prediction_result.delete('1.0', tk.END)
        self.prediction_result.insert(tk.END, f"Traffic Prediction for next 10 periods:\n{forecast}")
        self.log("Predictive Analytics: Traffic forecast generated")

    def automated_remediation(self, threat_data):
        affected_ip = threat_data['src_ip']
        # Use pybotx to isolate the affected system
        self.botx_client.send_message(f"Isolate system with IP {affected_ip}")
        self.log(f"Automated Remediation: Initiated isolation for IP {affected_ip}")

    def activate_voice_command(self):
        self.voice_result.config(text="Listening...")
        with sr.Microphone() as source:
            audio = self.recognizer.listen(source)
            try:
                command = self.recognizer.recognize_google(audio)
                self.process_voice_command(command)
            except sr.UnknownValueError:
                self.voice_result.config(text="Could not understand audio")

    def process_voice_command(self, command):
        if "start capture" in command.lower():
            self.start_capture()
            self.voice_result.config(text="Started packet capture")
        elif "stop capture" in command.lower():
            self.stop_capture()
            self.voice_result.config(text="Stopped packet capture")
        else:
            self.voice_result.config(text=f"Unrecognized command: {command}")

    def quantum_encrypt(self):
        message = "Sensitive network data"
        encrypted = self.quantum_key.public_key().encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.quantum_result.delete('1.0', tk.END)
        self.quantum_result.insert(tk.END, f"Encrypted data: {encrypted.hex()}")
        self.log("Quantum: Data encrypted with quantum-resistant algorithm")

    def start_federated_training(self):
        # Simulate federated learning process
        num_clients = 5
        for round in range(3):  # 3 rounds of training
            client_updates = self.fl_simulator.simulate_client_updates(num_clients)
            aggregated_model = self.fl_simulator.aggregate_models(client_updates)
            self.federated_result.insert(tk.END, f"Round {round+1}: Aggregated model accuracy: {aggregated_model['accuracy']:.2f}\n")
        self.log("Federated Learning: Completed training simulation")

    def safe_after(self, delay, func, *args):
        def wrapper():
            if self.master.winfo_exists():
                func(*args)
        self.master.after(delay, wrapper)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    
    root.mainloop()
