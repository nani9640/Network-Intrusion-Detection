# Network-Intrusion-Detection


from scapy.all import sniff
import matplotlib.pyplot as plt
from collections import defaultdict

# Define a simple rule for suspicious activity (e.g., HTTP requests to a specific IP)
suspicious_ips = {"192.168.1.100"}  # Example IP to monitor
alerts = defaultdict(int)  # To count alerts

def packet_callback(packet):
    # Check if the packet has IP layer
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        
        # Check for suspicious source IP
        if ip_src in suspicious_ips:
            print(f"ALERT: Suspicious activity detected from {ip_src} to {ip_dst}")
            alerts[ip_src] += 1

def visualize_alerts():
    # Visualize the alerts using a bar chart
    if alerts:
        plt.bar(alerts.keys(), alerts.values())
        plt.xlabel('IP Address')
        plt.ylabel('Number of Alerts')
        plt.title('Suspicious Activity Alerts')
        plt.show()
    else:
        print("No alerts to visualize.")

def main():
    print("Starting packet capture... (Press Ctrl+C to stop)")
    try:
        # Capture packets on the network interface (you may need to specify the interface)
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Stopping packet capture...")
        visualize_alerts()

if __name__ == "__main__":
    main()
