#!/usr/bin/env python3
from scapy.all import *
import threading
import time

# Configuration
MY_IP = "192.168.192.243"  # Replace with your local IP
PEER_IP = "192.168.206.223"  # Replace with the peer's IP
INTERFACE = "ens192"  # Replace with your network interface (e.g., "wlan0", "en0")

# Function to send chat messages
def send_messages():
    while True:
        message = input("You: ")  # Get user input
        if message.lower() == "exit":
            print("Chat ended.")
            break
        # Create and send a UDP packet with the message as payload
        packet = IP(dst=PEER_IP) / ICMP(type=8) / Raw(load=message) # type 8 echo request
        send(packet, iface=INTERFACE, verbose=False)
        time.sleep(0.1)  # Small delay to prevent overwhelming the network

# Function to receive chat messages
def receive_messages():
    def handle_packet(pkt):
        if IP in pkt and ICMP in pkt and pkt[IP].src == PEER_IP:
            if Raw in pkt:
                print(f"\nPeer: {pkt[Raw].load.decode(errors='ignore')}\nYou: ", end="")

    sniff(iface=INTERFACE, filter="icmp", prn=handle_packet)
# Main function to start the chat
def main():
    print("Starting bidirectional chat. Type 'exit' to quit.")
    print(f"Chatting with {PEER_IP} via {INTERFACE}")

    # Start the receiver in a separate thread
    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    # Start the sender in the main thread
    send_messages()

if __name__ == "__main__":
    main()
