from scapy.all import rdpcap
from PIL import Image
import os

pcap_file = 'arp-storm.pcap'
output_dir = '../Dataset/ARP'

os.makedirs(output_dir, exist_ok=True)

packets = rdpcap(pcap_file)

def process_packet(packet_data):
    binary_data = ''.join(format(byte, '08b') for byte in packet_data)
    
    # Ajuster la longueur à 320 bits
    target_length = 320
    if len(binary_data) > target_length:
        binary_data = binary_data[:target_length]  # Tronquer à 320 bits
    else:
        binary_data = binary_data.ljust(target_length, '0')  # Compléter avec des zéros
    
    # Convertir les bits en valeurs de niveaux de gris (0-255)
    grayscale_values = [int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8)]
    
    return grayscale_values

for idx, packet in enumerate(packets):
    
    if packet.haslayer('ARP'):
        packet_data = bytes(packet['ARP'])
        
        grayscale_values = process_packet(packet_data)
        
        img = Image.new('L', (8, 8))
        img.putdata(grayscale_values)
        
        img.save(f"{output_dir}/arp_{idx}.png")

print(f"Images ARP sauvegardées dans le dossier {output_dir}")
