from scapy.all import rdpcap
from PIL import Image
import os

# Chemin du fichier PCAP
pcap_file = 'dns.cap'
# Chemin du dossier où les images seront stockées
output_dir = '../Dataset/DNS'

# Créer le dossier de sortie s'il n'existe pas
os.makedirs(output_dir, exist_ok=True)

# Charger le fichier PCAP
packets = rdpcap(pcap_file)

# Fonction pour convertir une trame en binaire, normaliser et obtenir des valeurs en niveaux de gris
def process_packet(packet_data):
    # Convertir les données en binaire
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

# Processus de conversion de chaque paquet en image et sauvegarde
for idx, packet in enumerate(packets):
    # Extraire la charge utile du paquet si c'est un paquet ARP
    if packet.haslayer('DNS'):
        packet_data = bytes(packet['DNS'])
        
        # Traitement du paquet pour obtenir les valeurs en niveaux de gris
        grayscale_values = process_packet(packet_data)
        
        # Création d'une image 8x8 en niveaux de gris
        img = Image.new('L', (8, 8))
        img.putdata(grayscale_values)
        
        # Sauvegarder l'image dans le dossier de sortie
        img.save(f"{output_dir}/dns{idx}.png")

print(f"Images DNS sauvegardées dans le dossier {output_dir}")
