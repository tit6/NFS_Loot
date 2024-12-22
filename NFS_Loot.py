import pyshark
import os
import argparse

def extraction(i, packets):
    file_data = b""
    for t in range (i, len(packets)):
        next_packet = packets[t]
        if hasattr(next_packet.nfs, "main_opcode") and next_packet.nfs.main_opcode == 25: 
            if hasattr(next_packet.nfs, 'eof'): 
                eof = next_packet.nfs.eof
                if hasattr(next_packet.nfs, 'data'):
                    try:
                        file_data += next_packet.nfs.data
                    except ValueError:
                        file_data += str(next_packet.nfs.data)
                if eof == 1:
                    file_name = f"output/test{i}"
                    with open(file_name, 'wb') as f:
                        f.write(file_data)
                    file_data = b""
                    break

def main(fichier):
    # Crée un dossier "output" pour sauvegarder les fichiers
    if not os.path.exists("output"):
        os.makedirs("output")
    # Capture en direct sur un fichier de capture (pcapng)
    capture = pyshark.FileCapture(fichier, display_filter='nfs', use_ek=True)

    # Parcourir les paquets
    packets = list(capture)
    eof = None
    for i, packet in enumerate(packets):
        if hasattr(packet, "nfs"):
            if hasattr(packet,"rpc"):
                # Vérifier si le paquet est une requête OPEN (main_opcode == 18)
                if hasattr(packet.nfs, "main_opcode") and packet.nfs.main_opcode == 18:
                        if hasattr(packet.rpc, "msgtyp") and int(packet.rpc.msgtyp) == 0:
                            print(f"Paquet {i} : Opération OPEN détectée")
                            #la on n'a trouvé une demande OPEN donc on va pourvoir récupére l'ensemble des valeur
                            extraction(i, packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="il faut mettre un fichier",required=True)
    args = parser.parse_args()
    main(args.input)
    print("fini")