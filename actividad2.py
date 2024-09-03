from scapy.all import *
import time
import random

def extraer_paquete_base(destino):
    paquetes = sniff(filter=f"icmp and host {destino} and icmp[icmptype] = 8", count=1)
    return paquetes[0]

def crear_paquete_personalizado(paquete_base, caracter, seq_num, id_ip):
    # Los primeros 8 bytes se usarán para enviar el carácter
    # Se usa padding si es que necesitamos para tener los 8 bytes
    nuevo_payload = caracter.encode().ljust(8, b'\x00') + bytes(range(0x10, 0x38))

    # Crear el nuevo paquete con el payload modificado
    nuevo_paquete = IP(dst=paquete_base[IP].dst, src=paquete_base[IP].src, id=id_ip) / \
                    ICMP(type=8, id=paquete_base[ICMP].id, seq=seq_num) / \
                    Raw(load=nuevo_payload)
    
    return nuevo_paquete

def enviar_ping_caracteres(destino, texto):
    paquete_base = extraer_paquete_base(destino)
    
    id_base = paquete_base[IP].id
    id_ip = id_base + random.randint(10, 50)
    
    for i, caracter in enumerate(texto):
        # Crear un paquete ICMP personalizado con el carácter actual
        paquete_personalizado = crear_paquete_personalizado(paquete_base, caracter, i + 1, id_ip)
        send(paquete_personalizado)
        id_ip += random.randint(100, 200)
        time.sleep(1)

if __name__ == "__main__":
    destino = "64.233.186.93"  # IP donde enviaremos
    texto = "larycxpajorj h bnpdarmjm nw anmnb"  # Texto a enviar

    print("Enviando caracteres como paquetes ICMP...\n")
    enviar_ping_caracteres(destino, texto)
