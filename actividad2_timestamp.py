from scapy.all import *
import time
import random

def extraer_paquete_base(destino):
    # Capturar un paquete ICMP con tipo 8 para usarlo como base
    # Es decir, capturamos al de filtrado icmp.type == 8
    paquetes = sniff(filter=f"icmp and host {destino} and icmp[icmptype] = 8", count=1)
    return paquetes[0]


def crear_paquete_personalizado(paquete_base, caracter, seq_num, payload_inicial, id_ip):
    # Crear un nuevo paquete IP con el 'id' proporcionado y mantener el 'id' ICMP igual al paquete base
    nuevo_paquete = IP(dst=paquete_base[IP].dst, src=paquete_base[IP].src, id=id_ip) / \
                    ICMP(type=8, id=paquete_base[ICMP].id, seq=seq_num)

    # Crear un nuevo payload con los primeros 8 bytes constantes
    nuevo_payload = payload_inicial

    # Agregar el nuevo caracter después de los primeros 8 bytes
    nuevo_payload += caracter.encode()
    
    # Completar el payload con los bytes desde 0x10 a 0x37 del paquete base si existen
    if len(paquete_base[Raw].load) > 0x37:
        nuevo_payload += paquete_base[Raw].load[0x10:0x37]
    
    # Ajustar el tamaño del nuevo payload si es necesario
    nuevo_paquete /= Raw(load=nuevo_payload)
    
    return nuevo_paquete


def enviar_ping_caracteres(destino, texto):
    # Extraer el paquete base de la red
    paquete_base = extraer_paquete_base(destino)
    
    # Revisar si el paquete base tiene carga 'Raw' y extraer los primeros 8 bytes si es posible
    if Raw in paquete_base:
        payload_inicial = paquete_base[Raw].load[:8]
        print(payload_inicial)
        print(payload_inicial)
    else:
        payload_inicial = b''  # o establece algún valor por defecto si no existe Raw
    
    # Inicializar el valor del ID IP para el primer paquete
    id_base = paquete_base[IP].id
    id_ip = id_base + random.randint(10, 50)
    
    for i, caracter in enumerate(texto):
        # Crear un paquete ICMP personalizado
        paquete_personalizado = crear_paquete_personalizado(paquete_base, caracter, i + 1, payload_inicial, id_ip)
        
        # Enviar el paquete
        send(paquete_personalizado)
        
        # Actualizar el valor del ID IP sumando un número aleatorio para el siguiente paquete
        id_ip += random.randint(10, 600)  # Puedes ajustar el rango de incremento aquí
        
        time.sleep(1)  # Esperar un segundo entre cada ping para simular tráfico normal


if __name__ == "__main__":
    destino = "64.233.186.93"  # IP donde enviaremos
    texto = "larycxpajorj h bnpdarmjm nw amnb"  # Texto a enviar

    # Enviar los caracteres como paquetes ICMP
    print("Enviando caracteres como paquetes ICMP...\n")
    enviar_ping_caracteres(destino, texto)
