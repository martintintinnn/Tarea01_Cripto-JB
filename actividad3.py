from scapy.all import rdpcap, ICMP
from langdetect import detect, DetectorFactory
from langdetect.lang_detect_exception import LangDetectException
from termcolor import colored

# Fijar la semilla para la detección de lenguaje
DetectorFactory.seed = 0

# Cargar los paquetes del archivo pcapng
archivo_pcap = "captura.pcapng"
paquetes = rdpcap(archivo_pcap)

# Extraer los caracteres de los primeros 8 bytes del payload de cada paquete ICMP
def extraer_caracteres(paquetes, inicio, fin):
    texto = []
    for i, pkt in enumerate(paquetes):
        # Filtrar los paquetes en el rango especificado
        if inicio <= i + 1 <= fin:  # i + 1 porque el índice comienza en 0
            # Verificar que el paquete tiene una capa Raw y es ICMP tipo 8 (echo request)
            if pkt.haslayer('Raw') and pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                data = pkt['Raw'].load[:8]  # Extraer los primeros 8 bytes del payload
                caracter = data.decode(errors='ignore').strip('\x00')  # Decodificar a texto ignorando errores y quitar padding
                texto.append(caracter)
    return ''.join(texto)

# Aplicar un cifrado César a cada carácter de un texto
def aplicar_cifrado_cesar(texto, corrimiento):
    resultado = []
    for caracter in texto:
        if 'a' <= caracter <= 'z':  # Solo aplicar a letras minúsculas
            nuevo_caracter = chr((ord(caracter) - ord('a') + corrimiento) % 26 + ord('a'))
            resultado.append(nuevo_caracter)
        elif 'A' <= caracter <= 'Z':  # Aplicar a letras mayúsculas si existen
            nuevo_caracter = chr((ord(caracter) - ord('A') + corrimiento) % 26 + ord('A'))
            resultado.append(nuevo_caracter)
        else:  # Mantener los caracteres que no son letras
            resultado.append(caracter)
    return ''.join(resultado)

# Verificar si el texto es en español usando langdetect
def es_texto_en_espanol(texto):
    try:
        return detect(texto) == 'es'
    except LangDetectException:
        return False

# Encontrar el mejor desplazamiento y el texto descifrado
def encontrar_desplazamiento_correcto(texto):
    mejor_texto = ""
    mejor_corrimiento = 0
    for corrimiento in range(26):
        texto_descifrado = aplicar_cifrado_cesar(texto, -corrimiento)  # Usar desplazamiento negativo para descifrar
        if es_texto_en_espanol(texto_descifrado):
            mejor_texto = texto_descifrado
            mejor_corrimiento = corrimiento
            break  # Puedes optar por continuar buscando si deseas encontrar el mejor resultado posible
    return mejor_corrimiento, mejor_texto

# Definir el rango de los paquetes (desde el paquete 3389 hasta 12645)
inicio = 3389
fin = 12645

# Extraer y mostrar la palabra completa
palabra_completa = extraer_caracteres(paquetes, inicio, fin)
print("La palabra completa extraída de los paquetes es:")
print(palabra_completa)

# Encontrar el desplazamiento correcto
corrimiento_correcto, _ = encontrar_desplazamiento_correcto(palabra_completa)

# Imprimir todos los desplazamientos y resaltar en verde el texto del desplazamiento correcto
print("\nIntentando descifrar con diferentes desplazamientos:")
for corrimiento in range(26):
    texto_descifrado = aplicar_cifrado_cesar(palabra_completa, -corrimiento)
    if corrimiento == corrimiento_correcto:
        print(f"{corrimiento}: {colored(texto_descifrado, 'green')}")
    else:
        print(f"{corrimiento}: {texto_descifrado}")
