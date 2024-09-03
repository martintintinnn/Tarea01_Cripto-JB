#sudo python3 "actividad1.py" "criptografia y seguridad en redes" 9
#larycxpajorj h bnpdarmjm nw anmnb

import sys

def cifrado_cesar(texto, corrimiento):
    resultado = ""

    # Iterar sobre cada caracter del texto
    for char in texto:
        # Condicionales para cifrar segun caracter Mayus. o Minusc.
        if char.isupper():
            # Encontramos el indice del caracter correspondiente
            indice = ord(char) - ord('A')
            # Aplicamos corrimiento en formato, manteniendo rango 0 a 25(El mod usa el residuo)
            # Notar que utilizamos el alfabeto ingles
            nuevo_indice = (indice + corrimiento) % 26
            # Transformamos al formato final del caracter
            nuevo_caracter = chr(nuevo_indice + ord('A'))
            # Agregamos el nuevo caracter a la nueva cadena
            resultado += nuevo_caracter
        elif char.islower():
            indice = ord(char) - ord('a')
            nuevo_indice = (indice + corrimiento) % 26
            nuevo_caracter = chr(nuevo_indice + ord('a'))
            resultado += nuevo_caracter
        else:
            resultado += char

    return resultado

if __name__ == "__main__":
    # Si los argumentos que se pasan a la linea de comandos son distinto a 3 se corta la ejecucion
    if len(sys.argv) != 3:
        print("Uso: sudo python3 cesar.py \"texto a cifrar\" corrimiento")
        sys.exit(1)

    # Inputs
    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])

    # Aplicacion y luego impresion de la funcion
    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print(texto_cifrado)
