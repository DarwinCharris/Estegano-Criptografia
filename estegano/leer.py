from PIL import Image

caracter_terminacion = "11111111"

def obtener_lsb(byte):
	return byte[-1]

def obtener_representacion_binaria(numero):
	return bin(numero)[2:].zfill(8)

def binario_a_decimal(binario):
	return int(binario, 2)

def caracter_desde_codigo_ascii(numero):
	return chr(numero)

def leer_mensaje_desde_imagen(ruta_imagen):
	imagen = Image.open(ruta_imagen)
	pixeles = imagen.load()

	ancho, alto = imagen.size

	byte = ""
	mensaje = ""

	for x in range(ancho):
		for y in range(alto):
			pixel = pixeles[x, y]
			for color in pixel:
				byte += obtener_lsb(obtener_representacion_binaria(color))
				if len(byte) == 8:
					if byte == caracter_terminacion:
						return mensaje
					mensaje += caracter_desde_codigo_ascii(binario_a_decimal(byte))
					byte = ""

	return mensaje
