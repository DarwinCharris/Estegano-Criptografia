from PIL import Image
import math

caracter_terminacion = [1] * 8

def obtener_representacion_ascii(caracter):
	return ord(caracter)

def obtener_representacion_binaria(numero):
	return bin(numero)[2:].zfill(8)

def cambiar_ultimo_bit(byte, nuevo_bit):
	return byte[:-1] + str(nuevo_bit)

def binario_a_decimal(binario):
	return int(binario, 2)

def modificar_color(color_original, bit):
	color_binario = obtener_representacion_binaria(color_original)
	color_modificado = cambiar_ultimo_bit(color_binario, bit)
	return binario_a_decimal(color_modificado)

def obtener_lista_de_bits(texto):
	lista = []
	for letra in texto:
		binario = obtener_representacion_binaria(obtener_representacion_ascii(letra))
		lista.extend(list(binario))
	lista.extend([str(b) for b in caracter_terminacion])
	return lista

def ocultar_texto(mensaje, ruta_imagen_original, ruta_imagen_salida):
	imagen = Image.open(ruta_imagen_original)
	pixeles = imagen.load()

	ancho, alto = imagen.size
	lista_bits = obtener_lista_de_bits(mensaje)
	contador = 0

	for x in range(ancho):
		for y in range(alto):
			if contador >= len(lista_bits):
				break

			r, g, b = pixeles[x, y]

			if contador < len(lista_bits):
				r = modificar_color(r, lista_bits[contador])
				contador += 1
			if contador < len(lista_bits):
				g = modificar_color(g, lista_bits[contador])
				contador += 1
			if contador < len(lista_bits):
				b = modificar_color(b, lista_bits[contador])
				contador += 1

			pixeles[x, y] = (r, g, b)

		if contador >= len(lista_bits):
			break

	imagen.save(ruta_imagen_salida)
