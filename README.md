# StegoBMP

StegoBMP es un programa para esteganografía de imágenes BMP utilizando varios algoritmos, incluidos LSB1, LSB4 y LSBI. Este README proporciona una guía completa sobre cómo usar el programa, ejemplos y documentación detallada.

## Índice

- [Instalación](#instalación)
- [Uso](#uso)
- [Ejemplos](#ejemplos)
- [Licencia](#licencia)

## Instalación

Para instalar y compilar StegoBMP, primero clona el repositorio:

```bash
git clone https://github.com/TomyMarengo/Stego-BMP.git
```

Luego, compila el programa con el siguiente comando maven:

```bash
mvn clean install
```

## Uso

Para usar StegoBMP, ejecuta el siguiente comando:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography #[opciones]
```

Las opciones disponibles son:

- `-embed`: Oculta un archivo en una imagen BMP.
- `-extract`: Extrae un archivo de una imagen BMP.
- `-in`: Ruta del archivo a ocultar.
- `-p`: Ruta de la imagen BMP de entrada.
- `-out`: Ruta de la imagen BMP de salida.
- `-steg`: Algoritmo de esteganografía a utilizar (LSB1, LSB4, LSBI).
- `-a`: Algoritmo de cifrado a utilizar (AES128, AES192, AES256, DES).
- `-m`: Modo de cifrado a utilizar (CBC, ECB, OFB, CFB).
- `-pass`: Contraseña para cifrar/descifrar el archivo.

Por defecto, el programa utiliza el algoritmo de cifrado AES128 y el modo de cifrado CBC. 
Siempre se debe especificar una contraseña para cifrar/descifrar el archivo.

## Ejemplos

Para ocultar un archivo en una imagen BMP utilizando el algoritmo LSB1 sin cifrado:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -embed -in ./src/main/resources/messages/hello.txt -p ./src/main/resources/covers/tricolor.bmp -out imagen_con_texto.bmp -steg LSB1
```

Para extraer ese archivo de la imagen BMP:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -extract -p imagen_con_texto.bmp -out mensaje_extraido -steg LSB1
```

Para ocultarlo utilizando el algoritmo LSB4 con cifrado AES256 y modo OFB:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -embed -in ./src/main/resources/messages/hello.txt -p ./src/main/resources/covers/tricolor.bmp -out imagen_con_texto_cifrado.bmp -steg LSB4 -a aes256 -m ofb -pass secreto
```

Para extraerlo de la imagen BMP:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -extract -p imagen_con_texto_cifrado.bmp -out mensaje_descifrado_extraido -steg LSB4 -a aes256 -m ofb -pass secreto
```

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más información.
