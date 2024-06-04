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

Para usar StegoBMP, debes pararte en la carpeta raíz del proyecto y ejecutar un comando similar al siguiente:

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
- `-m`: Modo de cifrado a utilizar (CBC, ECB, OFB, OFB8, CFB, CFB8).
- `-pass`: Contraseña para cifrar/descifrar el archivo.
---

**Algunas consideraciones importantes:**
* Por defecto, el programa utiliza el algoritmo de cifrado AES128 y el modo de cifrado CBC.
* Por defecto, OFB y CFB trabajan con bloques de 128 bits.
* Por defecto, se usa PKCS5Padding para el cifrado.
* Se utiliza un salt fijo _(0x0000000000000000)_ para el cifrado.
* Siempre se debe especificar una contraseña para cifrar/descifrar el archivo.

### Antes de comenzar
1. En estos casos se usan las carpetas `messages` con el archivo `hello.txt` (archivo a ocultar) y `covers` con la imagen `tricolor.bmp` (imagen portadora) en la carpeta `src/main/resources`.

2. Además, se necesitan crear las carpetas `outputs` y `extracted` en la carpeta `src/main/resources` para almacenar los archivos de salida.

### Ejemplos

Para ocultar un archivo en una imagen BMP utilizando el algoritmo LSB1 sin cifrado:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -embed -in ./src/main/resources/messages/hello.txt -p ./src/main/resources/covers/tricolor.bmp -out ./src/main/resources/embedded/imagen_con_texto.bmp -steg LSB1
```

Para extraer ese archivo de la imagen BMP:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -extract -p ./src/main/resources/embedded/imagen_con_texto.bmp -out ./src/main/resources/extracted/mensaje_extraido -steg LSB1
```

Para ocultarlo utilizando el algoritmo LSB4 con cifrado AES256 y modo OFB:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -embed -in ./src/main/resources/messages/hello.txt -p ./src/main/resources/covers/tricolor.bmp -out ./src/main/resources/embedded/imagen_con_texto_cifrado.bmp -steg LSB4 -a aes256 -m ofb -pass secreto
```

Para extraerlo de la imagen BMP:

```bash
java -cp target/StegoBMP-1.0-SNAPSHOT.jar ar.edu.itba.cripto.Steganography -extract -p ./src/main/resources/embedded/imagen_con_texto_cifrado.bmp -out ./src/main/resources/extracted/mensaje_descifrado_extraido -steg LSB4 -a aes256 -m ofb -pass secreto
```

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más información.
