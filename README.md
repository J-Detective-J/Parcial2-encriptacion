# Parcial2-encriptacion
# Cifrador
- Integrantes: Juan Pablo Beltrán, Santiago Alejandro Céspedes , Jhonatan David Valdés


Programa en Python que genera números pseudoaleatorios de 40 cifras con cuatro técnicas distintas, busca primos entre ellos y los usa para cifrar y descifrar mensajes con tres algoritmos: **RSA**, **ElGamal** y **XOR por flujo**.


---

## Requisitos

- Python **3.9 o superior** (usa `pow(e, -1, phi)`, `int.to_bytes`, `math.gcd`, etc.).
- Solo biblioteca estándar: `hashlib`, `math`, `os`, `random`, `sys`, `unicodedata`.

---

## Cómo ejecutarlo

```bash
python cifrador.py
```

Por defecto lee el archivo `instrucciones.txt` en la misma carpeta. También puedes indicar otro archivo:

```bash
python cifrador.py mi_archivo.txt
```

Si el archivo no existe, el programa te muestra una plantilla con el formato esperado.


## Cómo funciona

### 1. Generación de números pseudoaleatorios

La clase `GeneradorNumerico` produce enteros de N cifras (por defecto 40). Se le pasa una técnica y una semilla:

| Técnica     | Descripción                                                 | 
|-------------|-------------------------------------------------------------|
| `mersenne`  | Mersenne Twister (`random.Random` de Python)                | 
| `sha256`    | PRNG basado en hash SHA-256 con contador interno            |
| `lcg`       | Generador congruencial lineal con periodo completo          | 
| `xorshift`  | Xorshift64 de Marsaglia                                     |

Todas las técnicas son **reproducibles**: la misma semilla + técnica produce la misma secuencia.

### 2. Búsqueda de primos

Con la máquina anterior se generan **10 000 números de 40 cifras**. Cada uno pasa por un test de **Miller-Rabin** con 12 bases (`2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37`), que es determinista hasta ~3·10^24 y probabilístico (con probabilidad de error ínfima) por encima. Se esperan ~100 primos, suficientes para RSA y ElGamal.

### 3. Algoritmos de cifrado

#### RSA (`MotorRSA` / `CifradorRSA`)
- Se eligen dos primos distintos `p` y `q` de la lista.
- `n = p·q`, `φ(n) = (p-1)(q-1)`, `e = 65537`.
- Clave privada: `d = e^(-1) mod φ(n)`.
- Cifrado por bloques: `c = m^e mod n`. Relleno: `0x01 || sal(4 bytes) || mensaje`.
- Descifrado: `m = c^d mod n`.

#### ElGamal (`CifradorElGamal`)
- Primo `p` grande, `g = 2`, clave privada `x`, clave pública `y = g^x mod p`.
- Cifrado: `c1 = g^k mod p`, `c2 = m·y^k mod p` con `k` aleatorio.
- Descifrado: `m = c2 · (c1^x)^(-1) mod p`.

#### XOR por flujo (`CifradorXOR`)
- Cifrado simétrico: la semilla **es** la clave.
- Se genera un keystream concatenando bytes derivados de los números del PRNG (un byte por número).
- `cifrado = mensaje XOR keystream`. Se añade un nonce de 8 bytes y un checksum SHA-256 de 4 bytes para detectar claves incorrectas.
- Descifrar es repetir el mismo XOR.

### 4. Etiquetas de algoritmo

Cada texto cifrado empieza con una etiqueta que identifica el algoritmo:

- `RSA|...`
- `ELG|...`
- `XOR|...`

Esto permite que el programa **detecte automáticamente** si el mensaje está cifrado y con qué algoritmo, y también avisa si intentas descifrar con el algoritmo equivocado.

---

## Salida del programa

Al ejecutarlo, muestra por consola:

```
=== RESULTADO ===
Acción     : cifrar
Semilla    : 123456  (valor numérico: 123456)
Técnica    : mersenne
Algoritmo  : rsa
Primos encontrados en los 10,000 números: 108

--- Mensaje original ---
Hola, como andan capos?

--- Mensaje cifrado ---
RSA|1a2b3c...:4d5e6f...
```

Para descifrar, copia el mensaje cifrado (con su etiqueta) en el campo `mensaje` de `instrucciones.txt`, pon `accion: descifrar` y usa la misma semilla, algoritmo y técnica.

---

## Estructura del código

| Componente                  | Función                                                                 |
|-----------------------------|-------------------------------------------------------------------------|
| `GeneradorNumerico`         | Máquina PRNG con cuatro técnicas                                        |
| `es_candidato_primo`        | Test de primalidad Miller-Rabin                                         |
| `MotorRSA`                  | Núcleo matemático de RSA (claves, cifrado/descifrado de enteros y texto)|
| `BaseCifrado`               | Interfaz común a todos los cifradores (`cifrar` / `descifrar`)          |
| `CifradorRSA`               | Cifrador RSA usando primos del PRNG                                     |
| `CifradorElGamal`           | Cifrador ElGamal                                                        |
| `CifradorXOR`               | Cifrador simétrico por flujo XOR                                        |
| `ContextoCifrado`           | Orquesta la sesión: semilla, técnica, algoritmo, primos, cifrador       |
| `resolver_semilla`          | Convierte número/frase/vacío en una semilla numérica                    |
| `cargar_configuracion`      | Lee `instrucciones.txt` y devuelve un diccionario                       |
| `validar_configuracion`     | Valida los campos y detecta la acción si no se especifica               |
| `procesar_mensaje`          | Prepara todo y cifra/descifra                                           |
| `imprimir_resultado`        | Muestra el resultado por consola                                        |
| `main`                      | Punto de entrada                                                        |

---

## Constantes configurables

Al inicio de `cifrador.py`:

```python
CANTIDAD = 10_000      # cuántos números de 40 cifras se generan
CIFRAS = 40            # cifras por número
EXPORTAR_PRIMOS = False
ARCHIVO_PRIMOS = "primos_encontrados.txt"
```

Si pones `EXPORTAR_PRIMOS = True`, al cifrar con RSA o ElGamal se guardará un archivo con todos los primos encontrados.

---

