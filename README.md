# Parcial2-encriptacion
# Cifrador Educativo

Programa en Python que genera números pseudoaleatorios de 40 cifras con cuatro técnicas distintas, busca primos entre ellos y los usa para cifrar y descifrar mensajes con tres algoritmos: **RSA**, **ElGamal** y **XOR por flujo**.

> ⚠️ **Advertencia:** este proyecto es **didáctico**. Los primos que genera (~40 cifras ≈ 133 bits) son demasiado pequeños para uso real, y algunas técnicas de PRNG no son criptográficamente seguras. **No lo uses para proteger información sensible.**

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

---

## Formato de `instrucciones.txt`

El archivo se compone de líneas `campo: valor`. Las líneas que empiezan con `#` son comentarios. El campo `mensaje` **debe ir al final** (consume todo lo que venga después, incluso varias líneas).

| Campo       | Obligatorio | Valores posibles                                          |
|-------------|-------------|-----------------------------------------------------------|
| `semilla`   | Sí          | Un número o una frase                                     |
| `algoritmo` | Sí          | `rsa`, `elgamal`, `xor` (o `1`, `2`, `3`)                 |
| `tecnica`   | No          | `mersenne`, `sha256`, `lcg`, `xorshift` (o `1`, `2`, `3`, `4`). Por defecto: `mersenne` |
| `accion`    | No          | `cifrar` o `descifrar`. Si se omite, se **detecta automáticamente**: si el mensaje empieza con `RSA|`, `ELG|` o `XOR|`, se descifra; si no, se cifra |
| `mensaje`   | Sí          | El texto a cifrar o el texto cifrado a descifrar          |

### Ejemplo para cifrar

```
semilla: 123456
algoritmo: rsa
tecnica: mersenne
accion: cifrar
mensaje: Hola, como andan capos?
```

### Ejemplo para descifrar

```
semilla: 123456
algoritmo: rsa
tecnica: mersenne
accion: descifrar
mensaje: RSA|1a2b3c...:4d5e6f...
```

> 🔑 **Regla de oro para descifrar:** usa **exactamente** la misma `semilla`, `algoritmo` y `tecnica` con los que cifraste. Si cambias cualquiera de los tres, las claves serán distintas y no podrás recuperar el mensaje.

---

## Cómo funciona

### 1. Generación de números pseudoaleatorios

La clase `GeneradorNumerico` produce enteros de N cifras (por defecto 40). Se le pasa una técnica y una semilla:

| Técnica     | Descripción                                                 | ¿Segura criptográficamente? |
|-------------|-------------------------------------------------------------|-----------------------------|
| `mersenne`  | Mersenne Twister (`random.Random` de Python)                | No                          |
| `sha256`    | PRNG basado en hash SHA-256 con contador interno            | Sí                          |
| `lcg`       | Generador congruencial lineal con periodo completo          | No                          |
| `xorshift`  | Xorshift64 de Marsaglia                                     | No                          |

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

## Limitaciones

- Los primos de 40 cifras (~133 bits) son **trivialmente factorizables** hoy en día. RSA real usa 2048–4096 bits.
- Mersenne Twister, LCG y Xorshift **no son seguros** para uso criptográfico. Solo SHA-256 lo sería.
- ElGamal con `g = 2` sin verificar que sea generador es una simplificación educativa.
- El relleno `0x01 || sal` no es OAEP; en un contexto interactivo podría ser vulnerable a padding oracle.
- El cifrado XOR por flujo depende de la calidad del PRNG y de que el nonce nunca se repita.

---

## Licencia

Uso libre con fines educativos. El autor no se responsabiliza del uso que se le dé.
