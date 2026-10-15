# Parcial2-encriptacion

- Integrantes: Juan Pablo Beltrán, Santiago Alejandro Céspedes, Jhonatan David Valdés

# Cifrador (Algoritmo J)

Programa en Python que genera números pseudoaleatorios de 40 cifras con cuatro técnicas distintas, busca primos entre ellos y los usa para cifrar y descifrar mensajes con el **Algoritmo J** (cifrado afín con primos).

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

| Campo      | Obligatorio | Valores posibles                                                                 |
|------------|-------------|----------------------------------------------------------------------------------|
| `semilla`  | Sí          | Un número o una frase                                                            |
| `tecnica`  | No          | `mersenne`, `sha256`, `lcg`, `xorshift` (o `1`, `2`, `3`, `4`). Por defecto: `mersenne` |
| `accion`   | No          | `cifrar` o `descifrar`. Si se omite, se **detecta automáticamente**: si el mensaje empieza con `J|`, se descifra; si no, se cifra |
| `mensaje`  | Sí          | El texto a cifrar o el texto cifrado a descifrar                                 |

> ❌ El campo `algoritmo` **ya no existe**. Ahora siempre se usa el Algoritmo J. Si aparece en el archivo, el programa muestra un error pidiendo eliminarlo.

### Ejemplo para cifrar

```
semilla: 123456
tecnica: mersenne
accion: cifrar
mensaje: Hola, como andan capos?
```

### Ejemplo para descifrar

```
semilla: 123456
tecnica: mersenne
accion: descifrar
mensaje: J|2501fc4ed2be11d2f08bc2af3baf367d3:4041bc2686de03452fe069caf68fe882a:...
```

> 🔑 **Regla de oro para descifrar:** usa **exactamente** la misma `semilla` y `tecnica` con las que cifraste. Si cambias cualquiera de las dos, las claves serán distintas y no podrás recuperar el mensaje.

---

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

Con la máquina anterior se generan **10 000 números de 40 cifras**. Cada uno pasa por un test de **Miller-Rabin** con 12 bases (`2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37`), que es determinista hasta ~3·10^24 y probabilístico (con probabilidad de error ínfima) por encima. Se esperan ~100 primos, suficientes para el Algoritmo J.

### 3. Algoritmo J (cifrado afín con primos)

Es el único algoritmo de cifrado del programa. Usa **tres primos distintos** `P`, `A` y `B` elegidos de la lista de primos encontrados.

**Claves:**
- `P` = módulo (primo).
- `A` = multiplicador (primo, reducido módulo `P`).
- `B` = desplazamiento (primo, reducido módulo `P`).
- `A_inv = A^(-1) mod P` → se calcula con `pow(A, -1, P)`. Como `P` es primo, el inverso siempre existe.

**Cifrado por bloque:**
1. Se antepone al mensaje una **suma de comprobación de 8 caracteres** (primeros 8 dígitos hexadecimales de SHA-256), para detectar claves incorrectas o mensajes alterados al descifrar.
2. El texto se parte en trozos de `bytes_mensaje` bytes.
3. Cada trozo se convierte a entero `m` añadiendo `0x01` al inicio (preserva ceros a la izquierda).
4. Se aplica la transformación afín: `c = (A · m + B) mod P`.
5. Cada bloque cifrado se guarda en hexadecimal, separados por `:`.

**Descifrado:**
1. Se calcula `m = (c − B) · A_inv mod P`.
2. Se verifica que el primer byte sea `0x01`.
3. Se concatenan los trozos, se separa la suma de comprobación y se compara con la del texto recuperado. Si no coincide → clave incorrecta o mensaje alterado.

**Ejemplo del formato de salida:**

```
J|2501fc4ed2be11d2f08bc2af3baf367d3:4041bc2686de03452fe069caf68fe882a:54fb5a6f...
```

**Ventajas didácticas:** muestra cómo funciona un cifrado afín modular y por qué es importante que el multiplicador sea invertible módulo `P`.

**Debilidades (por eso es didáctico):**
- Mensajes idénticos producen bloques cifrados idénticos.
- Con un par (texto plano, cifrado) conocido se pueden deducir `A` y `B` resolviendo un sistema de dos ecuaciones.
- No tiene difusión ni confusión reales (a diferencia de AES o RSA).

### 4. Etiqueta de algoritmo

Cada texto cifrado empieza con la etiqueta `J|`. Esto permite que el programa **detecte automáticamente** si el mensaje está cifrado y avise si intentas descifrar con una configuración distinta.

---

## Salida del programa

Al ejecutarlo, muestra por consola:

```
=== RESULTADO ===
Acción     : cifrar
Semilla    : 123456  (valor numérico: 123456)
Técnica    : mersenne
Algoritmo  : Algoritmo J
Primos encontrados en los 10,000 números: 108

--- Mensaje original ---
Hola, como andan capos?

--- Mensaje cifrado ---
J|2501fc4ed2be11d2f08bc2af3baf367d3:4041bc2686de03452fe069caf68fe882a:...
```

Para descifrar, copia el mensaje cifrado (con su etiqueta `J|`) en el campo `mensaje` de `instrucciones.txt`, pon `accion: descifrar` y usa la misma semilla y técnica.

---

## Estructura del código

| Componente              | Función                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| `GeneradorNumerico`     | Máquina PRNG con cuatro técnicas                                        |
| `es_candidato_primo`    | Test de primalidad Miller-Rabin                                         |
| `AlgoritmoJ`            | Cifrado afín con tres primos (cifra y descifra texto)                   |
| `dividir_bytes`         | Parte bytes en trozos de tamaño fijo                                    |
| `resolver_semilla`      | Convierte número/frase/vacío en una semilla numérica                    |
| `ContextoCifrado`       | Orquesta la sesión: semilla, técnica, primos, cifrador                  |
| `cargar_configuracion`  | Lee `instrucciones.txt` y devuelve un diccionario                       |
| `validar_configuracion` | Valida los campos y detecta la acción si no se especifica               |
| `procesar_mensaje`      | Prepara todo y cifra/descifra                                           |
| `imprimir_resultado`    | Muestra el resultado por consola                                        |
| `main`                  | Punto de entrada                                                        |

---

## Constantes configurables

Al inicio de `cifrador.py`:

```python
CANTIDAD = 10_000      # cuántos números de 40 cifras se generan
CIFRAS = 40            # cifras por número
EXPORTAR_PRIMOS = False
ARCHIVO_PRIMOS = "primos_encontrados.txt"
```

Si pones `EXPORTAR_PRIMOS = True`, se guardará un archivo con todos los primos encontrados.

---

## Limitaciones

- El **Algoritmo J** es un cifrado afín básico: no tiene difusión ni confusión reales, y con un par (texto plano, cifrado) se pueden deducir las claves.
- Los primos de 40 cifras (~133 bits) son **trivialmente factorizables** hoy en día.
- Mersenne Twister, LCG y Xorshift **no son seguros** para uso criptográfico. Solo SHA-256 lo sería.
- El cifrado no autentica el mensaje más allá de una suma de comprobación de 8 caracteres hexadecimales (32 bits), insuficiente frente a un atacante con recursos.

---

## Licencia

Uso libre con fines educativos. Los autores no se responsabilizan del uso que se le dé.
