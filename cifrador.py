import hashlib
import math
import os
import random
import sys
import unicodedata

CANTIDAD = 10_000
CIFRAS = 40
EXPORTAR_PRIMOS = False
ARCHIVO_PRIMOS = "primos_encontrados.txt"

MASCARA_64 = (1 << 64) - 1


class GeneradorNumerico:
    """Genera números pseudoaleatorios de N cifras según la técnica elegida."""

    TECNICAS = ("mersenne", "sha256", "lcg", "xorshift")

    def __init__(self, tecnica="mersenne", semilla=12345, cifras=40, **params):
        if tecnica not in self.TECNICAS:
            raise ValueError("Técnica no válida. Opciones: " + ", ".join(self.TECNICAS))
        if cifras < 2:
            raise ValueError("Se necesitan al menos 2 cifras")

        self.tecnica = tecnica
        self.semilla = semilla
        self.cifras = cifras

        self.minimo = 10 ** (cifras - 1)
        self.maximo = 10 ** cifras
        self.rango = self.maximo - self.minimo

        self.bits = math.ceil(cifras * math.log2(10)) + 64

        self.contador = 0
        self._preparar(params)

    def _preparar(self, params):
        if self.tecnica == "mersenne":
            self._rng = random.Random(self.semilla)
        elif self.tecnica == "sha256":
            self._hash = params.get("algoritmo", "sha256")
            hashlib.new(self._hash)
            self._base = str(self.semilla).encode()
        elif self.tecnica == "lcg":
            self._m = params.get("m", 2 ** self.bits)
            a = params.get("a", (6364136223846793005 << 64) + 1442695040888963407)
            self._a = a - (a % 4) + 1
            self._c = params.get("c", 1442695040888963407) | 1
            self._x = self.semilla % self._m
        elif self.tecnica == "xorshift":
            h = hashlib.sha256(str(self.semilla).encode()).digest()
            self._estado = int.from_bytes(h[:8], "big") or 1

    def _crudo_mersenne(self):
        return self._rng.getrandbits(self.bits)

    def _crudo_sha256(self):
        necesarios = (self.bits + 7) // 8
        bloques = []
        longitud = 0
        bloque = 0
        while longitud < necesarios:
            entrada = self._base + self.contador.to_bytes(8, "big") + bloque.to_bytes(2, "big")
            fragmento = hashlib.new(self._hash, entrada).digest()
            bloques.append(fragmento)
            longitud += len(fragmento)
            bloque += 1
        return int.from_bytes(b"".join(bloques)[:necesarios], "big")

    def _crudo_lcg(self):
        self._x = (self._a * self._x + self._c) % self._m
        return self._x

    def _xorshift64(self):
        x = self._estado
        x ^= (x << 13) & MASCARA_64
        x ^= x >> 7
        x ^= (x << 17) & MASCARA_64
        self._estado = x
        return x

    def _crudo_xorshift(self):
        palabras = math.ceil(self.bits / 64)
        valor = 0
        for _ in range(palabras):
            valor = (valor << 64) | self._xorshift64()
        return valor

    def extraer_numero(self):
        """Devuelve el siguiente número pseudoaleatorio de 'cifras' cifras."""
        crudo = getattr(self, "_crudo_" + self.tecnica)()
        self.contador += 1
        return self.minimo + (crudo % self.rango)

    def secuencia(self, cantidad):
        """Devuelve una lista con 'cantidad' números."""
        return [self.extraer_numero() for _ in range(cantidad)]

    def __repr__(self):
        return f"GeneradorNumerico(tecnica={self.tecnica!r}, semilla={self.semilla}, cifras={self.cifras})"


PRIMOS_PEQUENOS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                   53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
BASES_MR = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def es_candidato_primo(n):
    """True si n es (con probabilidad altísima) primo. Test de Miller-Rabin."""
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n % p == 0:
            return n == p

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in BASES_MR:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


BYTES_SAL = 4


class MotorRSA:
    """Motor RSA: cifra/descifra enteros y texto con claves p, q, e."""

    def __init__(self, p, q, e=65537):
        if p == q:
            raise ValueError("p y q deben ser distintos")
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            raise ValueError("e no es coprimo con phi; elegir otros primos")

        self.p, self.q, self.e = p, q, e
        self.n = p * q
        self._d = pow(e, -1, phi)

        self.bytes_bloque = (self.n.bit_length() - 1) // 8
        self.bytes_mensaje = self.bytes_bloque - 1 - BYTES_SAL

    @property
    def clave_publica(self):
        return (self.e, self.n)

    @property
    def clave_privada(self):
        return (self._d, self.n)

    def codificar_entero(self, m):
        if not 0 <= m < self.n:
            raise ValueError("El número debe estar entre 0 y n-1")
        return pow(m, self.e, self.n)

    def descodificar_entero(self, c):
        return pow(c, self._d, self.n)

    def codificar_texto(self, mensaje):
        """Recibe un str y devuelve el texto cifrado como cadena hexadecimal."""
        datos = mensaje.encode("utf-8")
        trozos = [datos[i:i + self.bytes_mensaje]
                  for i in range(0, len(datos), self.bytes_mensaje)] or [b""]

        bloques = []
        for trozo in trozos:
            sal = random.SystemRandom().randbytes(BYTES_SAL)
            m = int.from_bytes(b"\x01" + sal + trozo, "big")
            bloques.append(format(self.codificar_entero(m), "x"))
        return ":".join(bloques)

    def descodificar_texto(self, cifrado):
        """Recibe la cadena hexadecimal y devuelve el mensaje original."""
        datos = b""
        for bloque in cifrado.split(":"):
            m = self.descodificar_entero(int(bloque, 16))
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            if not b or b[0] != 1:
                raise ValueError("Bloque inválido: clave incorrecta o mensaje alterado")
            datos += b[1 + BYTES_SAL:]
        return datos.decode("utf-8")


class BaseCifrado:
    """Clase base: todos los algoritmos se usan igual (cifrar / descifrar)."""
    etiqueta = ""

    def cifrar(self, texto):
        return self.etiqueta + "|" + self._cifrar(texto)

    def descifrar(self, cifrado):
        etiqueta, _, cuerpo = cifrado.strip().partition("|")
        if etiqueta != self.etiqueta:
            raise ValueError(f"Este mensaje fue cifrado con '{etiqueta}', "
                             f"pero tienes seleccionado '{self.etiqueta}'")
        return self._descifrar(cuerpo)

    def claves(self):
        return []


def dividir_bytes(datos, tamano):
    """Parte unos bytes en trozos de 'tamano' bytes (al menos un trozo)."""
    return [datos[i:i + tamano] for i in range(0, len(datos), tamano)] or [b""]


class CifradorRSA(BaseCifrado):
    """Usa la clase MotorRSA. Elige p y q entre los primos encontrados."""
    etiqueta = "RSA"

    def __init__(self, primos, rng):
        while True:
            p, q = rng.sample(primos, 2)
            try:
                self.sistema = MotorRSA(p, q)
                break
            except ValueError:
                continue

    def _cifrar(self, texto):
        return self.sistema.codificar_texto(texto)

    def _descifrar(self, cuerpo):
        return self.sistema.descodificar_texto(cuerpo)

    def claves(self):
        s = self.sistema
        return [("p (privado)", s.p), ("q (privado)", s.q),
                ("n = p*q (público)", s.n), ("e (público)", s.e),
                ("d (privado)", s.clave_privada[0])]


class CifradorElGamal(BaseCifrado):
    """ElGamal: clave pública (p, g, y), privada x. Cifra bloques con k aleatorio."""
    etiqueta = "ELG"

    def __init__(self, primos, rng):
        self.p = rng.choice(primos)
        self.g = 2
        self._x = rng.randrange(2, self.p - 2)
        self.y = pow(self.g, self._x, self.p)
        self.bytes_bloque = (self.p.bit_length() - 1) // 8
        self.bytes_mensaje = self.bytes_bloque - 1 - BYTES_SAL

    def _cifrar(self, texto):
        azar = random.SystemRandom()
        bloques = []
        for trozo in dividir_bytes(texto.encode("utf-8"), self.bytes_mensaje):
            m = int.from_bytes(b"\x01" + azar.randbytes(BYTES_SAL) + trozo, "big")
            k = azar.randrange(2, self.p - 2)
            c1 = pow(self.g, k, self.p)
            c2 = (m * pow(self.y, k, self.p)) % self.p
            bloques.append(format(c1, "x") + "," + format(c2, "x"))
        return ":".join(bloques)

    def _descifrar(self, cuerpo):
        datos = bytearray()
        for bloque in cuerpo.split(":"):
            c1, c2 = (int(v, 16) for v in bloque.split(","))
            s = pow(c1, self._x, self.p)
            m = (c2 * pow(s, -1, self.p)) % self.p
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            if not b or b[0] != 1:
                raise ValueError("Bloque inválido")
            datos.extend(b[1 + BYTES_SAL:])
        return datos.decode("utf-8")

    def claves(self):
        return [("p (público)", self.p), ("g (público)", self.g),
                ("y = g^x mod p (público)", self.y), ("x (privado)", self._x)]


class CifradorXOR(BaseCifrado):
    """Cifrado simétrico: la clave es la semilla. Genera keystream con la PRNG elegida."""
    etiqueta = "XOR"

    def __init__(self, tecnica, semilla):
        self.tecnica = tecnica
        self.semilla = semilla

    def _keystream(self, nonce, longitud):
        base = str(self.semilla).encode() + nonce
        semilla_maquina = int.from_bytes(hashlib.sha256(base).digest()[:8], "big")
        maquina = GeneradorNumerico(self.tecnica, semilla_maquina, CIFRAS)
        flujo = bytearray()
        while len(flujo) < longitud:
            flujo.extend(maquina.extraer_numero().to_bytes(17, "big")[1:])
        return bytes(flujo[:longitud])

    @staticmethod
    def _xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _cifrar(self, texto):
        datos = texto.encode("utf-8")
        datos = hashlib.sha256(datos).digest()[:4] + datos
        nonce = random.SystemRandom().randbytes(8)
        cifrado = self._xor(datos, self._keystream(nonce, len(datos)))
        return nonce.hex() + ":" + cifrado.hex()

    def _descifrar(self, cuerpo):
        nonce_hex, cifrado_hex = cuerpo.split(":")
        nonce, cifrado = bytes.fromhex(nonce_hex), bytes.fromhex(cifrado_hex)
        datos = self._xor(cifrado, self._keystream(nonce, len(cifrado)))
        control, mensaje = datos[:4], datos[4:]
        if hashlib.sha256(mensaje).digest()[:4] != control:
            raise ValueError("Comprobación fallida: clave incorrecta o mensaje alterado")
        return mensaje.decode("utf-8")

    def claves(self):
        return [("semilla (clave secreta)", self.semilla)]


def resolver_semilla(texto):
    """Número -> se usa tal cual. Texto -> se convierte con un hash. Vacío -> azar."""
    texto = texto.strip()
    if texto == "":
        return random.SystemRandom().randrange(10 ** 6, 10 ** 9)
    if texto.lstrip("-").isdigit():
        return int(texto)
    return int.from_bytes(hashlib.sha256(texto.encode()).digest()[:8], "big")


class ContextoCifrado:
    """Guarda la configuración de la sesión y prepara el cifrador adecuado."""

    def __init__(self):
        self.semilla = None
        self.tecnica = None
        self.algoritmo = None
        self.primos = []
        self.cifrador = None
        self.ultimo_cifrado = None

    def buscar_primos(self):
        """Genera los números con la máquina y se queda con los primos."""
        maquina = GeneradorNumerico(self.tecnica, self.semilla, CIFRAS)
        numeros = maquina.secuencia(CANTIDAD)
        self.primos = [n for n in numeros if es_candidato_primo(n)]

    def exportar_primos(self, ruta=ARCHIVO_PRIMOS):
        with open(ruta, "w", encoding="utf-8") as archivo:
            archivo.write(f"Primos encontrados: {len(self.primos)}\n")
            archivo.write(f"Candidatos revisados: {CANTIDAD}\n\n")
            for primo in self.primos:
                archivo.write(f"{primo}\n")

    def preparar_cifrador(self):
        """Las claves salen de la semilla: misma configuración => mismas claves."""
        rng = random.Random(f"{self.semilla}|{self.tecnica}|{self.algoritmo}")
        if self.algoritmo == "rsa":
            self.cifrador = CifradorRSA(self.primos, rng)
        elif self.algoritmo == "elgamal":
            self.cifrador = CifradorElGamal(self.primos, rng)
        else:
            self.cifrador = CifradorXOR(self.tecnica, self.semilla)
        self.ultimo_cifrado = None


ARCHIVO_ENTRADA = "instrucciones.txt"

ALGORITMOS = {
    "1": "rsa", "rsa": "rsa",
    "2": "elgamal", "elgamal": "elgamal",
    "3": "xor", "xor": "xor", "flujo xor": "xor", "flujo": "xor",
}
TECNICAS = {
    "1": "mersenne", "mersenne": "mersenne", "mersenne twister": "mersenne",
    "2": "sha256", "sha256": "sha256", "sha-256": "sha256", "hash": "sha256",
    "3": "lcg", "lcg": "lcg",
    "4": "xorshift", "xorshift": "xorshift",
}
ACCIONES = {
    "cifrar": "cifrar", "encriptar": "cifrar", "1": "cifrar",
    "descifrar": "descifrar", "desencriptar": "descifrar", "2": "descifrar",
}
ETIQUETAS = ("RSA|", "ELG|", "XOR|")

PLANTILLA = """# INSTRUCCIONES PARA EL CIFRADOR
# Una línea por campo. El campo "mensaje" va SIEMPRE al final.
# semilla   : un número o una frase (obligatorio)
# algoritmo : rsa | elgamal | xor          (o 1 | 2 | 3)
# tecnica   : mersenne | sha256 | lcg | xorshift   (o 1 | 2 | 3 | 4)
# accion    : cifrar | descifrar
# Para DESCIFRAR: usa la misma semilla, algoritmo y técnica con los que
# cifraste, y pega el mensaje cifrado (empieza con RSA| ELG| o XOR|).

semilla: mi semilla secreta
algoritmo: rsa
tecnica: mersenne
accion: cifrar
mensaje: Hola, este es mi mensaje secreto
"""


class ErrorConfiguracion(Exception):
    """Error en el contenido del archivo de instrucciones."""
    pass


def normalizar_texto(texto):
    """Minúsculas y sin acentos: 'Técnica' -> 'tecnica'."""
    sin_acentos = unicodedata.normalize("NFD", texto)
    sin_acentos = "".join(c for c in sin_acentos if unicodedata.category(c) != "Mn")
    return sin_acentos.strip().lower()


def cargar_configuracion(ruta):
    """Devuelve un diccionario con los campos encontrados en el archivo."""
    with open(ruta, encoding="utf-8-sig") as f:
        lineas = f.read().splitlines()

    datos = {}
    for i, linea in enumerate(lineas):
        limpia = linea.strip()
        if not limpia or limpia.startswith("#"):
            continue

        campo, separador, valor = limpia.partition(":")
        if not separador:
            raise ErrorConfiguracion(f"Línea {i + 1} sin formato 'campo: valor': {limpia!r}")
        campo = normalizar_texto(campo)

        if campo == "mensaje":
            resto = [valor.lstrip()] + lineas[i + 1:]
            datos["mensaje"] = "\n".join(resto).rstrip("\n")
            break
        if campo not in ("semilla", "algoritmo", "tecnica", "accion"):
            raise ErrorConfiguracion(f"Campo desconocido en la línea {i + 1}: {campo!r}")
        datos[campo] = valor.strip()
    return datos


def validar_configuracion(datos):
    """Valida los campos y devuelve (semilla_texto, tecnica, algoritmo, accion, mensaje)."""
    for obligatorio in ("semilla", "algoritmo", "mensaje"):
        if not datos.get(obligatorio, "").strip():
            raise ErrorConfiguracion(f"Falta el campo obligatorio '{obligatorio}'")

    algoritmo = ALGORITMOS.get(normalizar_texto(datos["algoritmo"]))
    if algoritmo is None:
        raise ErrorConfiguracion("Algoritmo no válido. Usa: rsa, elgamal o xor (o 1, 2, 3)")

    tecnica = TECNICAS.get(normalizar_texto(datos.get("tecnica", "mersenne")))
    if tecnica is None:
        raise ErrorConfiguracion("Técnica no válida. Usa: mersenne, sha256, lcg o xorshift")

    mensaje = datos["mensaje"]
    if "accion" in datos and datos["accion"].strip():
        accion = ACCIONES.get(normalizar_texto(datos["accion"]))
        if accion is None:
            raise ErrorConfiguracion("Acción no válida. Usa: cifrar o descifrar")
    else:
        accion = "descifrar" if mensaje.strip().startswith(ETIQUETAS) else "cifrar"

    return datos["semilla"], tecnica, algoritmo, accion, mensaje


def procesar_mensaje(semilla_texto, tecnica, algoritmo, accion, mensaje):
    """Prepara la máquina y los primos, y cifra/descifra. Devuelve (sesion, resultado)."""
    sesion = ContextoCifrado()
    sesion.semilla = resolver_semilla(semilla_texto)
    sesion.tecnica = tecnica
    sesion.algoritmo = algoritmo
    if algoritmo in ("rsa", "elgamal"):
        sesion.buscar_primos()
    sesion.preparar_cifrador()

    if accion == "cifrar":
        return sesion, sesion.cifrador.cifrar(mensaje)

    try:
        return sesion, sesion.cifrador.descifrar(mensaje.strip())
    except (ValueError, UnicodeDecodeError, OverflowError, IndexError) as error:
        raise ErrorConfiguracion(
            "No se pudo descifrar. Revisa que la semilla, la técnica y el algoritmo "
            f"sean los mismos usados al cifrar y que el mensaje esté completo. ({error})")


def imprimir_resultado(sesion, accion, mensaje, resultado, semilla_texto):
    """Muestra el resultado en la consola (no escribe ningún archivo)."""
    print()
    print("=== RESULTADO ===")
    print(f"Acción     : {accion}")
    print(f"Semilla    : {semilla_texto}  (valor numérico: {sesion.semilla})")
    print(f"Técnica    : {sesion.tecnica}")
    print(f"Algoritmo  : {sesion.algoritmo}")
    if sesion.algoritmo in ("rsa", "elgamal"):
        print(f"Primos encontrados en los {CANTIDAD:,} números: {len(sesion.primos)}")
    print()
    if accion == "cifrar":
        print("--- Mensaje original ---")
        print(mensaje)
        print()
        print("--- Mensaje cifrado ---")
        print(resultado)
    else:
        print("--- Mensaje cifrado ---")
        print(mensaje.strip())
        print()
        print("--- Mensaje descifrado ---")
        print(resultado)


def main():
    entrada = sys.argv[1] if len(sys.argv) > 1 else ARCHIVO_ENTRADA

    if not os.path.exists(entrada):
        print(f"No se encontró el archivo '{entrada}'.")
        print("Créalo con este contenido y vuelve a ejecutar el programa:\n")
        print(PLANTILLA)
        return 1

    try:
        datos = cargar_configuracion(entrada)
        semilla_texto, tecnica, algoritmo, accion, mensaje = validar_configuracion(datos)
        print(f"Leyendo '{entrada}': acción={accion}, algoritmo={algoritmo}, "
              f"técnica={tecnica}")
        if algoritmo in ("rsa", "elgamal"):
            print(f"Generando {CANTIDAD:,} números de {CIFRAS} cifras y buscando primos...")
        sesion, resultado = procesar_mensaje(semilla_texto, tecnica, algoritmo, accion, mensaje)
    except ErrorConfiguracion as error:
        print("ERROR:", error)
        return 1

    imprimir_resultado(sesion, accion, mensaje, resultado, semilla_texto)
    if EXPORTAR_PRIMOS and sesion.primos:
        try:
            sesion.exportar_primos()
            print(f"Primos guardados en: {ARCHIVO_PRIMOS}")
        except OSError as error:
            print(f"No se pudo guardar el archivo de primos: {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
