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


def dividir_bytes(datos, tamano):
    """Parte unos bytes en trozos de 'tamano' bytes (al menos un trozo)."""
    return [datos[i:i + tamano] for i in range(0, len(datos), tamano)] or [b""]


class AlgoritmoJ:
    """
    Algoritmo J: cifrado afín con primos.

    Clave: tres primos DISTINTOS de los encontrados  ->  P, A y B
        P = módulo,  A = multiplicador,  B = desplazamiento

    Cada bloque del mensaje, convertido a número m, se cifra así:
        c = (A * m + B) mod P
    y se descifra con el inverso de A:
        m = (c - B) * A^-1 mod P        (A^-1 = pow(A, -1, P))

    Como P es primo, A siempre tiene inverso módulo P, y por eso el
    descifrado siempre es posible.

    Detalles:
      - Cada bloque se arma como 0x01 + trozo del mensaje (el 0x01 conserva
        los ceros a la izquierda).
      - Antes de cifrar se antepone al mensaje una suma de comprobación de 8
        caracteres (SHA-256), para detectar claves incorrectas y mensajes
        alterados al descifrar.

    AVISO: es un algoritmo didáctico y básico. No es seguro: mensajes iguales
    dan bloques cifrados iguales, y con un par (texto, cifrado) conocido se
    pueden deducir A y B resolviendo un sistema de ecuaciones.
    """
    etiqueta = "J"

    def __init__(self, primos, rng):
        if len(primos) < 3:
            raise ValueError("Se necesitan al menos 3 primos; aumenta CANTIDAD")
        p, a, b = rng.sample(primos, 3)
        self.P = p
        self._A = a % p
        self._B = b % p
        self._A_inv = pow(self._A, -1, p)

        # Bytes por bloque: el número del bloque debe ser menor que P
        self.bytes_bloque = (p.bit_length() - 1) // 8
        self.bytes_mensaje = self.bytes_bloque - 1

    @staticmethod
    def _control(texto):
        return hashlib.sha256(texto.encode("utf-8")).hexdigest()[:8]

    def cifrar(self, texto):
        texto = self._control(texto) + texto
        bloques = []
        for trozo in dividir_bytes(texto.encode("utf-8"), self.bytes_mensaje):
            m = int.from_bytes(b"\x01" + trozo, "big")
            c = (self._A * m + self._B) % self.P
            bloques.append(format(c, "x"))
        return self.etiqueta + "|" + ":".join(bloques)

    def descifrar(self, cifrado):
        etiqueta, _, cuerpo = cifrado.strip().partition("|")
        if etiqueta != self.etiqueta:
            raise ValueError(f"Este mensaje fue cifrado con '{etiqueta}', "
                             f"pero este programa usa el Algoritmo '{self.etiqueta}'")
        datos = bytearray()
        for bloque in cuerpo.split(":"):
            c = int(bloque, 16)
            m = ((c - self._B) * self._A_inv) % self.P
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            if not b or b[0] != 1:
                raise ValueError("Bloque inválido: clave incorrecta o mensaje alterado")
            datos.extend(b[1:])
        plano = datos.decode("utf-8")
        control, texto = plano[:8], plano[8:]
        if control != self._control(texto):
            raise ValueError("Comprobación fallida: clave incorrecta o mensaje alterado")
        return texto

    def claves(self):
        return [("P (módulo, primo)", self.P),
                ("A (multiplicador)", self._A),
                ("B (desplazamiento)", self._B)]


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
        rng = random.Random(f"{self.semilla}|{self.tecnica}|J")
        self.cifrador = AlgoritmoJ(self.primos, rng)
        self.ultimo_cifrado = None


ARCHIVO_ENTRADA = "instrucciones.txt"

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
ETIQUETAS = ("J|",)

PLANTILLA = """# INSTRUCCIONES PARA EL CIFRADOR (Algoritmo J)
# Una línea por campo. El campo "mensaje" va SIEMPRE al final.
# semilla   : un número o una frase (obligatorio)
# tecnica   : mersenne | sha256 | lcg | xorshift   (o 1 | 2 | 3 | 4)
# accion    : cifrar | descifrar
# Para DESCIFRAR: usa la misma semilla y técnica con las que cifraste,
# y pega el mensaje cifrado (empieza con J|).

semilla: mi semilla secreta
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
        if campo == "algoritmo":
            raise ErrorConfiguracion(f"Línea {i + 1}: el campo 'algoritmo' ya no existe; "
                                     "siempre se usa el Algoritmo J. Elimina esa línea.")
        if campo not in ("semilla", "tecnica", "accion"):
            raise ErrorConfiguracion(f"Campo desconocido en la línea {i + 1}: {campo!r}")
        datos[campo] = valor.strip()
    return datos


def validar_configuracion(datos):
    """Valida los campos y devuelve (semilla_texto, tecnica, accion, mensaje)."""
    for obligatorio in ("semilla", "mensaje"):
        if not datos.get(obligatorio, "").strip():
            raise ErrorConfiguracion(f"Falta el campo obligatorio '{obligatorio}'")

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

    return datos["semilla"], tecnica, accion, mensaje


def procesar_mensaje(semilla_texto, tecnica, accion, mensaje):
    """Prepara la máquina y los primos, y cifra/descifra. Devuelve (sesion, resultado)."""
    sesion = ContextoCifrado()
    sesion.semilla = resolver_semilla(semilla_texto)
    sesion.tecnica = tecnica
    sesion.buscar_primos()
    try:
        sesion.preparar_cifrador()
    except ValueError as error:
        raise ErrorConfiguracion(str(error))

    if accion == "cifrar":
        return sesion, sesion.cifrador.cifrar(mensaje)

    try:
        return sesion, sesion.cifrador.descifrar(mensaje.strip())
    except (ValueError, UnicodeDecodeError, OverflowError, IndexError) as error:
        raise ErrorConfiguracion(
            "No se pudo descifrar. Revisa que la semilla y la técnica "
            f"sean las mismas usadas al cifrar y que el mensaje esté completo. ({error})")


def imprimir_resultado(sesion, accion, mensaje, resultado, semilla_texto):
    """Muestra el resultado en la consola (no escribe ningún archivo)."""
    print()
    print("=== RESULTADO ===")
    print(f"Acción     : {accion}")
    print(f"Semilla    : {semilla_texto}  (valor numérico: {sesion.semilla})")
    print(f"Técnica    : {sesion.tecnica}")
    print("Algoritmo  : Algoritmo J")
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
        semilla_texto, tecnica, accion, mensaje = validar_configuracion(datos)
        print(f"Leyendo '{entrada}': acción={accion}, técnica={tecnica}")
        print(f"Generando {CANTIDAD:,} números de {CIFRAS} cifras y buscando primos...")
        sesion, resultado = procesar_mensaje(semilla_texto, tecnica, accion, mensaje)
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
