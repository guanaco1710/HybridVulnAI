"""Validación y resolución de objetivos.

Política del proyecto:
- Red local (RFC1918 + loopback): siempre permitida.
- IPs públicas y nombres de host: solo con `permitir_externos=True` (flag --permitir-externos), que
  equivale a declarar que se tiene autorización para escanearlos. Una IP pública suelta o un rango de
  hasta /24; un nombre que resuelva a más de MAX_IPS_POR_HOSTNAME direcciones se rechaza.
- Nunca, ni con el flag: direcciones no enrutables (link-local como 169.254.169.254 de los metadatos
  cloud, multicast, reservadas, documentación, CGNAT), rangos que mezclan local y público, rangos con
  guion y cualquier valor que empiece por '-' (inyección de opciones de nmap).

Los nombres de host se resuelven UNA vez aquí y se escanean las IPs resultantes, nunca el nombre:
así nmap/nuclei no pueden volver a resolverlo y acabar en otra dirección (DNS rebinding).
"""

import ipaddress
import re
import socket

REDES_LOCALES = tuple(
    ipaddress.ip_network(red)
    for red in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
    )
)

# Límite de tamaño para evitar escaneos enormes por error (un /16 IPv4 en la red local).
MAX_DIRECCIONES = 65536
# Fuera de la red local: una IP o, como mucho, un /24 IPv4.
MAX_DIRECCIONES_EXTERNAS = 256
MAX_IPS_POR_HOSTNAME = 8

# Nombre de host (RFC 1123): etiquetas de letras, dígitos y guiones, sin empezar ni acabar en guion.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
                       re.IGNORECASE)


class ObjetivoNoPermitido(ValueError):
    """El objetivo no es válido o queda fuera del alcance permitido."""


def _es_local(red) -> bool:
    return any(red.version == local.version and red.subnet_of(local) for local in REDES_LOCALES)


def _es_publica(ip) -> bool:
    """IP enrutable en Internet. `is_global` de Python da True también para multicast, así que se excluye."""
    ip = getattr(ip, "ipv4_mapped", None) or ip  # ::ffff:10.0.0.1 es la 10.0.0.1, no una dirección pública
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)


def _es_nombre_de_host(texto: str) -> bool:
    # La última etiqueta debe tener letras: así "192.168.0.1-255" o "2130706433" no se toman por nombres.
    return bool(_HOSTNAME.match(texto)) and any(c.isalpha() for c in texto.rsplit(".", 1)[-1])


def es_local(objetivo: str) -> bool:
    """True si la IP o el rango ya validado está dentro de la red local."""
    return _es_local(ipaddress.ip_network(objetivo, strict=False))


def validar_objetivo(texto: str, permitir_externos: bool = False) -> str:
    """Valida una IP o un rango CIDR (no nombres de host) y lo devuelve normalizado."""
    texto = texto.strip()
    if not texto:
        raise ObjetivoNoPermitido("objetivo vacío")
    if texto.startswith("-"):
        raise ObjetivoNoPermitido(f"{texto!r}: no puede empezar por '-'")

    try:
        red = ipaddress.ip_network(texto, strict=False)
    except ValueError:
        raise ObjetivoNoPermitido(
            f"{texto!r}: usa una IP o un rango CIDR (p. ej. 192.168.1.0/24); no se admiten rangos con guion"
        ) from None

    if _es_local(red):
        if red.num_addresses > MAX_DIRECCIONES:
            raise ObjetivoNoPermitido(
                f"{texto!r}: rango demasiado grande ({red.num_addresses} direcciones, máximo {MAX_DIRECCIONES})")
    else:
        _validar_externo(texto, red, permitir_externos)

    return str(red.network_address) if red.num_addresses == 1 else str(red)


def _validar_externo(texto: str, red, permitir_externos: bool) -> None:
    if red.num_addresses > MAX_DIRECCIONES_EXTERNAS or (red.version == 6 and red.num_addresses > 1):
        raise ObjetivoNoPermitido(
            f"{texto!r}: fuera de la red local solo se admite una IP o un rango IPv4 de hasta /24")
    # Se comprueba dirección a dirección: un rango no puede mezclar local, público y no enrutable.
    if not all(_es_publica(ip) for ip in red):
        raise ObjetivoNoPermitido(
            f"{texto!r}: no es una IP pública ni de la red local (link-local, multicast, reservada, "
            "CGNAT...); esas direcciones no se escanean nunca")
    if not permitir_externos:
        raise ObjetivoNoPermitido(
            f"{texto!r}: es una IP pública. Usa --permitir-externos solo si tienes autorización "
            "para escanearla")


def resolver_hostname(nombre: str, permitir_externos: bool = False, resolver=None) -> list[str]:
    """Resuelve un nombre y valida CADA IP resultante con la misma política que una IP escrita a mano."""
    try:
        respuestas = (resolver or socket.getaddrinfo)(nombre, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ObjetivoNoPermitido(f"{nombre!r}: no se pudo resolver ({e})") from None
    ips = sorted({r[4][0].split("%")[0] for r in respuestas})
    if len(ips) > MAX_IPS_POR_HOSTNAME:
        raise ObjetivoNoPermitido(
            f"{nombre!r}: resuelve a {len(ips)} direcciones (máximo {MAX_IPS_POR_HOSTNAME}); "
            "indica las IPs concretas")
    try:
        return [validar_objetivo(ip, permitir_externos) for ip in ips]
    except ObjetivoNoPermitido as e:
        raise ObjetivoNoPermitido(f"{nombre!r} resuelve a una dirección no permitida: {e}") from None


def resolver_objetivos(textos: list[str], permitir_externos: bool = False,
                       resolver=None) -> tuple[list[str], dict[str, str]]:
    """IPs/CIDR/nombres -> (lista de IPs/CIDR validados, {ip: nombre de host solicitado})."""
    if not textos:
        raise ObjetivoNoPermitido("no se ha indicado ningún objetivo")
    objetivos: list[str] = []
    nombres: dict[str, str] = {}
    for texto in (t.strip() for t in textos):
        if _es_nombre_de_host(texto):
            texto = texto.lower()  # los nombres de host no distinguen mayúsculas
            validados = resolver_hostname(texto, permitir_externos, resolver)
            for ip in validados:
                nombres.setdefault(ip, texto)
        else:  # IP o CIDR; si no lo es (vacío, '-x', rango con guion...) lanza el error adecuado
            validados = [validar_objetivo(texto, permitir_externos)]
        objetivos += [v for v in validados if v not in objetivos]
    return objetivos, nombres


def validar_objetivos(textos: list[str], permitir_externos: bool = False) -> list[str]:
    """Valida IPs/CIDR ya resueltos (defensa en profundidad antes de lanzar nmap)."""
    if not textos:
        raise ObjetivoNoPermitido("no se ha indicado ningún objetivo")
    return [validar_objetivo(t, permitir_externos) for t in textos]
