"""Validación de objetivos: solo se permite escanear la red local.

Política del proyecto: RFC1918 + loopback. Nunca IPs públicas.
Solo se aceptan direcciones IP o rangos CIDR; los nombres de host se rechazan
para evitar que un DNS los redirija a una IP pública.
"""

import ipaddress

REDES_PERMITIDAS = tuple(
    ipaddress.ip_network(red)
    for red in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
    )
)

# Límite de tamaño para evitar escaneos enormes por error (un /16 IPv4).
MAX_DIRECCIONES = 65536


class ObjetivoNoPermitido(ValueError):
    """El objetivo no es válido o queda fuera del alcance permitido."""


def validar_objetivo(texto: str) -> str:
    """Devuelve el objetivo normalizado o lanza ObjetivoNoPermitido."""
    texto = texto.strip()
    if not texto:
        raise ObjetivoNoPermitido("objetivo vacío")
    if texto.startswith("-"):
        raise ObjetivoNoPermitido(f"{texto!r}: no puede empezar por '-'")

    try:
        red = ipaddress.ip_network(texto, strict=False)
    except ValueError:
        raise ObjetivoNoPermitido(
            f"{texto!r}: usa una IP o un rango CIDR (p. ej. 192.168.1.0/24); "
            "no se admiten nombres de host ni rangos con guion"
        ) from None

    if red.num_addresses > MAX_DIRECCIONES:
        raise ObjetivoNoPermitido(
            f"{texto!r}: rango demasiado grande ({red.num_addresses} direcciones, "
            f"máximo {MAX_DIRECCIONES})"
        )

    if not any(
        red.version == permitida.version and red.subnet_of(permitida)
        for permitida in REDES_PERMITIDAS
    ):
        raise ObjetivoNoPermitido(
            f"{texto!r}: fuera de la red local permitida "
            "(10/8, 172.16/12, 192.168/16, 127/8, ::1)"
        )

    if red.num_addresses == 1:
        return str(red.network_address)
    return str(red)


def validar_objetivos(textos: list[str]) -> list[str]:
    if not textos:
        raise ObjetivoNoPermitido("no se ha indicado ningún objetivo")
    return [validar_objetivo(t) for t in textos]
