"""Ejecución de nmap con argumentos fijos (sin shell y sin opciones libres)."""

import os
import shutil
import subprocess

from .objetivos import validar_objetivos

# Perfiles cerrados: el usuario elige uno, nunca pasa opciones arbitrarias a nmap.
PERFILES = {
    "rapido": ["-sV", "--top-ports", "100", "-T4"],
    "estandar": ["-sV", "-sC", "-T4"],
    "vulners": ["-sV", "-sC", "--script", "vulners", "-T4"],
}


class ErrorEscaneo(RuntimeError):
    pass


def construir_comando(objetivos: list[str], perfil: str, detectar_so: bool = False,
                      permitir_externos: bool = False) -> list[str]:
    if perfil not in PERFILES:
        raise ErrorEscaneo(f"perfil desconocido: {perfil}")
    nmap = shutil.which("nmap")
    if nmap is None:
        raise ErrorEscaneo("nmap no está instalado o no está en el PATH")

    # Se revalida aquí también, por si acaso. Aquí ya solo llegan IPs/CIDR (los nombres se resolvieron antes).
    objetivos = validar_objetivos(objetivos, permitir_externos)
    comando = [nmap, *PERFILES[perfil]]
    if detectar_so:
        comando.append("-O")
    # "-oX -" => XML por la salida estándar; "--" => lo que sigue nunca es una opción.
    comando += ["-oX", "-", "--", *objetivos]
    return comando


def escanear(objetivos: list[str], perfil: str = "vulners", detectar_so: bool = False,
             timeout: int = 3600, permitir_externos: bool = False) -> str:
    """Lanza nmap y devuelve su salida XML."""
    if detectar_so and os.geteuid() != 0:
        raise ErrorEscaneo("la detección de SO (-O) requiere ejecutar como root")

    comando = construir_comando(objetivos, perfil, detectar_so, permitir_externos)
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ErrorEscaneo(f"nmap superó el tiempo límite de {timeout} s") from None

    if resultado.returncode != 0:
        raise ErrorEscaneo(f"nmap terminó con código {resultado.returncode}: "
                           f"{resultado.stderr.strip()}")
    return resultado.stdout
