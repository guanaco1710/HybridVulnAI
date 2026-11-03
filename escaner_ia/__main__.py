"""CLI: python -m escaner_ia 192.168.1.0/24"""

import argparse
import sys
from pathlib import Path

from . import nvd, ollama
from .escaner import PERFILES, ErrorEscaneo, escanear
from .informe import generar_informe
from .objetivos import ObjetivoNoPermitido, validar_objetivos
from .parser import parsear_xml


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="escaner_ia",
        description="Escanea la red local con nmap y analiza el resultado con un modelo de Ollama.")
    ap.add_argument("objetivos", nargs="+", help="IPs o rangos CIDR de la red local (RFC1918/loopback)")
    ap.add_argument("--perfil", choices=PERFILES, default="vulners", help="perfil de escaneo (def.: vulners)")
    ap.add_argument("--so", action="store_true", help="detectar sistema operativo (-O, requiere root)")
    ap.add_argument("--modelo", default=ollama.MODELO_POR_DEFECTO, help="modelo de Ollama")
    ap.add_argument("--ollama-url", default=ollama.URL_POR_DEFECTO)
    ap.add_argument("--salida", default="informe.md", help="fichero del informe (def.: informe.md)")
    ap.add_argument("--guardar-xml", metavar="FICHERO", help="guarda también el XML bruto de nmap")
    ap.add_argument("--verificar-cve", action="store_true",
                    help="comprueba en NVD que existen los CVE citados (envía solo los IDs)")
    ap.add_argument("--sin-ia", action="store_true", help="solo escanea, sin llamar a Ollama")
    args = ap.parse_args(argv)

    try:
        objetivos = validar_objetivos(args.objetivos)
        if not args.sin_ia:
            ollama.comprobar_modelo(args.modelo, args.ollama_url)
        print(f"[*] Escaneando {', '.join(objetivos)} (perfil {args.perfil})...", file=sys.stderr)
        xml = escanear(objetivos, args.perfil, args.so)
    except (ObjetivoNoPermitido, ErrorEscaneo, ollama.ErrorOllama) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.guardar_xml:
        Path(args.guardar_xml).write_text(xml, encoding="utf-8")
    datos = parsear_xml(xml)
    print(f"[*] {len(datos['hosts'])} host(s) activo(s).", file=sys.stderr)

    analisis = {}
    if not args.sin_ia:
        for host in datos["hosts"]:
            if not host["puertos"]:
                continue
            print(f"[*] Analizando {host['ip']} con {args.modelo}...", file=sys.stderr)
            try:
                analisis[host["ip"]] = ollama.analizar_host(host, args.modelo, args.ollama_url)
            except ollama.ErrorOllama as e:
                print(f"    aviso: {e}", file=sys.stderr)

    verificacion = None
    if args.verificar_cve:
        ids = {c["id"] for a in analisis.values() for h in a["hallazgos"] for c in h["cves"]}
        ids |= {c["id"] for h in datos["hosts"] for p in h["puertos"] for c in p["cves_nmap"]}
        if ids:
            print(f"[*] Verificando {len(ids)} CVE en NVD...", file=sys.stderr)
            verificacion = nvd.verificar_cves(ids)

    Path(args.salida).write_text(generar_informe(datos, analisis, verificacion, args.modelo), encoding="utf-8")
    print(f"[+] Informe guardado en {args.salida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
