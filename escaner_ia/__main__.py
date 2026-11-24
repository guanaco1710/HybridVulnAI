"""CLI de hybridVuln AI: python -m escaner_ia 192.168.1.0/24"""

import argparse
import os
import sys
from pathlib import Path

from . import nuclei, nvd, ollama, pdf, proveedores
from .escaner import PERFILES, ErrorEscaneo, escanear
from .informe import generar_informe, generar_informe_html
from .objetivos import ObjetivoNoPermitido, validar_objetivos
from .parser import parsear_xml


def cargar_env(args) -> dict:
    """El .env tiene prioridad sobre el entorno del proceso."""
    return {**os.environ, **proveedores.leer_env(Path(args.env))}


def analizar_con_ollama(hosts: list[dict], args) -> dict[str, dict]:
    """Ollama es local y sin cuota: se analiza host a host, que es lo que mejor van los modelos pequeños."""
    analisis = {}
    for host in hosts:
        print(f"[*] Analizando {host['ip']} con ollama:{args.modelo}...", file=sys.stderr)
        try:
            analisis[host["ip"]] = ollama.analizar_host(host, args.modelo, args.ollama_url)
        except ollama.ErrorOllama as e:
            print(f"    aviso: {e}", file=sys.stderr)
    return analisis


def ejecutar_nuclei(datos: dict, perfil: str, timeout: int) -> None:
    """Añade host["nuclei"] (lista de hallazgos) a cada host. Si nuclei falla, avisa y sigue sin ellos."""
    print(f"[*] Escaneando con nuclei (perfil {perfil})...", file=sys.stderr)
    try:
        hallazgos = nuclei.escanear(datos["hosts"], perfil, timeout)
    except nuclei.ErrorNuclei as e:
        print(f"    aviso: {e}", file=sys.stderr)
        if e.parciales is None:
            datos["nuclei"] = None  # no se afirma "sin vulnerabilidades" si el escaneo no se hizo
            return
        hallazgos = e.parciales
        datos["nuclei_incompleto"] = True
    for host in datos["hosts"]:
        host["nuclei"] = hallazgos.get(host["ip"], [])
    print(f"[*] nuclei: {sum(len(v) for v in hallazgos.values())} hallazgo(s).", file=sys.stderr)


def preparar_analizadores(args) -> list:
    """Analizadores disponibles por orden de preferencia: IA online (si hay API key) y Ollama."""
    analizadores = []
    env = cargar_env(args)
    try:
        online = proveedores.detectar(args.proveedor, env)
    except proveedores.ErrorOnline as e:
        print(f"[*] IA online no disponible: {e}", file=sys.stderr)
        online = None
    if online:
        prov, clave = online
        modelo = args.modelo_online or env.get("MODELO_IA") or proveedores.PROVEEDORES[prov]["modelo"]
        print(f"[!] Se enviarán los resultados del escaneo (IPs, puertos, versiones) a {prov} "
              f"({modelo}).", file=sys.stderr)
        analizadores.append((f"{prov}:{modelo}",
                             lambda hosts, xml: proveedores.analizar_red(xml, hosts, prov, modelo, clave)))
    try:
        ollama.comprobar_modelo(args.modelo, args.ollama_url)
        analizadores.append((f"ollama:{args.modelo}",
                             lambda hosts, xml: analizar_con_ollama(hosts, args)))
    except ollama.ErrorOllama as e:
        print(f"[*] Ollama no disponible: {e}", file=sys.stderr)
    return analizadores


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="escaner_ia",
        description="hybridVuln AI: escanea la red local con nmap y analiza el resultado con una IA online "
                    "(si hay API key en el .env) o con un modelo de Ollama. "
                    "Sin ninguna de las dos, solo guarda el XML de nmap.")
    ap.add_argument("objetivos", nargs="+", help="IPs o rangos CIDR de la red local (RFC1918/loopback)")
    ap.add_argument("--perfil", choices=PERFILES, default="vulners", help="perfil de escaneo (def.: vulners)")
    ap.add_argument("--so", action="store_true", help="detectar sistema operativo (-O, requiere root)")
    ap.add_argument("--modelo", default=ollama.MODELO_POR_DEFECTO, help="modelo de Ollama")
    ap.add_argument("--ollama-url", default=ollama.URL_POR_DEFECTO)
    ap.add_argument("--proveedor", choices=list(proveedores.PROVEEDORES),
                    help="IA online a usar (def.: PROVEEDOR_IA del .env o el deducido del prefijo de API_KEY_IA)")
    ap.add_argument("--env", default=str(proveedores.RUTA_ENV), metavar="FICHERO",
                    help="fichero .env con las API keys (def.: .env en la raíz del proyecto)")
    ap.add_argument("--modelo-online", help="modelo de la IA online (def.: MODELO_IA del .env o uno por proveedor)")
    ap.add_argument("--salida", default="informe.md", help="fichero del informe (def.: informe.md)")
    ap.add_argument("--guardar-xml", metavar="FICHERO", help="guarda también el XML bruto de nmap")
    ap.add_argument("--verificar-cve", action="store_true",
                    help="comprueba en NVD que existen los CVE citados (envía solo los IDs)")
    ap.add_argument("--nuclei", action="store_true",
                    help="tras nmap, escanea con nuclei los puertos abiertos encontrados (más lento)")
    ap.add_argument("--perfil-nuclei", choices=nuclei.PERFILES, default="estandar",
                    help="perfil de nuclei (def.: estandar = severidad media, alta y crítica)")
    ap.add_argument("--timeout-nuclei", type=int, default=3600, metavar="SEGUNDOS",
                    help="tiempo máximo de nuclei (def.: 3600). Tarda minutos por cada puerto abierto")
    ap.add_argument("--sin-pdf", action="store_true", help="no genera el PDF (solo el informe Markdown)")
    ap.add_argument("--sin-ia", action="store_true", help="solo escanea, sin llamar a ninguna IA")
    args = ap.parse_args(argv)

    try:
        objetivos = validar_objetivos(args.objetivos)
        analizadores = [] if args.sin_ia else preparar_analizadores(args)
        if args.nuclei:
            nuclei.binario()  # falla antes de escanear si nuclei no está instalado
        print(f"[*] Escaneando {', '.join(objetivos)} (perfil {args.perfil})...", file=sys.stderr)
        xml = escanear(objetivos, args.perfil, args.so)
    except (ObjetivoNoPermitido, ErrorEscaneo, nuclei.ErrorNuclei) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Con nuclei hay datos que merecen informe aunque no haya IA; sin él, solo se guarda el XML.
    sin_analizadores = not args.sin_ia and not analizadores and not args.nuclei
    if args.guardar_xml or sin_analizadores:
        ruta_xml = Path(args.guardar_xml or Path(args.salida).with_suffix(".xml"))
        ruta_xml.write_text(xml, encoding="utf-8")
        print(f"[+] XML de nmap guardado en {ruta_xml}", file=sys.stderr)
    if sin_analizadores:
        print("[*] Sin IA online ni Ollama: solo se guarda el XML (sin informe).", file=sys.stderr)
        return 0
    datos = parsear_xml(xml)
    print(f"[*] {len(datos['hosts'])} host(s) activo(s).", file=sys.stderr)

    datos["nuclei"] = args.perfil_nuclei if args.nuclei else None
    if args.nuclei:
        ejecutar_nuclei(datos, args.perfil_nuclei, args.timeout_nuclei)

    analisis, usados = {}, set()
    pendientes = [h for h in datos["hosts"] if h["puertos"]]
    for etiqueta, analizar in analizadores:
        if not pendientes:
            break
        print(f"[*] Analizando {len(pendientes)} host(s) con {etiqueta}...", file=sys.stderr)
        obtenido = analizar(pendientes, xml)
        if obtenido:
            usados.add(etiqueta)
        analisis.update(obtenido)
        pendientes = [h for h in pendientes if h["ip"] not in analisis]
    modelo = ", ".join(sorted(usados)) or "ninguno"

    verificacion = None
    if args.verificar_cve:
        ids = {c["id"] for a in analisis.values() for h in a["hallazgos"] for c in h["cves"]}
        ids |= {c["id"] for h in datos["hosts"] for p in h["puertos"] for c in p["cves_nmap"]}
        ids |= {c for h in datos["hosts"] for n in h.get("nuclei", []) for c in n["cves"]}
        if ids:
            print(f"[*] Verificando {len(ids)} CVE en NVD...", file=sys.stderr)
            verificacion = nvd.verificar_cves(ids, cargar_env(args))

    Path(args.salida).write_text(generar_informe(datos, analisis, verificacion, modelo), encoding="utf-8")
    print(f"[+] Informe guardado en {args.salida}", file=sys.stderr)
    if not args.sin_pdf:
        ruta_pdf = Path(args.salida).with_suffix(".pdf")
        try:
            pdf.guardar_pdf(generar_informe_html(datos, analisis, verificacion, modelo), ruta_pdf)
            print(f"[+] Informe PDF guardado en {ruta_pdf}", file=sys.stderr)
        except pdf.ErrorPDF as e:
            print(f"aviso: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
