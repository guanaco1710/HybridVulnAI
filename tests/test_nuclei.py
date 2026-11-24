"""Tests de la integración con nuclei. Nuclei no se ejecuta de verdad: subprocess se simula."""

import contextlib
import io
import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from escaner_ia import __main__ as cli
from escaner_ia import nuclei, nvd, ollama, pdf, proveedores
from escaner_ia.informe import generar_informe, generar_informe_html
from tests.test_escaner_ia import XML
from tests.test_informe_cli import DATOS


def host(ip="192.168.1.5", puertos=(22, 80)):
    return {"ip": ip, "nombres": [], "so": [], "scripts_host": [], "puertos": [
        {"puerto": p, "protocolo": "tcp", "servicio": "x", "producto": "", "version": "", "extra": "",
         "cpe": [], "scripts": [], "cves_nmap": []} for p in puertos]}


def linea(**cambios):
    """Una línea JSONL con la forma que emite nuclei."""
    base = {"template-id": "CVE-2023-1234", "type": "http", "host": "192.168.1.5:80", "port": "80",
            "ip": "192.168.1.5", "matched-at": "http://192.168.1.5:80/login", "extracted-results": ["v1"],
            "info": {"name": "Panel expuesto", "severity": "high", "description": "d",
                     "reference": ["https://a", "https://b", "https://c", "https://d"],
                     "classification": {"cve-id": ["cve-2023-1234"], "cvss-score": 8.8}}}
    base.update(cambios)
    return json.dumps(base)


class TestObjetivos(unittest.TestCase):
    def test_ip_puerto_de_los_abiertos(self):
        self.assertEqual(nuclei.objetivos_de_hosts([host(puertos=(22, 80))]),
                         ["192.168.1.5:22", "192.168.1.5:80"])

    def test_ipv6_va_entre_corchetes(self):
        self.assertEqual(nuclei.objetivos_de_hosts([host("::1", (80,))]), ["[::1]:80"])

    def test_hosts_sin_puertos_no_se_escanean(self):
        self.assertEqual(nuclei.objetivos_de_hosts([host(puertos=())]), [])

    def test_nunca_pasa_ips_publicas_ni_rangos_ni_basura(self):
        for ip in ("8.8.8.8", "1.1.1.1", "desconocida", "10.0.0.0/24", "-sS", "scanme.nmap.org"):
            self.assertEqual(nuclei.objetivos_de_hosts([host(ip)]), [], msg=ip)

    def test_una_ip_publica_no_contamina_a_las_privadas(self):
        self.assertEqual(nuclei.objetivos_de_hosts([host("8.8.8.8"), host("10.0.0.7", (443,))]),
                         ["10.0.0.7:443"])


class TestComando(unittest.TestCase):
    def comando(self, perfil="estandar"):
        with mock.patch.object(nuclei.shutil, "which", return_value="/usr/bin/nuclei"):
            return nuclei.construir_comando("/tmp/objetivos.txt", perfil)

    def test_opciones_de_seguridad_fijas(self):
        cmd = self.comando()
        self.assertEqual(cmd[:3], ["/usr/bin/nuclei", "-list", "/tmp/objetivos.txt"])
        for opcion in ("-jsonl", "-silent", "-ni", "-duc", "-dut", "-or"):
            self.assertIn(opcion, cmd)
        self.assertEqual(cmd[cmd.index("-etags") + 1], nuclei.TAGS_EXCLUIDOS)
        for tag in ("dos", "fuzz", "intrusive", "bruteforce"):
            self.assertIn(tag, nuclei.TAGS_EXCLUIDOS)

    def test_perfiles(self):
        for perfil, severidades in (("rapido", "high,critical"), ("estandar", "medium,high,critical"),
                                    ("completo", "info,low,medium,high,critical")):
            cmd = self.comando(perfil)
            self.assertEqual(cmd[cmd.index("-severity") + 1], severidades)

    def test_perfil_desconocido(self):
        with self.assertRaises(nuclei.ErrorNuclei):
            self.comando("inventado")

    def test_sin_nuclei_instalado(self):
        with mock.patch.object(nuclei.shutil, "which", return_value=None):
            with self.assertRaises(nuclei.ErrorNuclei) as cm:
                nuclei.binario()
        self.assertIn("no está instalado", str(cm.exception))


class TestParseo(unittest.TestCase):
    IPS = {"192.168.1.5"}

    def parsear(self, *lineas, ips=None):
        return nuclei.parsear_jsonl("\n".join(lineas), ips or self.IPS)

    def test_hallazgo_completo(self):
        h = self.parsear(linea())["192.168.1.5"][0]
        self.assertEqual(h["id"], "CVE-2023-1234")
        self.assertEqual(h["nombre"], "Panel expuesto")
        self.assertEqual((h["severidad"], h["puerto"], h["cvss"]), ("alta", 80, 8.8))
        self.assertEqual(h["cves"], ["CVE-2023-1234"])
        self.assertEqual(h["referencias"], ["https://a", "https://b", "https://c"])  # máximo 3
        self.assertEqual(h["extraidos"], ["v1"])
        self.assertEqual(h["detalles"], [])

    def test_agrupa_los_matchers_de_una_misma_plantilla(self):
        """Salida real de nuclei: una línea por matcher (una por cada cabecera que falta)."""
        r = self.parsear(linea(**{"matcher-name": "x-frame-options"}),
                         linea(**{"matcher-name": "referrer-policy"}),
                         linea(**{"matcher-name": "x-frame-options"}),  # repetido: no se duplica
                         linea(**{"matcher-name": "otra-url"}, **{"matched-at": "http://192.168.1.5:80/otra"}),
                         linea(**{"template-id": "otra-plantilla", "matcher-name": "m"}))
        hallazgos = r["192.168.1.5"]
        self.assertEqual(len(hallazgos), 3)
        self.assertEqual(hallazgos[0]["detalles"], ["x-frame-options", "referrer-policy"])
        self.assertEqual(hallazgos[1]["detalles"], ["otra-url"])  # otra coincidencia = otro hallazgo
        self.assertEqual(hallazgos[2]["id"], "otra-plantilla")

    def test_extracted_results_nulo(self):
        """Nuclei emite null cuando no hay resultados extraídos."""
        self.assertEqual(self.parsear(linea(**{"extracted-results": None}))["192.168.1.5"][0]["extraidos"], [])

    def test_cve_como_cadena_en_vez_de_lista(self):
        info = {"name": "n", "severity": "low", "classification": {"cve-id": "CVE-2020-0001"}}
        self.assertEqual(self.parsear(linea(info=info))["192.168.1.5"][0]["cves"], ["CVE-2020-0001"])

    def test_cve_invalido_o_ausente(self):
        for clasificacion in ({"cve-id": ["no-es-cve"]}, {"cve-id": None}, {}):
            info = {"name": "n", "severity": "low", "classification": clasificacion}
            self.assertEqual(self.parsear(linea(info=info))["192.168.1.5"][0]["cves"], [])

    def test_severidades(self):
        for original, esperada in (("critical", "critica"), ("MEDIUM", "media"), ("info", "info"),
                                   ("unknown", "info"), ("rara", "info")):
            info = {"name": "n", "severity": original}
            self.assertEqual(self.parsear(linea(info=info))["192.168.1.5"][0]["severidad"], esperada)

    def test_ignora_lineas_que_no_son_objetos_json(self):
        r = self.parsear("[INF] arrancando", "", "[1, 2]", "42", linea())
        self.assertEqual(len(r["192.168.1.5"]), 1)

    def test_descarta_resultados_de_ips_no_escaneadas(self):
        self.assertEqual(self.parsear(linea(ip="8.8.8.8", host="8.8.8.8:80")), {})

    def test_ip_deducida_del_campo_host(self):
        sin_ip = json.loads(linea())
        del sin_ip["ip"]
        self.assertIn("192.168.1.5", self.parsear(json.dumps(sin_ip)))
        sin_ip["host"] = "[::1]:80"
        self.assertIn("::1", self.parsear(json.dumps(sin_ip), ips={"::1"}))

    def test_puerto_invalido_y_campos_opcionales_ausentes(self):
        minimo = json.dumps({"template-id": "x", "ip": "192.168.1.5", "port": "abc"})
        h = self.parsear(minimo)["192.168.1.5"][0]
        self.assertEqual((h["puerto"], h["nombre"], h["severidad"], h["referencias"], h["extraidos"]),
                         (0, "x", "info", [], []))

    def test_referencias_que_no_son_lista_y_descripcion_larga(self):
        info = {"name": "n", "severity": "low", "reference": "https://solo-una", "description": "d" * 900}
        h = self.parsear(linea(info=info))["192.168.1.5"][0]
        self.assertEqual(h["referencias"], [])
        self.assertEqual(len(h["descripcion"]), nuclei.MAX_DESCRIPCION)


class TestEscanear(unittest.TestCase):
    def ejecutar(self, hosts=None, **resultado):
        usados = {}

        def falso(comando, **kw):
            ruta = comando[comando.index("-list") + 1]
            usados["ruta"], usados["contenido"], usados["kw"] = ruta, Path(ruta).read_text(), kw
            if isinstance(resultado.get("side_effect"), Exception):
                raise resultado["side_effect"]
            return resultado["return_value"]

        with mock.patch.object(nuclei.shutil, "which", return_value="/usr/bin/nuclei"), \
                mock.patch.object(nuclei.subprocess, "run", side_effect=falso):
            try:
                return nuclei.escanear(hosts or [host()], "rapido"), usados
            finally:
                self.assertFalse(os.path.exists(usados["ruta"]), "el fichero temporal debe borrarse")

    def test_sin_objetivos_no_ejecuta_nada(self):
        with mock.patch.object(nuclei.subprocess, "run") as run:
            self.assertEqual(nuclei.escanear([host(puertos=())]), {})
        run.assert_not_called()

    def test_ok(self):
        r, usados = self.ejecutar(return_value=mock.Mock(returncode=0, stdout=linea(), stderr=""))
        self.assertEqual(r["192.168.1.5"][0]["id"], "CVE-2023-1234")
        self.assertEqual(usados["contenido"], "192.168.1.5:22\n192.168.1.5:80\n")
        self.assertFalse(usados["kw"].get("shell", False))

    def test_ipv6_filtra_por_la_ip_sin_corchetes(self):
        salida = linea(ip="::1", host="[::1]:80")
        r, _ = self.ejecutar([host("::1", (80,))],
                             return_value=mock.Mock(returncode=0, stdout=salida, stderr=""))
        self.assertIn("::1", r)

    def test_timeout_conserva_los_hallazgos_parciales(self):
        for parcial in (linea().encode(), linea(), None):  # bytes, str o nada (según la versión de Python)
            with self.assertRaises(nuclei.ErrorNuclei) as cm:
                self.ejecutar(side_effect=subprocess.TimeoutExpired("nuclei", 1, output=parcial))
            self.assertIn("tiempo límite", str(cm.exception))
            self.assertIn("incompletos", str(cm.exception))
            esperados = 0 if parcial is None else 1
            self.assertEqual(len(cm.exception.parciales.get("192.168.1.5", [])), esperados)

    def test_otros_errores_no_traen_parciales(self):
        self.assertIsNone(nuclei.ErrorNuclei("x").parciales)

    def test_codigo_distinto_de_cero_sugiere_actualizar_plantillas(self):
        with self.assertRaises(nuclei.ErrorNuclei) as cm:
            self.ejecutar(return_value=mock.Mock(returncode=1, stdout="", stderr="no templates provided"))
        self.assertIn("nuclei -ut", str(cm.exception))
        self.assertIn("no templates provided", str(cm.exception))


class TestUsoEnLaIA(unittest.TestCase):
    def host_con_nuclei(self):
        h = host()
        h["nuclei"] = [{"id": "t", "nombre": "n", "severidad": "alta", "puerto": 22, "coincidencia": "u", "detalles": ["m1"],
                        "descripcion": "d", "cves": ["CVE-2023-1234"], "cvss": 8.8,
                        "referencias": ["https://x"], "extraidos": ["no"], "tipo": "http"}]
        return h

    def test_nuclei_compacto_quita_campos_inutiles(self):
        c = ollama.nuclei_compacto(self.host_con_nuclei())[0]
        self.assertNotIn("referencias", c)
        self.assertNotIn("extraidos", c)
        self.assertEqual(ollama.nuclei_compacto(host()), [])

    def test_el_prompt_de_ollama_incluye_nuclei(self):
        self.assertIn('"nuclei"', ollama.mensaje_usuario(self.host_con_nuclei()))

    def test_origen_nuclei_para_los_cve_que_confirmo(self):
        r = ollama.clasificar_origen({"hallazgos": [{"cves": ["CVE-2023-1234", "CVE-2099-0001"]}]},
                                     self.host_con_nuclei())
        self.assertEqual(r["hallazgos"][0]["cves"], [{"id": "CVE-2023-1234", "origen": "nuclei"},
                                                     {"id": "CVE-2099-0001", "origen": "ia"}])

    def test_la_peticion_online_adjunta_los_hallazgos_de_nuclei(self):
        h = self.host_con_nuclei()
        h["ip"] = "192.168.1.5"
        enviados = []

        def falsa(modelo, clave, sistema, usuario, timeout):
            enviados.append(usuario)
            return '{"hosts": []}'
        with mock.patch.dict(proveedores._LLAMADAS, {"openai": falsa}):
            proveedores.analizar_red(XML, [h], "openai", "m", "k")
        self.assertIn("Hallazgos de nuclei por host", enviados[0])
        self.assertIn("CVE-2023-1234", enviados[0])

    def test_sin_nuclei_la_peticion_no_cambia(self):
        enviados = []

        def falsa(modelo, clave, sistema, usuario, timeout):
            enviados.append(usuario)
            return '{"hosts": []}'
        with mock.patch.dict(proveedores._LLAMADAS, {"openai": falsa}):
            proveedores.analizar_red(XML, [host()], "openai", "m", "k")
        self.assertNotIn("nuclei", enviados[0])


class TestInformeNuclei(unittest.TestCase):
    def datos(self, nuclei_perfil="estandar"):
        h1 = host("10.0.0.1")
        h1["nuclei"] = [
            {"id": "x|y", "nombre": "Baja | con pipe\nsalto", "severidad": "baja", "puerto": 0,
             "coincidencia": "", "cves": [], "cvss": None, "detalles": ["h1", "h|2"]},
            {"id": "CVE-2023-1234", "nombre": "<b>Alta</b>", "severidad": "alta", "puerto": 22,
             "coincidencia": "http://10.0.0.1/x", "cves": ["CVE-2023-1234"], "cvss": 8.8, "detalles": []},
            {"id": "z", "nombre": "Rara", "severidad": "inventada", "puerto": 80,
             "coincidencia": "u", "cves": [], "cvss": None, "detalles": []}]
        h2 = host("10.0.0.2")
        h2["nuclei"] = []
        h3 = host("10.0.0.3")  # sin clave "nuclei": nuclei no se ejecutó o falló
        return {"comando": "nmap", "nuclei": nuclei_perfil, "hosts": [h1, h2, h3]}

    def test_markdown(self):
        md = generar_informe(self.datos(), {}, None, "m")
        self.assertIn("- Nuclei: perfil `estandar`", md)
        self.assertEqual(md.count("Vulnerabilidades detectadas por nuclei"), 2)  # h3 no la tiene
        self.assertIn("Sin vulnerabilidades detectadas por nuclei", md)
        self.assertIn("CVE-2023-1234", md)
        self.assertIn("Baja \\| con pipe salto", md)
        self.assertIn(": h1, h\\|2", md)  # los detalles agrupados se muestran, con el | escapado  # el | no rompe la tabla ni hay saltos de línea
        self.assertLess(md.index("ALTA"), md.index("BAJA"))
        self.assertLess(md.index("BAJA"), md.index("INVENTADA"))

    def test_html_escapa_y_ordena(self):
        html = generar_informe_html(self.datos(), {}, None, "m")
        self.assertIn("perfil <code>estandar</code>", html)
        self.assertNotIn("<b>Alta</b>", html)
        self.assertIn("&lt;b&gt;Alta&lt;/b&gt;", html)
        self.assertIn("Sin vulnerabilidades detectadas por nuclei", html)
        self.assertIn(": h1, h|2", html)
        self.assertLess(html.index("&lt;b&gt;Alta"), html.index("Baja"))

    def test_informe_incompleto_no_afirma_que_no_hay_vulnerabilidades(self):
        datos = self.datos()
        datos["nuclei_incompleto"] = True
        md = generar_informe(datos, {}, None, "m")
        self.assertIn("(**INCOMPLETO**", md)
        self.assertIn("en el tiempo disponible** (escaneo incompleto)", md)
        html = generar_informe_html(datos, {}, None, "m")
        self.assertIn("<b>INCOMPLETO</b>", html)
        self.assertIn("en el tiempo disponible</b> (escaneo incompleto)", html)

    def test_sin_nuclei_no_hay_seccion_ni_cabecera(self):
        for generar in (generar_informe, generar_informe_html):
            texto = generar(DATOS, {}, None, "m")
            self.assertNotIn("nuclei", texto.lower())


class TestCliNuclei(unittest.TestCase):
    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(cli, "escanear", return_value=XML).start()
        mock.patch.object(ollama, "comprobar_modelo", side_effect=ollama.ErrorOllama("caído")).start()
        mock.patch.object(pdf, "guardar_pdf").start()
        self.binario = mock.patch.object(nuclei, "binario", return_value="/usr/bin/nuclei").start()
        self.hallazgos = {"192.168.1.5": [{
            "id": "t", "nombre": "Vuln nuclei", "severidad": "alta", "puerto": 22, "coincidencia": "u",
            "tipo": "http", "descripcion": "d", "cves": ["CVE-2099-0007"], "cvss": 9.0, "detalles": [],
            "referencias": [], "extraidos": []}]}
        self.escanear_nuclei = mock.patch.object(nuclei, "escanear", return_value=self.hallazgos).start()
        self.verificar = mock.patch.object(nvd, "verificar_cves", return_value={}).start()

    def main(self, *args):
        argv = ["192.168.1.5", "--salida", str(self.dir / "informe.md"),
                "--env", str(self.dir / "no.env"), *args]
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()) as err:
            rc = cli.main(argv)
        return rc, err.getvalue()

    def informe(self):
        return (self.dir / "informe.md").read_text()

    def test_por_defecto_no_se_usa_nuclei(self):
        self.main("--sin-ia")
        self.escanear_nuclei.assert_not_called()
        self.assertNotIn("nuclei", self.informe().lower())

    def test_con_nuclei_aparece_en_el_informe_aunque_no_haya_ia(self):
        rc, err = self.main("--nuclei")
        self.assertEqual(rc, 0)
        self.assertTrue((self.dir / "informe.md").exists())  # sin IA pero con nuclei: hay informe
        self.assertFalse((self.dir / "informe.xml").exists())
        self.assertIn("Vuln nuclei", self.informe())
        self.assertIn("perfil `estandar`", self.informe())
        self.assertIn("1 hallazgo(s)", err)
        self.assertEqual(self.escanear_nuclei.call_args.args[1], "estandar")

    def test_perfil_nuclei(self):
        self.main("--nuclei", "--perfil-nuclei", "completo")
        self.assertEqual(self.escanear_nuclei.call_args.args[1], "completo")
        self.assertIn("perfil `completo`", self.informe())

    def test_los_cve_de_nuclei_se_verifican_en_nvd(self):
        self.main("--nuclei", "--verificar-cve")
        self.assertIn("CVE-2099-0007", self.verificar.call_args.args[0])

    def test_nuclei_ausente_falla_antes_de_escanear(self):
        self.binario.side_effect = nuclei.ErrorNuclei("nuclei no está instalado")
        rc, err = self.main("--nuclei")
        self.assertEqual(rc, 1)
        self.assertIn("nuclei no está instalado", err)
        cli.escanear.assert_not_called()

    def test_si_nuclei_falla_avisa_y_no_afirma_que_no_hay_vulnerabilidades(self):
        self.escanear_nuclei.side_effect = nuclei.ErrorNuclei("plantillas sin descargar")
        rc, err = self.main("--nuclei")
        self.assertEqual(rc, 0)
        self.assertIn("aviso: plantillas sin descargar", err)
        self.assertNotIn("Sin vulnerabilidades detectadas por nuclei", self.informe())
        self.assertNotIn("Vulnerabilidades detectadas por nuclei", self.informe())

    def test_timeout_de_nuclei_conserva_lo_encontrado_y_marca_el_informe_incompleto(self):
        self.escanear_nuclei.side_effect = nuclei.ErrorNuclei("tiempo límite", self.hallazgos)
        rc, err = self.main("--nuclei", "--timeout-nuclei", "5")
        self.assertEqual(rc, 0)
        self.assertEqual(self.escanear_nuclei.call_args.args[2], 5)
        self.assertIn("Vuln nuclei", self.informe())  # lo conseguido no se pierde
        self.assertIn("**INCOMPLETO**", self.informe())

    def test_timeout_por_defecto_una_hora(self):
        self.main("--nuclei")
        self.assertEqual(self.escanear_nuclei.call_args.args[2], 3600)

    def test_host_sin_hallazgos_de_nuclei_queda_con_lista_vacia(self):
        self.escanear_nuclei.return_value = {}
        self.main("--nuclei")
        self.assertIn("Sin vulnerabilidades detectadas por nuclei", self.informe())


if __name__ == "__main__":
    unittest.main()
