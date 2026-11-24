"""Tests del informe (Markdown y HTML) y de la orquestación del CLI."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from escaner_ia import __main__ as cli
from escaner_ia import nvd, objetivos, ollama, pdf, proveedores
from escaner_ia.escaner import ErrorEscaneo
from escaner_ia.informe import generar_informe, generar_informe_html
from tests.test_escaner_ia import XML


def puerto(n, servicio="ssh", producto="OpenSSH", version="8.2", cves=()):
    return {"puerto": n, "protocolo": "tcp", "servicio": servicio, "producto": producto,
            "version": version, "cves_nmap": [{"id": c, "cvss": 9.8} for c in cves]}


def hallazgo(titulo, severidad="alta", p=22, cves=()):
    return {"puerto": p, "tipo": "cve", "titulo": titulo, "severidad": severidad, "cves": list(cves),
            "descripcion": f"desc {titulo}", "recomendacion": f"rec {titulo}"}


DATOS = {"comando": "nmap -sV", "hosts": [
    {"ip": "10.0.0.1", "nombres": ["router.local"], "so": [{"nombre": "Linux 5.x", "precision": 95}],
     "puertos": [puerto(22, cves=["CVE-2023-38408"]), puerto(80, servicio="", producto="", version="")]},
    {"ip": "10.0.0.2", "nombres": [], "so": [], "puertos": []},
    {"ip": "10.0.0.3", "nombres": [], "so": [], "puertos": [puerto(21, "ftp", "vsftpd", "2.3.4")]},
    {"ip": "10.0.0.4", "nombres": [], "so": [], "puertos": [puerto(443, "https")]},
]}
ANALISIS = {
    "10.0.0.1": {"resumen": "Resumen uno", "hallazgos": [
        hallazgo("Baja cosa", "baja", 0),
        hallazgo("SSH vulnerable", "alta", 22,
                 [{"id": "CVE-2023-38408", "origen": "nmap"}, {"id": "CVE-2099-0001", "origen": "ia"}]),
        hallazgo("Gravedad rara", "inventada", 80)]},
    "10.0.0.4": {"resumen": "Sin nada", "hallazgos": []},
}
VERIFICACION = {"CVE-2023-38408": {"estado": "EXISTE", "detalle": "d"}}


class TestInforme(unittest.TestCase):
    def comprobar_comun(self, texto):
        for esperado in ("10.0.0.1", "router.local", "Linux 5.x", "95%", "Sin puertos abiertos detectados",
                         "No se pudo analizar este host", "Resumen uno", "Sin hallazgos",
                         "SSH vulnerable", "CVE-2023-38408 (origen: nmap, NVD: EXISTE)",
                         "CVE-2099-0001 (origen: ia)", "rec SSH vulnerable", "vsftpd 2.3.4", "hybridVuln AI"):
            self.assertIn(esperado, texto)
        self.assertNotIn("CVE-2099-0001 (origen: ia, NVD", texto)  # sin verificación no se inventa estado

    def test_markdown(self):
        md = generar_informe(DATOS, ANALISIS, VERIFICACION, "m")
        self.comprobar_comun(md)
        self.assertIn("(puerto 22, cve)", md)
        self.assertIn("(host, cve)", md)  # puerto 0 = hallazgo del host completo
        # orden por severidad: alta antes que baja; una severidad desconocida va al final
        self.assertLess(md.index("[ALTA]"), md.index("[BAJA]"))
        self.assertLess(md.index("[BAJA]"), md.index("[INVENTADA]"))

    def test_markdown_sin_verificacion(self):
        md = generar_informe(DATOS, ANALISIS, None, "m")
        self.assertNotIn("NVD:", md)

    def test_html(self):
        html = generar_informe_html(DATOS, ANALISIS, VERIFICACION, "m")
        self.comprobar_comun(html)
        self.assertIn("sev-alta", html)
        self.assertIn("sev-info", html)  # una severidad desconocida se pinta como "info"
        self.assertNotIn("sev-inventada", html)  # y nunca se inyecta en el atributo class

    def test_html_sin_verificacion(self):
        self.assertNotIn("NVD:", generar_informe_html(DATOS, ANALISIS, None, "m"))


class TestCli(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.addCleanup(mock.patch.stopall)
        self.escanear = mock.patch.object(cli, "escanear", return_value=XML).start()
        self.comprobar = mock.patch.object(ollama, "comprobar_modelo").start()
        self.analizar_host = mock.patch.object(
            ollama, "analizar_host", return_value={"resumen": "r", "hallazgos": []}).start()
        self.analizar_red = mock.patch.object(proveedores, "analizar_red", return_value={}).start()
        self.verificar = mock.patch.object(
            nvd, "verificar_cves", return_value={"CVE-2099-0001": {"estado": "EXISTE"}}).start()
        self.guardar_pdf = mock.patch.object(pdf, "guardar_pdf").start()

    def main(self, *args, env=None, objetivo="192.168.1.5"):
        """Ejecuta cli.main sin tocar el .env real ni el entorno. Devuelve (código, stderr).

        Nuclei va activo por defecto: aquí se desactiva (los tests de nuclei están en test_nuclei.py).
        """
        argv = [objetivo, "--salida", str(self.dir / "informe.md"),
                "--env", str(self.dir / "no-existe.env"), "--sin-nuclei", *args]
        with mock.patch.dict(os.environ, env or {}, clear=True), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = cli.main(argv)
        return rc, err.getvalue()

    def informe(self) -> str:
        return (self.dir / "informe.md").read_text()

    def test_objetivo_publico_se_rechaza_sin_el_flag(self):
        rc, err = self.main(objetivo="8.8.8.8")
        self.assertEqual(rc, 1)
        self.assertIn("Error:", err)
        self.assertIn("--permitir-externos", err)
        self.escanear.assert_not_called()

    def test_ip_publica_con_el_flag_avisa_y_llega_a_nmap(self):
        rc, err = self.main("--sin-ia", "--permitir-externos", objetivo="8.8.8.8")
        self.assertEqual(rc, 0)
        self.assertIn("fuera de la red local: asegúrate de tener autorización", err)
        self.assertEqual(self.escanear.call_args.args[0], ["8.8.8.8"])
        self.assertTrue(self.escanear.call_args.kwargs["permitir_externos"])

    def test_la_red_local_no_avisa_ni_necesita_el_flag(self):
        rc, err = self.main("--sin-ia")
        self.assertEqual(rc, 0)
        self.assertNotIn("autorización", err)
        self.assertFalse(self.escanear.call_args.kwargs["permitir_externos"])

    def test_nombre_de_host_se_resuelve_y_se_escanea_la_ip_no_el_nombre(self):
        falso = lambda nombre, puerto, type=0: [(2, type, 0, "", ("192.168.1.5", 0))]  # noqa: E731
        with mock.patch.object(objetivos.socket, "getaddrinfo", side_effect=falso):
            rc, _ = self.main("--sin-ia", objetivo="Router.Lab")
        self.assertEqual(rc, 0)
        self.assertEqual(self.escanear.call_args.args[0], ["192.168.1.5"])  # nunca el nombre
        self.assertIn("## Host 192.168.1.5 (router.lab)", self.informe())

    def test_nombre_que_resuelve_a_ip_publica_exige_el_flag(self):
        falso = lambda nombre, puerto, type=0: [(2, type, 0, "", ("93.184.216.34", 0))]  # noqa: E731
        with mock.patch.object(objetivos.socket, "getaddrinfo", side_effect=falso):
            rc, err = self.main("--sin-ia", objetivo="example.com")
        self.assertEqual(rc, 1)
        self.assertIn("--permitir-externos", err)
        self.escanear.assert_not_called()

    def test_error_de_nmap(self):
        self.escanear.side_effect = ErrorEscaneo("boom")
        rc, err = self.main("--sin-ia")
        self.assertEqual(rc, 1)
        self.assertIn("boom", err)

    def test_sin_ia_no_llama_a_ninguna_ia_pero_genera_informe_y_pdf(self):
        rc, _ = self.main("--sin-ia")
        self.assertEqual(rc, 0)
        self.comprobar.assert_not_called()
        self.analizar_host.assert_not_called()
        self.analizar_red.assert_not_called()
        self.guardar_pdf.assert_called_once()
        self.assertEqual(self.guardar_pdf.call_args.args[1], self.dir / "informe.pdf")
        self.assertIn("Modelo de IA: `ninguno`", self.informe())

    def test_sin_pdf(self):
        self.main("--sin-ia", "--sin-pdf")
        self.guardar_pdf.assert_not_called()

    def test_fallo_del_pdf_solo_avisa(self):
        self.guardar_pdf.side_effect = pdf.ErrorPDF("sin weasyprint")
        rc, err = self.main("--sin-ia")
        self.assertEqual(rc, 0)
        self.assertIn("aviso: sin weasyprint", err)
        self.assertTrue((self.dir / "informe.md").exists())  # el Markdown se conserva

    def test_guardar_xml_explicito(self):
        ruta = self.dir / "bruto.xml"
        self.main("--sin-ia", "--guardar-xml", str(ruta))
        self.assertEqual(ruta.read_text(), XML)

    def test_sin_ia_ni_ollama_solo_guarda_el_xml(self):
        self.comprobar.side_effect = ollama.ErrorOllama("caído")
        rc, err = self.main()
        self.assertEqual(rc, 0)
        self.assertEqual((self.dir / "informe.xml").read_text(), XML)
        self.assertFalse((self.dir / "informe.md").exists())
        self.assertIn("Ollama no disponible", err)
        self.guardar_pdf.assert_not_called()

    def test_ollama_analiza_host_a_host(self):
        rc, _ = self.main()
        self.assertEqual(rc, 0)
        self.analizar_host.assert_called_once()
        self.assertIn("ollama:llama3.1:8b", self.informe())

    def test_ia_online_tiene_prioridad_y_respeta_modelo_del_env(self):
        self.analizar_red.return_value = {"192.168.1.5": {"resumen": "online", "hallazgos": []}}
        self.main(env={"API_KEY_IA": "sk-ant-k"})
        self.analizar_host.assert_not_called()
        self.assertIn("anthropic:claude-haiku-5-5", self.informe())

    def test_modelo_online_por_env_y_por_cli(self):
        self.analizar_red.return_value = {"192.168.1.5": {"resumen": "online", "hallazgos": []}}
        (self.dir / "e.env").write_text("API_KEY_IA=sk-k\nMODELO_IA=del-env\n")
        argv = ["--env", str(self.dir / "e.env")]
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["192.168.1.5", "--salida", str(self.dir / "informe.md"), "--sin-nuclei", *argv])
        self.assertIn("openai:del-env", self.informe())
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["192.168.1.5", "--salida", str(self.dir / "informe.md"), "--sin-nuclei", *argv,
                      "--modelo-online", "del-cli"])
        self.assertIn("openai:del-cli", self.informe())

    def test_si_la_online_no_devuelve_nada_cae_a_ollama(self):
        self.main(env={"API_KEY_IA": "sk-k"})
        self.analizar_red.assert_called_once()
        self.analizar_host.assert_called_once()
        self.assertIn("ollama:", self.informe())

    def test_clave_sin_proveedor_deducible_avisa_y_usa_ollama(self):
        rc, err = self.main(env={"API_KEY_IA": "xyz"})
        self.assertEqual(rc, 0)
        self.assertIn("IA online no disponible", err)
        self.analizar_red.assert_not_called()
        self.analizar_host.assert_called_once()

    def test_error_de_ollama_en_un_host_deja_el_informe_sin_analisis(self):
        self.analizar_host.side_effect = ollama.ErrorOllama("modelo roto")
        rc, err = self.main()
        self.assertEqual(rc, 0)
        self.assertIn("aviso: modelo roto", err)
        self.assertIn("No se pudo analizar este host", self.informe())

    def test_hosts_sin_puertos_abiertos_no_se_analizan(self):
        self.escanear.return_value = XML.replace('state="open"', 'state="closed"')
        self.main()
        self.analizar_host.assert_not_called()

    def test_verificar_cve_envia_los_ids_de_nmap_y_de_la_ia(self):
        self.analizar_host.return_value = {"resumen": "r", "hallazgos": [{
            "puerto": 22, "tipo": "cve", "titulo": "t", "severidad": "alta",
            "cves": [{"id": "CVE-2099-0001", "origen": "ia"}], "descripcion": "d", "recomendacion": "r"}]}
        self.main("--verificar-cve")
        self.assertEqual(self.verificar.call_args.args[0], {"CVE-2023-38408", "CVE-2099-0001"})
        self.assertIn("NVD: EXISTE", self.informe())

    def test_verificar_cve_sin_cves_no_consulta_nvd(self):
        import re
        self.escanear.return_value = re.sub(r"<script.*?/>", "", XML, flags=re.S)
        self.main("--verificar-cve")
        self.verificar.assert_not_called()


if __name__ == "__main__":
    unittest.main()
