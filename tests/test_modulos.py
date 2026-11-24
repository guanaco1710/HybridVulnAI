"""Tests de escaner, nvd, ollama, objetivos y pdf. Sin red ni nmap reales: todo se simula."""

import io
import json
import subprocess
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from escaner_ia import escaner, nvd, objetivos, ollama, pdf
from escaner_ia.parser import parsear_xml
from tests.test_escaner_ia import XML


class RespuestaFalsa:
    """Imita la respuesta de urlopen (context manager con read())."""

    def __init__(self, cuerpo):
        self._cuerpo = cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo).encode()

    def read(self, *a):
        return self._cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def error_http(caso, codigo=500, cuerpo=b"detalle"):
    e = urllib.error.HTTPError("http://x", codigo, "err", {}, io.BytesIO(cuerpo))
    caso.addCleanup(e.close)
    return e


class TestObjetivosVacios(unittest.TestCase):
    def test_sin_objetivos(self):
        with self.assertRaises(objetivos.ObjetivoNoPermitido):
            objetivos.validar_objetivos([])


class TestEscaner(unittest.TestCase):
    def test_una_ip_publica_solo_llega_a_nmap_con_el_permiso(self):
        with mock.patch.object(escaner.shutil, "which", return_value="/usr/bin/nmap"):
            with self.assertRaises(objetivos.ObjetivoNoPermitido):
                escaner.construir_comando(["8.8.8.8"], "rapido")
            cmd = escaner.construir_comando(["8.8.8.8"], "rapido", permitir_externos=True)
        self.assertEqual(cmd[-2:], ["--", "8.8.8.8"])

    def test_escanear_propaga_el_permiso(self):
        with mock.patch.object(escaner.shutil, "which", return_value="/usr/bin/nmap"), \
                mock.patch.object(escaner.subprocess, "run",
                                  return_value=mock.Mock(returncode=0, stdout="<x/>", stderr="")) as run:
            escaner.escanear(["8.8.8.8"], "rapido", permitir_externos=True)
        self.assertEqual(run.call_args.args[0][-1], "8.8.8.8")

    def test_perfil_desconocido(self):
        with self.assertRaises(escaner.ErrorEscaneo):
            escaner.construir_comando(["192.168.1.1"], "inventado")

    def test_sin_nmap(self):
        with mock.patch.object(escaner.shutil, "which", return_value=None):
            with self.assertRaises(escaner.ErrorEscaneo):
                escaner.construir_comando(["192.168.1.1"], "rapido")

    def test_detectar_so_anade_O(self):
        with mock.patch.object(escaner.shutil, "which", return_value="/usr/bin/nmap"):
            cmd = escaner.construir_comando(["192.168.1.1"], "rapido", detectar_so=True)
        self.assertIn("-O", cmd)
        self.assertEqual(cmd[0], "/usr/bin/nmap")

    def test_so_requiere_root(self):
        with mock.patch.object(escaner.os, "geteuid", return_value=1000):
            with self.assertRaises(escaner.ErrorEscaneo) as cm:
                escaner.escanear(["192.168.1.1"], "rapido", detectar_so=True)
        self.assertIn("root", str(cm.exception))

    def ejecutar(self, **resultado):
        with mock.patch.object(escaner.shutil, "which", return_value="/usr/bin/nmap"), \
                mock.patch.object(escaner.subprocess, "run", **resultado) as run:
            return escaner.escanear(["192.168.1.1"], "rapido"), run

    def test_escanear_devuelve_el_xml_sin_shell(self):
        salida, run = self.ejecutar(return_value=mock.Mock(returncode=0, stdout="<xml/>", stderr=""))
        self.assertEqual(salida, "<xml/>")
        argumentos = run.call_args
        self.assertIsInstance(argumentos.args[0], list)  # lista de argumentos, nunca un string
        self.assertFalse(argumentos.kwargs.get("shell", False))

    def test_timeout(self):
        with self.assertRaises(escaner.ErrorEscaneo) as cm:
            self.ejecutar(side_effect=subprocess.TimeoutExpired("nmap", 1))
        self.assertIn("tiempo límite", str(cm.exception))

    def test_codigo_de_salida_distinto_de_cero(self):
        with self.assertRaises(escaner.ErrorEscaneo) as cm:
            self.ejecutar(return_value=mock.Mock(returncode=2, stdout="", stderr=" boom \n"))
        self.assertIn("código 2: boom", str(cm.exception))


class TestNvd(unittest.TestCase):
    def consultar(self, respuestas, env=None, ids=("CVE-2023-0001",)):
        with mock.patch.object(nvd.urllib.request, "urlopen", side_effect=respuestas) as uo, \
                mock.patch.object(nvd.time, "sleep") as sleep:
            return nvd.verificar_cves(set(ids), env if env is not None else {}), uo, sleep

    def test_existe(self):
        datos = {"vulnerabilities": [{"cve": {"descriptions": [
            {"lang": "es", "value": "hola"}, {"lang": "en", "value": "Buffer overflow"}]}}]}
        r, _, _ = self.consultar([RespuestaFalsa(datos)])
        self.assertEqual(r["CVE-2023-0001"], {"estado": "EXISTE", "detalle": "Buffer overflow"})

    def test_existe_sin_descripcion_en_ingles(self):
        r, _, _ = self.consultar([RespuestaFalsa({"vulnerabilities": [{"cve": {}}]})])
        self.assertEqual(r["CVE-2023-0001"], {"estado": "EXISTE", "detalle": ""})

    def test_no_encontrado(self):
        r, _, _ = self.consultar([RespuestaFalsa({"vulnerabilities": []})])
        self.assertEqual(r["CVE-2023-0001"]["estado"], "NO ENCONTRADO")

    def test_errores_de_red_y_json(self):
        for fallo in (urllib.error.URLError("sin red"), TimeoutError("lento"),
                      RespuestaFalsa(b"no es json")):
            r, _, _ = self.consultar([fallo])
            self.assertEqual(r["CVE-2023-0001"]["estado"], "NO VERIFICABLE", msg=repr(fallo))

    def test_sin_clave_espera_6_5_s_entre_consultas(self):
        vacia = RespuestaFalsa({"vulnerabilities": []})
        _, uo, sleep = self.consultar([vacia, vacia], ids=("CVE-2023-0001", "CVE-2023-0002"))
        sleep.assert_called_once_with(6.5)
        req = uo.call_args.args[0]
        self.assertNotIn("Apikey", req.headers)  # urllib capitaliza: "Apikey"

    def test_con_clave_va_en_cabecera_y_espera_menos(self):
        vacia = RespuestaFalsa({"vulnerabilities": []})
        _, uo, sleep = self.consultar([vacia, vacia], env={"NVD_API_KEY": "secreta"},
                                      ids=("CVE-2023-0001", "CVE-2023-0002"))
        sleep.assert_called_once_with(0.7)
        req = uo.call_args.args[0]
        self.assertEqual(req.headers["Apikey"], "secreta")
        self.assertNotIn("secreta", req.full_url)  # la clave nunca va en la URL

    def test_sin_env_usa_el_entorno_del_proceso(self):
        with mock.patch.dict(nvd.os.environ, {"NVD_API_KEY": "del_proceso"}), \
                mock.patch.object(nvd.urllib.request, "urlopen",
                                  return_value=RespuestaFalsa({"vulnerabilities": []})) as uo:
            nvd.verificar_cves({"CVE-2023-0001"})
        self.assertEqual(uo.call_args.args[0].headers["Apikey"], "del_proceso")


class TestOllama(unittest.TestCase):
    def host(self):
        return parsear_xml(XML)["hosts"][0]

    def test_mensaje_usuario_recorta_scripts_largos(self):
        host = self.host()
        host["puertos"][0]["scripts"] = [{"id": "x", "salida": "a" * 5000}]
        self.assertLess(len(ollama.mensaje_usuario(host)), 4000)

    def test_peticion_ok(self):
        with mock.patch.object(ollama.urllib.request, "urlopen", return_value=RespuestaFalsa({"a": 1})):
            self.assertEqual(ollama._peticion("http://x", {}, 5), {"a": 1})

    def test_peticion_http_error(self):
        with mock.patch.object(ollama.urllib.request, "urlopen", side_effect=error_http(self, 500)):
            with self.assertRaises(ollama.ErrorOllama) as cm:
                ollama._peticion("http://x", {}, 5)
        self.assertIn("500", str(cm.exception))

    def test_peticion_sin_conexion(self):
        for fallo in (urllib.error.URLError("rechazada"), TimeoutError()):
            with mock.patch.object(ollama.urllib.request, "urlopen", side_effect=fallo):
                with self.assertRaises(ollama.ErrorOllama) as cm:
                    ollama._peticion("http://x", {}, 5)
            self.assertIn("ollama serve", str(cm.exception))

    def test_analizar_host(self):
        contenido = json.dumps({"resumen": "ok", "hallazgos": [{"cves": ["CVE-2099-0001"]}]})
        with mock.patch.object(ollama, "_peticion", return_value={"message": {"content": contenido}}) as p:
            r = ollama.analizar_host(self.host(), "m", "http://h:1/")
        self.assertEqual(p.call_args.args[0], "http://h:1/api/chat")
        self.assertEqual(r["hallazgos"][0]["cves"], [{"id": "CVE-2099-0001", "origen": "ia"}])

    def test_analizar_host_json_invalido(self):
        for respuesta in ({"message": {"content": "no json"}}, {}):
            with mock.patch.object(ollama, "_peticion", return_value=respuesta):
                with self.assertRaises(ollama.ErrorOllama):
                    ollama.analizar_host(self.host(), "m")

    def comprobar(self, modelos, modelo="llama3.1:8b"):
        cuerpo = {"models": [{"name": n} for n in modelos]}
        with mock.patch.object(ollama.urllib.request, "urlopen", return_value=RespuestaFalsa(cuerpo)):
            ollama.comprobar_modelo(modelo)

    def test_comprobar_modelo_presente(self):
        self.comprobar(["llama3.1:8b"])
        self.comprobar(["mistral:latest"], modelo="mistral")  # sin etiqueta == :latest

    def test_comprobar_modelo_ausente(self):
        with self.assertRaises(ollama.ErrorOllama) as cm:
            self.comprobar(["otro:1b"])
        self.assertIn("ollama pull", str(cm.exception))
        with self.assertRaises(ollama.ErrorOllama) as cm:
            self.comprobar([])
        self.assertIn("ninguno", str(cm.exception))

    def test_comprobar_modelo_sin_servidor(self):
        with mock.patch.object(ollama.urllib.request, "urlopen", side_effect=urllib.error.URLError("x")):
            with self.assertRaises(ollama.ErrorOllama):
                ollama.comprobar_modelo("m")


class TestPdfErrores(unittest.TestCase):
    def test_fallo_al_maquetar(self):
        weasy = mock.Mock()
        weasy.HTML.return_value.write_pdf.side_effect = ValueError("css roto")
        with mock.patch.dict("sys.modules", {"weasyprint": weasy}):
            with self.assertRaises(pdf.ErrorPDF) as cm:
                pdf.guardar_pdf("<p>x</p>", Path("/tmp/no.pdf"))
        self.assertIn("css roto", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
