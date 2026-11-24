import contextlib
import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from escaner_ia import __main__ as cli
from escaner_ia import ollama, pdf, proveedores
from escaner_ia.informe import generar_informe_html
from escaner_ia.ollama import clasificar_origen
from escaner_ia.parser import parsear_xml
from tests.test_escaner_ia import XML
from tests.test_modulos import RespuestaFalsa, error_http

RESPUESTA_RED = '{"hosts": [{"ip": "192.168.1.5", "resumen": "ok", "hallazgos": [{"puerto": 22, "titulo": "SSH", "cves": ["CVE-2099-0001"]}]}]}'
RESPUESTA = '{"resumen": "ok", "hallazgos": [{"puerto": 22, "titulo": "SSH", "cves": ["CVE-2099-0001"]}]}'


class TestDetectar(unittest.TestCase):
    def test_sin_clave(self):
        self.assertIsNone(proveedores.detectar(env={}))
        self.assertIsNone(proveedores.detectar(env={"API_KEY_IA": ""}))

    def test_deduce_por_prefijo(self):
        for clave, prov in (("sk-ant-x", "anthropic"), ("sk-proj-x", "openai"), ("AIzaX", "gemini"), ("gsk_x", "groq")):
            self.assertEqual(proveedores.detectar(env={"API_KEY_IA": clave}), (prov, clave))

    def test_proveedor_explicito_gana_al_prefijo(self):
        self.assertEqual(proveedores.detectar(env={"API_KEY_IA": "sk-ant-x", "PROVEEDOR_IA": "OpenAI"}),
                         ("openai", "sk-ant-x"))
        self.assertEqual(proveedores.detectar("gemini", {"API_KEY_IA": "k", "PROVEEDOR_IA": "openai"}),
                         ("gemini", "k"))

    def test_no_deducible_o_invalido(self):
        for env in ({"API_KEY_IA": "xyz"}, {"API_KEY_IA": "k", "PROVEEDOR_IA": "otro"}):
            with self.assertRaises(proveedores.ErrorOnline):
                proveedores.detectar(env=env)


class TestEnvFile(unittest.TestCase):
    def test_lee_comentarios_comillas_y_export(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / ".env"
            f.write_text('# c\n\nAPI_KEY_IA="abc"\nexport PROVEEDOR_IA = openai\nvacia=\nsin_igual\n')
            self.assertEqual(proveedores.leer_env(f),
                             {"API_KEY_IA": "abc", "PROVEEDOR_IA": "openai", "vacia": ""})

    def test_no_existe(self):
        self.assertEqual(proveedores.leer_env(Path("/no/existe/.env")), {})

    def test_cli_env_tiene_prioridad_sobre_entorno(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / ".env"
            f.write_text("API_KEY_IA=del_env\nPROVEEDOR_IA=openai\n")
            args = mock.Mock(env=str(f))
            with mock.patch.dict(os.environ, {"API_KEY_IA": "del_entorno"}, clear=True):
                self.assertEqual(proveedores.detectar(env=cli.cargar_env(args)), ("openai", "del_env"))


class TestRespuesta(unittest.TestCase):
    def test_json_con_texto_y_vallas(self):
        self.assertEqual(proveedores._extraer_json("```json\n{\"a\": 1}\n```"), {"a": 1})

    def test_json_invalido(self):
        with self.assertRaises(proveedores.ErrorOnline):
            proveedores._extraer_json("no hay json")

    def test_normaliza_campos_omitidos(self):
        datos = parsear_xml(XML)
        llamadas = []

        def falsa(modelo, clave, sistema, usuario, timeout):
            llamadas.append(usuario)
            return RESPUESTA_RED

        with mock.patch.dict(proveedores._LLAMADAS, {"openai": falsa}):
            r = proveedores.analizar_red(XML, datos["hosts"], "openai", "m", "k")
        self.assertEqual(len(llamadas), 1)
        h = r["192.168.1.5"]["hallazgos"][0]
        self.assertEqual(h["severidad"], "info")
        self.assertEqual(h["cves"], [{"id": "CVE-2099-0001", "origen": "ia"}])

    def test_ip_desconocida_se_ignora(self):
        resp = '{"hosts": [{"ip": "10.9.9.9", "resumen": "x", "hallazgos": []}]}'
        with mock.patch.dict(proveedores._LLAMADAS, {"openai": lambda *a: resp}):
            self.assertEqual(proveedores.analizar_red(XML, parsear_xml(XML)["hosts"], "openai", "m", "k"), {})

    def test_fallo_devuelve_vacio_y_avisa(self):
        def falla(*a):
            raise proveedores.ErrorOnline("429 cuota")
        with mock.patch.dict(proveedores._LLAMADAS, {"groq": falla}), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(proveedores.analizar_red(XML, parsear_xml(XML)["hosts"], "groq", "m", "k"), {})


class TestXmlPodado(unittest.TestCase):
    def test_solo_hosts_y_puertos_abiertos(self):
        hosts = proveedores.hosts_podados(XML)
        self.assertEqual([ip for ip, _ in hosts], ["192.168.1.5"])
        self.assertIn('portid="22"', hosts[0][1])
        self.assertNotIn('portid="80"', hosts[0][1])  # puerto cerrado

    def test_recorta_salida_de_scripts(self):
        largo = XML.replace('output="cpe:', 'output="' + "x" * 5000 + 'cpe:')
        self.assertLess(len(proveedores.hosts_podados(largo)[0][1]), 3000)

    def test_lotes_respetan_el_limite(self):
        hosts = [(f"10.0.0.{i}", "x" * 10000) for i in range(5)]
        lotes = proveedores._lotes(hosts)
        self.assertEqual([len(l) for l in lotes], [2, 2, 1])


class TestPeticiones(unittest.TestCase):
    def llamar(self, prov, respuesta):
        with mock.patch.object(proveedores, "_peticion", return_value=respuesta) as p:
            texto = proveedores._LLAMADAS[prov]("modelo", "CLAVE", "sis", "usu", 5)
        return texto, p.call_args.args

    def test_anthropic(self):
        texto, (_, url, cab, cuerpo, _) = self.llamar("anthropic", {"content": [{"text": "{}"}]})
        self.assertEqual(texto, "{}")
        self.assertEqual(cab["x-api-key"], "CLAVE")
        self.assertEqual(cuerpo["system"], "sis")

    def test_openai(self):
        texto, (_, url, cab, cuerpo, _) = self.llamar("openai", {"choices": [{"message": {"content": "{}"}}]})
        self.assertEqual(cab["Authorization"], "Bearer CLAVE")
        self.assertEqual(cuerpo["response_format"], {"type": "json_object"})

    def test_groq_usa_api_compatible_con_openai(self):
        texto, (prov, url, cab, cuerpo, _) = self.llamar("groq", {"choices": [{"message": {"content": "{}"}}]})
        self.assertEqual(prov, "groq")
        self.assertTrue(url.startswith("https://api.groq.com/openai/v1/"))
        self.assertEqual(cab["Authorization"], "Bearer CLAVE")

    def test_gemini_clave_en_cabecera_no_en_url(self):
        texto, (_, url, cab, cuerpo, _) = self.llamar(
            "gemini", {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]})
        self.assertEqual(cab["x-goog-api-key"], "CLAVE")
        self.assertNotIn("CLAVE", url)


class TestDeteccionSinEnv(unittest.TestCase):
    def test_sin_argumento_mezcla_entorno_y_env(self):
        with mock.patch.dict(os.environ, {"API_KEY_IA": "sk-del_entorno"}, clear=True), \
                mock.patch.object(proveedores, "leer_env", return_value={"PROVEEDOR_IA": "gemini"}):
            self.assertEqual(proveedores.detectar(), ("gemini", "sk-del_entorno"))


class TestPeticionHttp(unittest.TestCase):
    def peticion(self):
        return proveedores._peticion("groq", "https://x", {"X-Test": "1"}, {"a": 1}, 5)

    def test_ok_envia_user_propio_y_cabeceras(self):
        with mock.patch.object(proveedores.urllib.request, "urlopen",
                               return_value=RespuestaFalsa({"ok": True})) as uo:
            self.assertEqual(self.peticion(), {"ok": True})
        req = uo.call_args.args[0]
        self.assertEqual(req.headers["User-agent"], "hybridVulnAI/1.0")
        self.assertEqual(req.headers["X-test"], "1")

    def test_http_error_incluye_proveedor_y_codigo(self):
        with mock.patch.object(proveedores.urllib.request, "urlopen", side_effect=error_http(self, 429, b"cuota")):
            with self.assertRaises(proveedores.ErrorOnline) as cm:
                self.peticion()
        self.assertIn("groq respondió 429: cuota", str(cm.exception))

    def test_reintenta_los_errores_temporales_con_espera(self):
        respuestas = [error_http(self, 503), error_http(self, 504), RespuestaFalsa({"ok": True})]
        with mock.patch.object(proveedores.urllib.request, "urlopen", side_effect=respuestas) as uo, \
                mock.patch.object(proveedores.time, "sleep") as sleep:
            self.assertEqual(self.peticion(), {"ok": True})
        self.assertEqual(uo.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [2, 5])

    def test_si_el_503_persiste_se_rinde_tras_los_reintentos(self):
        respuestas = [error_http(self, 503) for _ in range(3)]
        with mock.patch.object(proveedores.urllib.request, "urlopen", side_effect=respuestas) as uo, \
                mock.patch.object(proveedores.time, "sleep"):
            with self.assertRaises(proveedores.ErrorOnline) as cm:
                self.peticion()
        self.assertEqual(uo.call_count, 3)  # 1 intento + 2 reintentos
        self.assertIn("503", str(cm.exception))

    def test_cuota_y_errores_permanentes_no_se_reintentan(self):
        for codigo in (400, 401, 404, 429, 500):
            with mock.patch.object(proveedores.urllib.request, "urlopen",
                                   side_effect=error_http(self, codigo)) as uo, \
                    mock.patch.object(proveedores.time, "sleep") as sleep:
                with self.assertRaises(proveedores.ErrorOnline):
                    self.peticion()
            self.assertEqual(uo.call_count, 1, msg=codigo)
            sleep.assert_not_called()

    def test_sin_conexion(self):
        for fallo in (urllib.error.URLError("x"), TimeoutError()):
            with mock.patch.object(proveedores.urllib.request, "urlopen", side_effect=fallo):
                with self.assertRaises(proveedores.ErrorOnline):
                    self.peticion()


class TestXmlPodadoCasos(unittest.TestCase):
    XML_RUIDO = """<nmaprun>
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><extraports state="closed" count="99"/>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>
<script id="s" output="salida"><elem key="k">v</elem><table key="t"/></script></port>
<port protocol="tcp" portid="23"/></ports><times srtt="1"/><distance value="1"/></host>
<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>"""

    def test_poda_ruido_hijos_de_scripts_y_hosts_sin_puertos_abiertos(self):
        hosts = proveedores.hosts_podados(self.XML_RUIDO)
        self.assertEqual([ip for ip, _ in hosts], ["10.0.0.1"])  # 10.0.0.2 y .3 no tienen puertos abiertos
        texto = hosts[0][1]
        for ruido in ("extraports", "times", "distance", "<elem", "<table", 'portid="23"'):
            self.assertNotIn(ruido, texto)
        self.assertIn('output="salida"', texto)

    def test_ip_desconocida_si_no_hay_direccion(self):
        xml = XML.replace('<address addr="192.168.1.5" addrtype="ipv4"/>', "")
        self.assertEqual(proveedores.hosts_podados(xml)[0][0], "desconocida")


class TestAnalizarRedFallos(unittest.TestCase):
    def analizar(self, llamada):
        with mock.patch.dict(proveedores._LLAMADAS, {"openai": llamada}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            r = proveedores.analizar_red(XML, parsear_xml(XML)["hosts"], "openai", "m", "k")
        return r, err.getvalue()

    def test_respuesta_con_estructura_inesperada(self):
        for excepcion in (KeyError("candidates"), IndexError(), TypeError()):
            def llamada(*a, _e=excepcion):
                raise _e
            r, err = self.analizar(llamada)
            self.assertEqual(r, {})
            self.assertIn("respuesta inesperada de openai", err)

    def test_entradas_de_host_que_no_son_objetos_se_ignoran(self):
        r, _ = self.analizar(lambda *a: '{"hosts": ["texto", {"sin_ip": 1}]}')
        self.assertEqual(r, {})

    def test_fallo_en_un_lote_corta_los_siguientes(self):
        llamadas = []

        def llamada(*a):
            llamadas.append(1)
            raise proveedores.ErrorOnline("429")
        with mock.patch.object(proveedores, "MAX_CHARS_LOTE", 1), \
                mock.patch.dict(proveedores._LLAMADAS, {"openai": llamada}), \
                contextlib.redirect_stderr(io.StringIO()):
            xml2 = XML.replace("</nmaprun>", XML.split("<nmaprun")[1].split("<host>")[1]
                               .split("</host>")[0].join(["<host>", "</host>"])
                               .replace("192.168.1.5", "192.168.1.6") + "</nmaprun>")
            hosts = parsear_xml(xml2)["hosts"]
            self.assertGreaterEqual(len(hosts), 2)
            proveedores.analizar_red(xml2, hosts, "openai", "m", "k")
        self.assertEqual(len(llamadas), 1)  # no se insiste con el segundo lote


class TestPdf(unittest.TestCase):
    def datos(self):
        d = parsear_xml(XML)
        a = {"192.168.1.5": clasificar_origen({"resumen": "<b>r</b>", "hallazgos": [{
            "puerto": 22, "tipo": "cve", "titulo": "<script>x</script>", "severidad": "alta",
            "cves": ["CVE-2023-38408"], "descripcion": "d", "recomendacion": "r"}]}, d["hosts"][0])}
        return d, a

    def test_html_escapa_el_contenido_de_la_ia(self):
        html = generar_informe_html(*self.datos(), None, "m")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_pdf_valido(self):
        try:
            import weasyprint  # noqa: F401
        except (ImportError, OSError):
            self.skipTest("WeasyPrint no disponible")
        with tempfile.TemporaryDirectory() as d_:
            ruta = Path(d_) / "i.pdf"
            pdf.guardar_pdf(generar_informe_html(*self.datos(), None, "m"), ruta)
            self.assertTrue(ruta.read_bytes().startswith(b"%PDF-"))

    def test_sin_weasyprint_avisa_y_no_rompe(self):
        with mock.patch.dict("sys.modules", {"weasyprint": None}):
            with self.assertRaises(pdf.ErrorPDF):
                pdf.guardar_pdf("<p>x</p>", Path("/tmp/no.pdf"))


class TestCadenaDeRespaldo(unittest.TestCase):
    """online -> Ollama -> solo XML."""

    def ejecutar(self, env, ollama_ok, online_ok=True):
        def comprobar(*a):
            if not ollama_ok:
                raise ollama.ErrorOllama("caído")

        def online(*a, **k):
            if not online_ok:
                return {}
            return {"192.168.1.5": {"resumen": "online", "hallazgos": []}}

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "escanear", return_value=XML), \
                mock.patch.object(ollama, "comprobar_modelo", side_effect=comprobar), \
                mock.patch.object(ollama, "analizar_host",
                                  return_value={"resumen": "local", "hallazgos": []}), \
                mock.patch.object(proveedores, "analizar_red", side_effect=online), \
                contextlib.redirect_stderr(io.StringIO()):
            salida = Path(d) / "informe.md"
            rc = cli.main(["192.168.1.5", "--salida", str(salida), "--env", str(Path(d) / ".env"), "--sin-nuclei"])
            return rc, salida.exists(), salida.with_suffix(".xml").exists(), \
                salida.read_text() if salida.exists() else ""

    def test_con_clave_usa_online(self):
        rc, informe, xml, md = self.ejecutar({"API_KEY_IA": "sk-ant-k"}, ollama_ok=True)
        self.assertEqual((rc, informe, xml), (0, True, False))
        self.assertIn("anthropic:", md)
        self.assertNotIn("ollama:", md)

    def test_sin_clave_usa_ollama(self):
        rc, informe, xml, md = self.ejecutar({}, ollama_ok=True)
        self.assertEqual((rc, informe, xml), (0, True, False))
        self.assertIn("ollama:llama3.1:8b", md)

    def test_online_falla_cae_a_ollama(self):
        rc, informe, _, md = self.ejecutar({"API_KEY_IA": "sk-k"}, ollama_ok=True, online_ok=False)
        self.assertIn("ollama:", md)

    def test_sin_nada_solo_xml(self):
        rc, informe, xml, _ = self.ejecutar({}, ollama_ok=False)
        self.assertEqual((rc, informe, xml), (0, False, True))


if __name__ == "__main__":
    unittest.main()
