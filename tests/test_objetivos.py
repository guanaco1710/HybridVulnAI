"""Política de objetivos: red local, IPs públicas y nombres de host (con y sin --permitir-externos)."""

import socket
import unittest

from escaner_ia import objetivos
from escaner_ia.objetivos import (ObjetivoNoPermitido, es_local, resolver_hostname, resolver_objetivos,
                                  validar_objetivo, validar_objetivos)


def dns(tabla):
    """Resolver falso: {nombre: [ips]}. Lo que no está en la tabla no resuelve."""
    def resolver(nombre, puerto, type=0):
        if nombre not in tabla:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, type, 0, "", (ip, 0)) for ip in tabla[nombre]]
    return resolver


class TestRedLocal(unittest.TestCase):
    def test_siempre_permitida_sin_flag(self):
        for t in ("192.168.1.1", "10.0.0.0/24", "172.16.5.0/24", "127.0.0.1", "::1", " 192.168.1.1 "):
            validar_objetivo(t)
        self.assertEqual(validar_objetivo("192.168.1.7"), "192.168.1.7")
        self.assertEqual(validar_objetivo("192.168.1.9/24"), "192.168.1.0/24")  # normaliza

    def test_el_flag_no_cambia_lo_local(self):
        self.assertEqual(validar_objetivo("10.0.0.0/16", permitir_externos=True), "10.0.0.0/16")

    def test_rango_local_demasiado_grande(self):
        with self.assertRaises(ObjetivoNoPermitido) as cm:
            validar_objetivo("10.0.0.0/8")
        self.assertIn("demasiado grande", str(cm.exception))

    def test_es_local(self):
        self.assertTrue(es_local("192.168.1.0/24"))
        self.assertTrue(es_local("::1"))
        self.assertFalse(es_local("8.8.8.8"))


class TestExternos(unittest.TestCase):
    def test_ip_publica_exige_el_flag(self):
        for ip in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:4860:4860::8888"):
            with self.assertRaises(ObjetivoNoPermitido, msg=ip) as cm:
                validar_objetivo(ip)
            self.assertIn("--permitir-externos", str(cm.exception))
            self.assertEqual(validar_objetivo(ip, permitir_externos=True), ip)

    def test_rango_publico_hasta_slash_24(self):
        self.assertEqual(validar_objetivo("8.8.8.0/24", permitir_externos=True), "8.8.8.0/24")
        for t in ("8.8.0.0/16", "8.8.8.0/23", "0.0.0.0/0", "2001:4860::/64"):
            with self.assertRaises(ObjetivoNoPermitido, msg=t):
                validar_objetivo(t, permitir_externos=True)

    def test_un_rango_no_puede_mezclar_local_y_publico(self):
        for t in ("10.0.0.0/7", "192.168.0.0/15"):  # incluyen 11.x y 192.169.x, públicas
            with self.assertRaises(ObjetivoNoPermitido, msg=t):
                validar_objetivo(t, permitir_externos=True)

    def test_nunca_se_escanea_lo_no_enrutable_ni_con_el_flag(self):
        for ip in ("169.254.169.254", "169.254.0.1", "100.64.0.1", "224.0.0.1", "0.0.0.0", "240.0.0.1",
                   "192.0.2.1", "198.51.100.5", "255.255.255.255", "fe80::1", "ff02::1", "ff0e::1", "169.254.1.0/24",
                   "64:ff9b::1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:127.0.0.1"):
            for flag in (False, True):
                with self.assertRaises(ObjetivoNoPermitido, msg=f"{ip} flag={flag}") as cm:
                    validar_objetivo(ip, permitir_externos=flag)
                self.assertIn("nunca", str(cm.exception))


class TestFormato(unittest.TestCase):
    MALOS = ("", "   ", "-sS", "--script=x", "-oN /tmp/x", "192.168.0.1-255", "8.8.8.8; ls", "192.168.1.1 && id",
             "1.2.3.4.5", "2130706433", "10.0.0.0/33", "ñandú.com", "a b.com", "bad_name.com", "-malo.com",
             "a..b.com", "x" * 64 + ".com", "$(id)", "example.com/24", "http://example.com")

    def test_se_rechazan_con_y_sin_flag(self):
        for texto in self.MALOS:
            for flag in (False, True):
                with self.assertRaises(ObjetivoNoPermitido, msg=f"{texto!r} flag={flag}"):
                    resolver_objetivos([texto], flag, dns({}))

    def test_un_valor_de_mas_basta_para_rechazarlo_todo(self):
        with self.assertRaises(ObjetivoNoPermitido):
            resolver_objetivos(["192.168.1.1", "-sS"], True, dns({}))

    def test_sin_objetivos(self):
        for funcion in (lambda: resolver_objetivos([]), lambda: validar_objetivos([])):
            with self.assertRaises(ObjetivoNoPermitido):
                funcion()


class TestHostnames(unittest.TestCase):
    def test_localhost_es_local_y_no_necesita_flag(self):
        objs, nombres = resolver_objetivos(["localhost"], False, dns({"localhost": ["127.0.0.1"]}))
        self.assertEqual((objs, nombres), (["127.0.0.1"], {"127.0.0.1": "localhost"}))

    def test_nombre_que_resuelve_a_publica_exige_el_flag(self):
        resolver = dns({"example.com": ["93.184.216.34"]})
        with self.assertRaises(ObjetivoNoPermitido) as cm:
            resolver_objetivos(["example.com"], False, resolver)
        self.assertIn("resuelve a una dirección no permitida", str(cm.exception))
        self.assertIn("--permitir-externos", str(cm.exception))
        objs, nombres = resolver_objetivos(["Example.COM"], True, resolver)
        # se escanea la IP resuelta, nunca el nombre
        self.assertEqual((objs, nombres), (["93.184.216.34"], {"93.184.216.34": "example.com"}))

    def test_cada_ip_resuelta_pasa_la_politica_ni_con_flag_se_cuela_lo_no_enrutable(self):
        """Protección contra DNS rebinding / SSRF: un nombre público que apunta a los metadatos cloud."""
        for ip in ("169.254.169.254", "100.64.0.1", "fe80::1%eth0", "224.0.0.1"):
            with self.assertRaises(ObjetivoNoPermitido, msg=ip) as cm:
                resolver_objetivos(["evil.example"], True, dns({"evil.example": ["8.8.8.8", ip]}))
            self.assertIn("evil.example", str(cm.exception))

    def test_varias_ips_locales_y_publicas(self):
        objs, nombres = resolver_objetivos(["multi.lab"], True, dns({"multi.lab": ["8.8.8.8", "192.168.1.5"]}))
        self.assertEqual(objs, ["192.168.1.5", "8.8.8.8"])
        self.assertEqual(set(nombres), {"8.8.8.8", "192.168.1.5"})

    def test_ipv6_con_scope_id(self):
        self.assertEqual(resolver_hostname("v6.lab", False, dns({"v6.lab": ["::1%lo"]})), ["::1"])

    def test_demasiadas_ips(self):
        ips = [f"8.8.8.{i}" for i in range(1, objetivos.MAX_IPS_POR_HOSTNAME + 2)]
        with self.assertRaises(ObjetivoNoPermitido) as cm:
            resolver_hostname("cdn.example", True, dns({"cdn.example": ips}))
        self.assertIn("indica las IPs concretas", str(cm.exception))

    def test_no_resuelve(self):
        with self.assertRaises(ObjetivoNoPermitido) as cm:
            resolver_objetivos(["no-existe.example"], True, dns({}))
        self.assertIn("no se pudo resolver", str(cm.exception))

    def test_sin_duplicados_y_se_conserva_el_primer_nombre(self):
        objs, nombres = resolver_objetivos(
            ["192.168.1.5", "a.lab", "b.lab", "192.168.1.5"], False,
            dns({"a.lab": ["192.168.1.5"], "b.lab": ["192.168.1.5", "192.168.1.6"]}))
        self.assertEqual(objs, ["192.168.1.5", "192.168.1.6"])
        self.assertEqual(nombres, {"192.168.1.5": "a.lab", "192.168.1.6": "b.lab"})

    def test_nombres_de_una_sola_etiqueta(self):
        objs, _ = resolver_objetivos(["router"], False, dns({"router": ["192.168.1.1"]}))
        self.assertEqual(objs, ["192.168.1.1"])


class TestRevalidacion(unittest.TestCase):
    def test_validar_objetivos_propaga_el_permiso(self):
        with self.assertRaises(ObjetivoNoPermitido):
            validar_objetivos(["192.168.1.1", "8.8.8.8"])
        self.assertEqual(validar_objetivos(["192.168.1.1", "8.8.8.8"], True), ["192.168.1.1", "8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
