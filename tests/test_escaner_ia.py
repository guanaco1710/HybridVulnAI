import unittest

from escaner_ia.escaner import construir_comando
from escaner_ia.informe import generar_informe
from escaner_ia.objetivos import ObjetivoNoPermitido, validar_objetivo
from escaner_ia.ollama import clasificar_origen
from escaner_ia.parser import parsear_xml

XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.5" startstr="hoy" version="7.9">
<host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.2p1"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe></service>
<script id="vulners" output="cpe:/a:openbsd:openssh:8.2p1:&#10;  CVE-2023-38408  9.8  https://vulners.com/x"/>
</port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
</nmaprun>"""


class TestObjetivos(unittest.TestCase):
    def test_permitidos(self):
        for t in ("192.168.1.1", "10.0.0.0/24", "172.16.5.0/24", "127.0.0.1", "::1"):
            validar_objetivo(t)

    def test_rechazados(self):
        for t in ("8.8.8.8", "0.0.0.0/0", "192.168.0.1-255", "-sS", "--script=x", "",
                  "scanme.nmap.org", "169.254.1.1", "172.32.0.1", "10.0.0.0/7", "192.168.1.1; ls"):
            with self.assertRaises(ObjetivoNoPermitido, msg=t):
                validar_objetivo(t)

    def test_comando_usa_doble_guion(self):
        cmd = construir_comando(["192.168.1.0/24"], "rapido")
        self.assertEqual(cmd[-2:], ["--", "192.168.1.0/24"])


class TestParser(unittest.TestCase):
    def test_parseo(self):
        d = parsear_xml(XML)
        self.assertEqual(len(d["hosts"]), 1)
        p = d["hosts"][0]["puertos"]
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["producto"], "OpenSSH")
        self.assertEqual(p[0]["cves_nmap"], [{"id": "CVE-2023-38408", "cvss": 9.8}])

    def test_origen_cve(self):
        host = parsear_xml(XML)["hosts"][0]
        a = {"hallazgos": [{"cves": ["cve-2023-38408", "CVE-2099-0001", "basura"]}]}
        r = clasificar_origen(a, host)["hallazgos"][0]["cves"]
        self.assertEqual(r, [{"id": "CVE-2023-38408", "origen": "nmap"},
                             {"id": "CVE-2099-0001", "origen": "ia"}])

    def test_informe(self):
        d = parsear_xml(XML)
        a = {"192.168.1.5": clasificar_origen({"resumen": "ok", "hallazgos": [{
            "puerto": 22, "tipo": "cve", "titulo": "SSH", "severidad": "alta",
            "cves": ["CVE-2023-38408"], "descripcion": "d", "recomendacion": "r"}]}, d["hosts"][0])}
        md = generar_informe(d, a, None, "m")
        self.assertIn("origen: nmap", md)
        self.assertIn("[ALTA] SSH", md)


if __name__ == "__main__":
    unittest.main()
