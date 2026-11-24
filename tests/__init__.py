"""Red de seguridad: ningún test puede lanzar procesos reales (nmap, nuclei...).

Sin esto, un test que olvide simular la ejecución escanearía de verdad (por ejemplo la IP ficticia del
XML de prueba). Los tests que necesitan simular subprocess lo hacen con mock.patch encima de este bloqueo.

Se asigna directamente (no con mock.patch.start) porque varios tests llaman a mock.patch.stopall() en su
limpieza, y eso también desharía un patch iniciado aquí.
"""

import subprocess


def _proceso_real_prohibido(*args, **kwargs):
    raise AssertionError(f"un test intentó lanzar un proceso real: {args[0] if args else kwargs}")


subprocess.run = _proceso_real_prohibido
