"""Conversión del informe HTML a PDF con WeasyPrint (dependencia opcional)."""

from pathlib import Path


class ErrorPDF(RuntimeError):
    pass


def guardar_pdf(html: str, ruta: Path) -> None:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as e:  # OSError: faltan librerías del sistema (pango)
        raise ErrorPDF(f"WeasyPrint no está disponible ({e}). Instálalo con: sudo apt install python3-weasyprint") from None
    try:
        HTML(string=html).write_pdf(str(ruta))
    except Exception as e:  # WeasyPrint puede fallar de muchas formas al maquetar
        raise ErrorPDF(f"no se pudo generar el PDF: {e}") from None
