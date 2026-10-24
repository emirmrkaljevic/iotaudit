"""Write a PDF from an iotaudit HTML report.

The renderer ships in the optional ``pdf`` extra (xhtml2pdf, pure Python).
It is imported only when a PDF is requested, so a normal install stays small.
"""

from __future__ import annotations

import logging
from pathlib import Path

PDF_INSTALL_HINT = 'PDF export needs the optional extra: pip install "iotaudit[pdf]"'

_QUIET_LOGGERS = ("xhtml2pdf", "xhtml2pdf.parser", "reportlab", "reportlab.pdfbase")


class PdfExtraMissing(RuntimeError):
    """PDF export was requested and the optional extra is not installed."""


def write_pdf(html: str, dest: str | Path) -> None:
    """Render ``html`` to ``dest``. Raise PdfExtraMissing when xhtml2pdf is absent."""
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:
        raise PdfExtraMissing(PDF_INSTALL_HINT) from exc

    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    loggers = [logging.getLogger(name) for name in _QUIET_LOGGERS]
    previous = [(lg, lg.level) for lg in loggers]
    for lg, _level in previous:
        lg.setLevel(logging.ERROR)
    status = None
    try:
        with path.open("wb") as fh:
            status = pisa.CreatePDF(html, dest=fh, encoding="utf-8")
    except Exception as exc:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"PDF render failed: {exc}") from exc
    finally:
        for lg, level in previous:
            lg.setLevel(level)
    if getattr(status, "err", 0):
        path.unlink(missing_ok=True)
        raise RuntimeError("PDF render failed")
