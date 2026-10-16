"""HTML report rendering."""

from __future__ import annotations

import datetime as dt

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__


def render_html(devices: list[dict], meta: dict | None = None) -> str:
    env = Environment(loader=PackageLoader("iotaudit", "templates"),
                      autoescape=select_autoescape(["html"]))
    tpl = env.get_template("report.html.j2")
    return tpl.render(devices=devices, meta=meta or {}, version=__version__,
                      generated=dt.datetime.now().strftime("%Y-%m-%d %H:%M"))
