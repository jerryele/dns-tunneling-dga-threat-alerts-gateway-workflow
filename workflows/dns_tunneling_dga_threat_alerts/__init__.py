"""
DNS Tunneling/DGA Threat Alerts workflow initialization.

Single workflow package providing both the navigable UI page (via `sub_pages`, type="ui")
and the flask_restx REST API for BDDS DNS Activity ingest + computed tunneling/DGA alerts.
"""
from typing import Final

from flask import Blueprint
from flask_restx import Api
from main_app import app

type: str = "ui"  # noqa: A001
sub_pages: list[dict[str, str]] = [
    {
        "name": "dns_tunneling_dga_threat_alerts_page",
        "title": "DNS Tunneling/DGA Threat Alerts",
        "endpoint": "dns_tunneling_dga_threat_alerts/page",
        "description": "Tunneling/DGA alerting from BDDS DNS Activity logs",
    },
]

API_VERSION: Final[str] = "1.0"
API_PREFIX: Final[str] = "/dns_tunneling_dga_threat_alerts/v1"

api_endpoints: Blueprint = Blueprint(
    "dns_tunneling_dga_threat_alerts_api",
    "dns_tunneling_dga_threat_alerts_api",
)

dns_tunneling_dga_threat_alerts_api: Api = Api(
    api_endpoints,
    version=API_VERSION,
    title="DNS Tunneling/DGA Threat Alerts API",
    description="REST API for DNS Activity ingest and tunneling/DGA alerts",
    doc="/doc",
    default_label="DNS Tunneling/DGA Threat Alerts",
    validate=True,
)

app.register_blueprint(api_endpoints, url_prefix=API_PREFIX)

from .api import v1

for namespace in v1.namespaces:
    dns_tunneling_dga_threat_alerts_api.add_namespace(namespace)
