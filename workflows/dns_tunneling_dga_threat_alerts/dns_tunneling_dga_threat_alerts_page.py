import os

from flask import send_from_directory
from main_app import app

from bluecat import route
from bluecat.gateway.decorators import page_exc_handler, require_permission


@route(app, "/dns_tunneling_dga_threat_alerts/page")
@page_exc_handler(default_message="Failed to load DNS Tunneling/DGA Threat Alerts workflow.")
@require_permission("dns_tunneling_dga_threat_alerts_page")
def dns_tunneling_dga_threat_alerts_page():
    return send_from_directory(os.path.dirname(os.path.abspath(str(__file__))), "dnsTunnelingDgaThreatAlertsPage/index.html")
