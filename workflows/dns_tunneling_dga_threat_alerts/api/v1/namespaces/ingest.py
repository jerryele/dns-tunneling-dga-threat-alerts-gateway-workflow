"""
Ingest endpoint for BDDS's "HTTP" DNS Activity Logging destination, plus the admin-facing
token/health/config-URL helpers needed to wire that destination up in BAM.
"""
from flask import g, request
from flask_restx import Namespace, Resource

from ..services import auth, storage
from ..services.parser import extract_record, iter_json_objects

ingest_ns = Namespace("ingest", description="DNS Activity ingest from BDDS")


@ingest_ns.route("")
class Ingest(Resource):
    """
    POST target for BAM's DNS Activity Logging "HTTP" destination. Body is one or more
    dnstap-derived JSON events (see services/parser.py for the exact shapes tolerated) -
    not wrapped in a Splunk-HEC-style envelope, since this is BAM's generic HTTP destination
    type, not its separate Splunk HEC destination type.
    """

    def post(self):
        if not auth.check_request(request):
            return {"error": "unauthorized"}, 401

        raw_text = request.get_data(as_text=True)
        accepted, skipped = [], 0
        for event in iter_json_objects(raw_text):
            record = extract_record(event)
            if record is None:
                skipped += 1
                continue
            accepted.append(record)

        storage.append_records(accepted)
        return {"accepted": len(accepted), "skipped": skipped}, 200


@ingest_ns.route("/health")
class Health(Resource):
    """Unauthenticated - matches BAM's optional 'Healthcheck URI' probe, reveals no data."""

    def get(self):
        return {"status": "ok"}, 200


@ingest_ns.route("/token")
class Token(Resource):
    """
    Reveals the ingest token - requires an active Gateway session (`g.user`), unlike this
    workflow's other API routes. On some Gateway installs, flask_restx API blueprints aren't
    permission-gated the way page routes are, so this route enforces its own session check
    since it specifically returns a secret.
    """

    def get(self):
        if not getattr(g, "user", None):
            return {"error": "unauthorized"}, 401
        token = auth.get_or_create_token()
        return {
            "token": token,
            "ingest_path": "/dns_tunneling_dga_threat_alerts/v1/ingest",
            "ingest_query": "?token=" + token,
        }, 200
