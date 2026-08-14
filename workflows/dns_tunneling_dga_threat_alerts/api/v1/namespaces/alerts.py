"""
REST endpoints the alerts UI polls: computed tunneling/DGA alerts, storage stats, and the
detectors' editable threshold configuration.
"""
from flask import request
from flask_restx import Namespace, Resource

from ..services import detector, runtime_config, storage

alerts_ns = Namespace("alerts", description="Computed tunneling/DGA alerts")


@alerts_ns.route("")
class Alerts(Resource):
    """
    Accepts an optional `?window=<minutes>` to override both detectors' default lookback
    window (see /config for the separate tunneling/DGA defaults used otherwise).
    """

    def get(self):
        window_param = request.args.get("window")
        try:
            window_minutes = int(window_param) if window_param else None
        except ValueError:
            return {"error": "window must be an integer number of minutes"}, 400
        return {"alerts": detector.compute_alerts(window_minutes)}, 200


@alerts_ns.route("/stats")
class Stats(Resource):
    def get(self):
        return storage.storage_stats(), 200


@alerts_ns.route("/config")
class Config(Resource):
    """
    The detectors' threshold configuration - GET returns the effective values (defaults
    merged with any saved overrides), POST saves a partial update to one or both sections.
    """

    def get(self):
        return runtime_config.get_config(), 200

    def post(self):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "expected a JSON object"}, 400

        current = None
        try:
            for section in ("tunneling", "dga"):
                if section not in payload:
                    continue
                if not isinstance(payload[section], dict):
                    return {"error": "{} must be an object".format(section)}, 400
                current = runtime_config.update_config(section, payload[section])
        except ValueError as e:
            return {"error": str(e)}, 400

        return current or runtime_config.get_config(), 200


@alerts_ns.route("/config/reset")
class ConfigReset(Resource):
    """POST with `{"section": "tunneling"|"dga"}`, or an empty body to reset both sections."""

    def post(self):
        payload = request.get_json(silent=True) or {}
        section = payload.get("section")
        try:
            return runtime_config.reset_to_defaults(section), 200
        except ValueError as e:
            return {"error": str(e)}, 400
