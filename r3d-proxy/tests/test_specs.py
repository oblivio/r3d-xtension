"""Tests for routers/specs — OpenAPI parsing and endpoint extraction."""

import json

import pytest
import yaml

from routers.specs import _extract_endpoints, _parse_openapi_spec


# ── _parse_openapi_spec ──────────────────────────────────────────────


class TestParseSpec:
    def test_parse_json(self):
        raw = json.dumps({"openapi": "3.0.0", "paths": {}})
        result = _parse_openapi_spec(raw, "json")
        assert result["openapi"] == "3.0.0"

    def test_parse_yaml(self):
        raw = yaml.dump({"openapi": "3.0.0", "paths": {}})
        result = _parse_openapi_spec(raw, "yaml")
        assert result["openapi"] == "3.0.0"

    def test_parse_yml_alias(self):
        raw = yaml.dump({"swagger": "2.0"})
        result = _parse_openapi_spec(raw, "yml")
        assert result["swagger"] == "2.0"

    def test_rejects_malformed_json(self):
        with pytest.raises(Exception):
            _parse_openapi_spec("{not valid", "json")


# ── _extract_endpoints ───────────────────────────────────────────────


def _spec(paths, **kwargs):
    return {"paths": paths, **kwargs}


class TestExtractEndpoints:
    def test_basic_extraction(self):
        spec = _spec({"/api/users": {"get": {"summary": "List users"}}})
        eps = _extract_endpoints(spec)
        assert len(eps) == 1
        assert eps[0]["path"] == "/api/users"
        assert eps[0]["method"] == "GET"
        assert eps[0]["summary"] == "List users"

    def test_multiple_methods(self):
        spec = _spec({"/items": {
            "get": {"summary": "List"},
            "post": {"summary": "Create"},
        }})
        eps = _extract_endpoints(spec)
        methods = {e["method"] for e in eps}
        assert methods == {"GET", "POST"}

    def test_ignores_non_http_methods(self):
        spec = _spec({"/api": {
            "get": {"summary": "OK"},
            "parameters": [{"name": "x"}],
        }})
        eps = _extract_endpoints(spec)
        assert len(eps) == 1

    def test_base_path_prefix(self):
        spec = _spec({"/users": {"get": {}}}, basePath="/v2")
        eps = _extract_endpoints(spec)
        assert eps[0]["path"] == "/v2/users"

    def test_parameters_extracted(self):
        spec = _spec({"/search": {"get": {
            "parameters": [
                {"name": "q", "in": "query", "required": True, "type": "string"},
                {"name": "limit", "in": "query", "required": False, "type": "integer"},
            ],
        }}})
        eps = _extract_endpoints(spec)
        params = eps[0]["parameters"]
        assert len(params) == 2
        assert params[0]["name"] == "q"
        assert params[0]["required"] is True

    def test_request_body_schema(self):
        spec = _spec({"/users": {"post": {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                    }
                }
            },
        }}})
        eps = _extract_endpoints(spec)
        assert eps[0]["bodySchema"]["type"] == "object"

    # ── Sensitive flags ──────────────────────────────────────────────

    def test_ssrf_candidate_flag(self):
        spec = _spec({"/proxy": {"get": {
            "parameters": [{"name": "url", "in": "query"}],
        }}})
        eps = _extract_endpoints(spec)
        assert "ssrf_candidate" in eps[0]["sensitiveFlags"]

    def test_open_redirect_candidate_flag(self):
        spec = _spec({"/login": {"get": {
            "parameters": [{"name": "redirect_uri", "in": "query"}],
        }}})
        eps = _extract_endpoints(spec)
        assert "open_redirect_candidate" in eps[0]["sensitiveFlags"]
        assert "ssrf_candidate" in eps[0]["sensitiveFlags"]

    def test_idor_candidate_flag(self):
        spec = _spec({"/users/{id}/profile": {"get": {}}})
        eps = _extract_endpoints(spec)
        assert "idor_candidate" in eps[0]["sensitiveFlags"]

    def test_sensitive_data_flag(self):
        spec = _spec({"/auth": {"post": {
            "parameters": [{"name": "password", "in": "body"}],
        }}})
        eps = _extract_endpoints(spec)
        assert "sensitive_data" in eps[0]["sensitiveFlags"]

    def test_no_sensitive_flags_for_clean_endpoint(self):
        spec = _spec({"/health": {"get": {}}})
        eps = _extract_endpoints(spec)
        assert eps[0]["sensitiveFlags"] == []

    # ── Auth detection ───────────────────────────────────────────────

    def test_auth_required_from_operation_security(self):
        spec = _spec({"/secret": {"get": {
            "security": [{"bearerAuth": []}],
        }}})
        eps = _extract_endpoints(spec)
        assert eps[0]["authRequired"] is True

    def test_auth_required_from_spec_level_security(self):
        spec = _spec({"/data": {"get": {}}}, security=[{"apiKey": []}])
        eps = _extract_endpoints(spec)
        assert eps[0]["authRequired"] is True

    def test_no_auth_when_no_security(self):
        spec = _spec({"/public": {"get": {}}})
        eps = _extract_endpoints(spec)
        assert eps[0]["authRequired"] is False
