"""Tests for graph_builder — AttackGraph, build_graph_from_session, find_all_attack_paths."""

import pytest

from graph_builder import AttackGraph, build_graph_from_session, find_all_attack_paths


# ── AttackGraph basics ────────────────────────────────────────────────


class TestAttackGraphConstruction:
    def test_add_node(self):
        g = AttackGraph("s1")
        g.add_node("sys-a", "system", name="Portal")
        assert "sys-a" in g.nodes
        assert g.nodes["sys-a"]["type"] == "system"
        assert g.nodes["sys-a"]["name"] == "Portal"

    def test_add_edge(self):
        g = AttackGraph("s1")
        g.add_node("a", "system")
        g.add_node("b", "system")
        g.add_edge("a", "b", label="lateral", confidence="confirmed")
        assert len(g.edges) == 1
        assert g.edges[0]["from"] == "a"
        assert g.edges[0]["to"] == "b"
        assert g.edges[0]["confidence"] == "confirmed"

    def test_to_dict_contains_required_keys(self):
        g = AttackGraph("s1")
        g.add_node("a", "system")
        d = g.to_dict()
        assert d["sessionId"] == "s1"
        assert "nodes" in d
        assert "edges" in d
        assert "entryPoints" in d
        assert "crownJewels" in d


# ── BFS pathfinding ──────────────────────────────────────────────────


class TestFindPaths:
    @staticmethod
    def _linear_graph() -> AttackGraph:
        """A -> B -> C"""
        g = AttackGraph("s1")
        for n in ("A", "B", "C"):
            g.add_node(n, "system")
        g.add_edge("A", "B", label="hop1", confidence="confirmed")
        g.add_edge("B", "C", label="hop2", confidence="confirmed")
        return g

    def test_simple_path(self):
        g = self._linear_graph()
        paths = g.find_paths("A", "C")
        assert paths == [["A", "B", "C"]]

    def test_no_path(self):
        g = self._linear_graph()
        paths = g.find_paths("C", "A")
        assert paths == []

    def test_cycle_avoidance(self):
        g = AttackGraph("s1")
        for n in ("A", "B", "C"):
            g.add_node(n, "system")
        g.add_edge("A", "B", label="1")
        g.add_edge("B", "C", label="2")
        g.add_edge("C", "A", label="3")
        paths = g.find_paths("A", "C")
        assert len(paths) == 1
        assert "A" not in paths[0][1:]

    def test_max_depth_cutoff(self):
        g = self._linear_graph()
        paths = g.find_paths("A", "C", max_depth=1)
        assert paths == []

    def test_max_depth_allows_exact_depth(self):
        g = self._linear_graph()
        paths = g.find_paths("A", "C", max_depth=2)
        assert paths == [["A", "B", "C"]]

    def test_min_confidence_filters_edges(self):
        g = AttackGraph("s1")
        for n in ("A", "B", "C"):
            g.add_node(n, "system")
        g.add_edge("A", "B", label="hop1", confidence="confirmed")
        g.add_edge("B", "C", label="hop2", confidence="hypothesis")
        paths = g.find_paths("A", "C", min_confidence="likely")
        assert paths == []

    def test_min_confidence_allows_matching(self):
        g = AttackGraph("s1")
        for n in ("A", "B", "C"):
            g.add_node(n, "system")
        g.add_edge("A", "B", label="hop1", confidence="confirmed")
        g.add_edge("B", "C", label="hop2", confidence="likely")
        paths = g.find_paths("A", "C", min_confidence="likely")
        assert paths == [["A", "B", "C"]]

    def test_multiple_paths(self):
        g = AttackGraph("s1")
        for n in ("A", "B", "C", "D"):
            g.add_node(n, "system")
        g.add_edge("A", "B", label="1")
        g.add_edge("B", "D", label="2")
        g.add_edge("A", "C", label="3")
        g.add_edge("C", "D", label="4")
        paths = g.find_paths("A", "D")
        assert len(paths) == 2
        path_sets = {tuple(p) for p in paths}
        assert ("A", "B", "D") in path_sets
        assert ("A", "C", "D") in path_sets


# ── Shortest path ────────────────────────────────────────────────────


class TestFindShortestPath:
    def test_shortest_of_two(self):
        g = AttackGraph("s1")
        for n in ("A", "B", "C", "D"):
            g.add_node(n, "system")
        g.add_edge("A", "D", label="direct")
        g.add_edge("A", "B", label="1")
        g.add_edge("B", "C", label="2")
        g.add_edge("C", "D", label="3")
        result = g.find_shortest_path("A", "D")
        assert result == ["A", "D"]

    def test_no_path_returns_none(self):
        g = AttackGraph("s1")
        g.add_node("A", "system")
        g.add_node("B", "system")
        assert g.find_shortest_path("A", "B") is None


# ── Entry points and crown jewels ────────────────────────────────────


class TestEntryPointsAndCrownJewels:
    def test_entry_points_are_sources_without_incoming_edges(self):
        g = AttackGraph("s1")
        g.add_node("ext", "system")
        g.add_node("int", "system")
        g.add_edge("ext", "int", label="exploit")
        assert g.get_entry_points() == ["ext"]

    def test_crown_jewels_by_risk_score(self):
        g = AttackGraph("s1")
        g.add_node("low", "system", riskScore=20)
        g.add_node("high", "system", riskScore=80)
        jewels = g.get_crown_jewels()
        assert "high" in jewels
        assert "low" not in jewels

    def test_crown_jewels_by_data_classification(self):
        g = AttackGraph("s1")
        g.add_node("db", "system", dataClassification="PII")
        g.add_node("cdn", "system")
        jewels = g.get_crown_jewels()
        assert "db" in jewels
        assert "cdn" not in jewels


# ── Path risk scoring ────────────────────────────────────────────────


class TestPathRisk:
    def test_risk_score_computation(self):
        g = AttackGraph("s1")
        g.add_node("A", "system")
        g.add_node("V", "vulnerability", severity="CRITICAL")
        g.add_node("B", "system")
        g.add_edge("A", "V", label="triggers", confidence="confirmed")
        g.add_edge("V", "B", label="exploits", confidence="confirmed")
        risk = g.path_risk(["A", "V", "B"])
        assert risk["length"] == 2
        assert risk["maxSeverity"] == 10
        assert risk["minConfidence"] == "confirmed"
        assert risk["riskScore"] == pytest.approx(10.0)

    def test_confidence_degrades_along_path(self):
        g = AttackGraph("s1")
        g.add_node("A", "system")
        g.add_node("B", "system")
        g.add_node("C", "system")
        g.add_edge("A", "B", label="1", confidence="confirmed")
        g.add_edge("B", "C", label="2", confidence="hypothesis")
        risk = g.path_risk(["A", "B", "C"])
        assert risk["minConfidence"] == "hypothesis"

    def test_empty_path_edge_case(self):
        g = AttackGraph("s1")
        g.add_node("A", "system")
        risk = g.path_risk(["A"])
        assert risk["length"] == 0
        assert risk["steps"] == []


# ── build_graph_from_session ─────────────────────────────────────────


class TestBuildGraphFromSession:
    @staticmethod
    def _minimal_session(events: list[dict] | None = None) -> dict:
        return {"_id": "sess-1", "events": events or []}

    def test_empty_session_produces_empty_graph(self):
        g = build_graph_from_session(self._minimal_session())
        assert len(g.nodes) == 0
        assert len(g.edges) == 0

    def test_request_events_create_system_nodes(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-hr", "systemName": "HR Portal", "url": "https://hr.corp.com/api/v1"}},
            {"type": "request", "data": {"systemId": "sys-hr", "systemName": "HR Portal", "url": "https://hr.corp.com/api/v2"}},
        ])
        g = build_graph_from_session(session)
        assert "sys-hr" in g.nodes
        assert g.nodes["sys-hr"]["type"] == "system"

    def test_finding_events_create_vulnerability_nodes(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-a", "systemName": "A", "url": "https://a.com"}},
            {"type": "finding", "data": {
                "id": "f1", "systemId": "sys-a", "title": "XSS in search",
                "severity": "HIGH", "cwe": "CWE-79", "confidence": "high", "status": "confirmed",
            }},
        ])
        g = build_graph_from_session(session)
        assert "vuln-f1" in g.nodes
        assert g.nodes["vuln-f1"]["type"] == "vulnerability"
        assert g.nodes["vuln-f1"]["severity"] == "HIGH"
        edge_labels = [e["label"] for e in g.edges]
        assert any("XSS in search" in l for l in edge_labels)

    def test_finding_updates_system_risk_score(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-a", "systemName": "A", "url": "https://a.com"}},
            {"type": "finding", "data": {
                "id": "f1", "systemId": "sys-a", "title": "SQLi",
                "severity": "CRITICAL", "status": "confirmed",
            }},
        ])
        g = build_graph_from_session(session)
        assert g.nodes["sys-a"]["riskScore"] == 10

    def test_token_reuse_pattern_creates_bidirectional_edges(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-a", "systemName": "A", "url": "https://a.com"}},
            {"type": "request", "data": {"systemId": "sys-b", "systemName": "B", "url": "https://b.com"}},
            {"type": "pattern", "data": {"title": "Cross-system token reuse detected"}},
        ])
        g = build_graph_from_session(session)
        edge_pairs = {(e["from"], e["to"]) for e in g.edges}
        assert ("sys-a", "sys-b") in edge_pairs
        assert ("sys-b", "sys-a") in edge_pairs

    def test_oauth_finding_creates_credential_node_and_sso_edges(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-idp", "systemName": "IDP", "url": "https://idp.com"}},
            {"type": "request", "data": {"systemId": "sys-app", "systemName": "App", "url": "https://app.com"}},
            {"type": "finding", "data": {
                "id": "f-oauth", "systemId": "sys-idp", "title": "OAuth misconfiguration (missing PKCE)",
                "severity": "HIGH", "status": "confirmed",
            }},
        ])
        g = build_graph_from_session(session)
        cred_id = "cred-oauth-sys-idp"
        assert cred_id in g.nodes
        assert g.nodes[cred_id]["type"] == "credential"
        sso_edges = [e for e in g.edges if e.get("label", "").startswith("may authenticate")]
        assert len(sso_edges) >= 1

    def test_idor_finding_creates_data_asset_node(self):
        session = self._minimal_session([
            {"type": "request", "data": {"systemId": "sys-hr", "systemName": "HR", "url": "https://hr.com"}},
            {"type": "finding", "data": {
                "id": "f-idor", "systemId": "sys-hr", "title": "IDOR in user profile endpoint",
                "severity": "HIGH", "status": "likely",
            }},
        ])
        g = build_graph_from_session(session)
        assert "data-sys-hr" in g.nodes
        assert g.nodes["data-sys-hr"]["type"] == "data_asset"


# ── find_all_attack_paths ────────────────────────────────────────────


class TestFindAllAttackPaths:
    def test_finds_paths_from_entries_to_jewels(self):
        g = AttackGraph("s1")
        g.add_node("ext", "system", riskScore=10)
        g.add_node("int", "system", riskScore=80, dataClassification="PII")
        g.add_edge("ext", "int", label="pivot", confidence="confirmed")
        paths = find_all_attack_paths(g)
        assert len(paths) >= 1
        assert paths[0]["source"] == "ext"
        assert paths[0]["target"] == "int"

    def test_fallback_when_no_entry_points(self):
        g = AttackGraph("s1")
        g.add_node("A", "system", riskScore=80)
        g.add_node("B", "system", riskScore=90)
        g.add_edge("A", "B", label="lateral")
        g.add_edge("B", "A", label="reverse")
        paths = find_all_attack_paths(g)
        assert len(paths) >= 1

    def test_empty_graph_returns_empty(self):
        g = AttackGraph("s1")
        assert find_all_attack_paths(g) == []

    def test_paths_sorted_by_risk_descending(self):
        g = AttackGraph("s1")
        g.add_node("ext", "system", riskScore=5)
        g.add_node("v-high", "vulnerability", severity="HIGH")
        g.add_node("v-low", "vulnerability", severity="LOW")
        g.add_node("jewel", "system", riskScore=90)
        g.add_edge("ext", "v-high", label="1", confidence="confirmed")
        g.add_edge("v-high", "jewel", label="2", confidence="confirmed")
        g.add_edge("ext", "v-low", label="3", confidence="confirmed")
        g.add_edge("v-low", "jewel", label="4", confidence="confirmed")
        paths = find_all_attack_paths(g)
        if len(paths) >= 2:
            assert paths[0]["riskScore"] >= paths[1]["riskScore"]
