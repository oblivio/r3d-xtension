"""
R3D Attack Graph Builder — Constructs lateral movement graphs from session data.

Builds a directed graph of systems, vulnerabilities, and credentials,
then finds attack paths between entry points and crown jewels.
"""

from __future__ import annotations
from collections import defaultdict, deque
from typing import Any


class AttackGraph:
    """Directed graph of systems, vulnerabilities, and credentials."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._adjacency: dict[str, list[dict]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, **kwargs) -> None:
        """Add a node (system, vulnerability, credential, data_asset)."""
        self.nodes[node_id] = {"id": node_id, "type": node_type, **kwargs}

    def add_edge(self, from_id: str, to_id: str, label: str, confidence: str = "hypothesis", **kwargs) -> None:
        """Add a directed edge between two nodes."""
        edge = {"from": from_id, "to": to_id, "label": label, "confidence": confidence, **kwargs}
        self.edges.append(edge)
        self._adjacency[from_id].append(edge)

    def find_paths(self, source: str, target: str, max_depth: int = 10, min_confidence: str | None = None) -> list[list[str]]:
        """BFS to find all paths from source to target up to max_depth.

        If min_confidence is set, only traverse edges with confidence >= that level.
        Confidence ordering: confirmed > likely > hypothesis.
        """
        CONF_ORDER = {"confirmed": 3, "likely": 2, "hypothesis": 1}
        min_conf_val = CONF_ORDER.get(min_confidence, 0) if min_confidence else 0

        paths = []
        queue = deque([(source, [source])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if current == target and len(path) > 1:
                paths.append(path)
                continue

            for edge in self._adjacency.get(current, []):
                edge_conf = CONF_ORDER.get(edge.get("confidence", "hypothesis"), 1)
                if edge_conf < min_conf_val:
                    continue
                next_node = edge["to"]
                if next_node not in path:
                    queue.append((next_node, path + [next_node]))

        return paths

    def find_shortest_path(self, source: str, target: str, min_confidence: str | None = None) -> list[str] | None:
        """BFS shortest path from source to target."""
        paths = self.find_paths(source, target, max_depth=20, min_confidence=min_confidence)
        return min(paths, key=len) if paths else None

    def get_entry_points(self) -> list[str]:
        """Nodes with no incoming edges — likely external-facing systems."""
        targets = {e["to"] for e in self.edges}
        sources = {e["from"] for e in self.edges}
        return [nid for nid in sources if nid not in targets and self.nodes.get(nid, {}).get("type") == "system"]

    def get_crown_jewels(self) -> list[str]:
        """High-risk systems with sensitive data or high risk scores."""
        return [
            nid for nid, node in self.nodes.items()
            if node.get("type") == "system" and (node.get("riskScore", 0) >= 70 or node.get("dataClassification"))
        ]

    def to_dict(self) -> dict:
        """Serialize the graph to a dict for MongoDB storage and API responses."""
        return {
            "sessionId": self.session_id,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "entryPoints": self.get_entry_points(),
            "crownJewels": self.get_crown_jewels(),
        }

    def path_risk(self, path: list[str]) -> dict:
        """Calculate cumulative risk and confidence for a path."""
        CONF_ORDER = {"confirmed": 3, "likely": 2, "hypothesis": 1}
        min_confidence = 3
        max_severity_score = 0
        SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}

        steps = []
        for i in range(len(path) - 1):
            from_id, to_id = path[i], path[i + 1]
            edge = next((e for e in self.edges if e["from"] == from_id and e["to"] == to_id), None)
            if edge:
                conf_val = CONF_ORDER.get(edge.get("confidence", "hypothesis"), 1)
                min_confidence = min(min_confidence, conf_val)
                steps.append(edge)
            node = self.nodes.get(to_id, {})
            if node.get("type") == "vulnerability":
                sev = SEVERITY_SCORE.get(node.get("severity", "LOW"), 2)
                max_severity_score = max(max_severity_score, sev)

        conf_labels = {3: "confirmed", 2: "likely", 1: "hypothesis"}
        return {
            "path": path,
            "steps": steps,
            "length": len(path) - 1,
            "minConfidence": conf_labels.get(min_confidence, "hypothesis"),
            "maxSeverity": max_severity_score,
            "riskScore": max_severity_score * (min_confidence / 3),
        }


def build_graph_from_session(session: dict) -> AttackGraph:
    """Build an attack graph from a full R3D session document (with events).

    Extracts systems, findings, tokens, and patterns from session events
    and constructs nodes + edges automatically.
    """
    graph = AttackGraph(session.get("_id") or session.get("id", "unknown"))

    systems: dict[str, dict] = {}
    findings: list[dict] = []
    tokens: list[dict] = []
    patterns: list[dict] = []

    for ev in session.get("events", []):
        ev_type = ev.get("type", "")
        data = ev.get("data", {})

        if ev_type == "request" and data.get("systemId"):
            sid = data["systemId"]
            if sid not in systems:
                systems[sid] = {"id": sid, "name": data.get("systemName", sid), "domains": set(), "riskScore": 0}
            url = data.get("url", "")
            try:
                from urllib.parse import urlparse as _urlparse
                host = _urlparse(url).hostname
                if host:
                    systems[sid]["domains"].add(host)
            except Exception:
                pass

        elif ev_type == "finding":
            findings.append(data)
            sid = data.get("systemId")
            if sid and sid in systems:
                SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}
                systems[sid]["riskScore"] = max(
                    systems[sid]["riskScore"],
                    SEVERITY_SCORE.get(data.get("severity", "LOW"), 2)
                )

        elif ev_type == "pattern":
            patterns.append(data)

    # Add system nodes
    for sid, sys in systems.items():
        sys_copy = {k: (list(v) if isinstance(v, set) else v) for k, v in sys.items()}
        graph.add_node(sid, "system", **sys_copy)

    # Add vulnerability nodes from findings
    for f in findings:
        fid = f.get("id") or f.get("findingId", "")
        if not fid:
            continue
        node_id = f"vuln-{fid}"
        graph.add_node(node_id, "vulnerability",
                       title=f.get("title", ""), severity=f.get("severity", "LOW"),
                       cwe=f.get("cwe", ""), confidence=f.get("confidence", "low"),
                       status=f.get("status", "hypothesis"))

        sys_id = f.get("systemId")
        if sys_id:
            conf = f.get("status", "hypothesis")
            if conf not in ("confirmed", "likely", "hypothesis"):
                conf = "hypothesis"
            graph.add_edge(node_id, sys_id, label=f"exploits: {f.get('title', '')[:50]}", confidence=conf)

    # Detect cross-system token reuse from patterns
    for p in patterns:
        title = p.get("title", "").lower()
        if "token reuse" in title or "cross-system" in title:
            sys_ids = [sid for sid in systems]
            for i in range(len(sys_ids)):
                for j in range(i + 1, len(sys_ids)):
                    graph.add_edge(sys_ids[i], sys_ids[j],
                                   label="shared auth / token reuse", confidence="likely")
                    graph.add_edge(sys_ids[j], sys_ids[i],
                                   label="shared auth / token reuse", confidence="likely")

    # Detect OAuth/SSO relationships from findings
    for f in findings:
        title = (f.get("title") or "").lower()
        if "oauth" in title or "oidc" in title or "sso" in title or "pkce" in title:
            sys_id = f.get("systemId")
            if sys_id:
                cred_id = f"cred-oauth-{sys_id}"
                graph.add_node(cred_id, "credential", kind="oauth", scope=sys_id)
                graph.add_edge(sys_id, cred_id, label="issues OAuth token", confidence="confirmed")
                for other_sid in systems:
                    if other_sid != sys_id:
                        graph.add_edge(cred_id, other_sid,
                                       label="may authenticate via SSO", confidence="hypothesis")

    # Detect IDOR chains — systems with IDOR findings can pivot to user data
    idor_systems = set()
    for f in findings:
        title = (f.get("title") or "").lower()
        if "idor" in title or "user enum" in title or "horizontal priv" in title:
            sid = f.get("systemId")
            if sid:
                idor_systems.add(sid)
                data_id = f"data-{sid}"
                graph.add_node(data_id, "data_asset", name=f"User data on {systems.get(sid, {}).get('name', sid)}")
                graph.add_edge(sid, data_id, label="IDOR exposes user data",
                               confidence=f.get("status", "hypothesis"))

    return graph


def find_all_attack_paths(graph: AttackGraph, max_depth: int = 8, min_confidence: str | None = None) -> list[dict]:
    """Find attack paths from all entry points to all crown jewels."""
    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()

    if not entry_points:
        entry_points = [nid for nid, n in graph.nodes.items() if n.get("type") == "system"]
    if not crown_jewels:
        scored = [(nid, n.get("riskScore", 0)) for nid, n in graph.nodes.items() if n.get("type") == "system"]
        scored.sort(key=lambda x: x[1], reverse=True)
        crown_jewels = [nid for nid, _ in scored[:3]]

    all_paths = []
    for entry in entry_points:
        for jewel in crown_jewels:
            if entry == jewel:
                continue
            paths = graph.find_paths(entry, jewel, max_depth=max_depth, min_confidence=min_confidence)
            for p in paths:
                risk = graph.path_risk(p)
                risk["source"] = entry
                risk["target"] = jewel
                risk["sourceName"] = graph.nodes.get(entry, {}).get("name", entry)
                risk["targetName"] = graph.nodes.get(jewel, {}).get("name", jewel)
                all_paths.append(risk)

    all_paths.sort(key=lambda x: (-x["riskScore"], x["length"]))
    return all_paths
