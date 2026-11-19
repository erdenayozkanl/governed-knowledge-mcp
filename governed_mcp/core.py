"""Deterministic, policy-enforced tools behind a governed knowledge MCP."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256


DOCUMENTS = [
    {"id": "runbook-profile", "tenant": "acme", "classification": "internal", "title": "Profile Service runbook", "text": "Profile Service is owned by Platform Team. Check dependency health before rollback."},
    {"id": "privacy-standard", "tenant": "acme", "classification": "internal", "title": "Privacy handling standard", "text": "Customer data access needs an approved purpose and a traceable audit event."},
    {"id": "customer-schema", "tenant": "acme", "classification": "confidential", "title": "Customer dataset schema", "text": "CustomerDataset contains confidential profile attributes."},
]

NODES = {
    "PlatformTeam": {"type": "Team", "tenant": "acme", "classification": "internal"},
    "ProfileService": {"type": "Service", "tenant": "acme", "classification": "internal"},
    "CustomerDataset": {"type": "Dataset", "tenant": "acme", "classification": "confidential"},
    "PrivacyPolicy": {"type": "Policy", "tenant": "acme", "classification": "internal"},
}
EDGES = [
    ("PlatformTeam", "OWNS", "ProfileService"),
    ("ProfileService", "CONSUMES", "CustomerDataset"),
    ("PrivacyPolicy", "GOVERNS", "CustomerDataset"),
]
RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(frozen=True)
class Caller:
    subject: str
    roles: frozenset[str]
    tenant: str
    clearance: str
    model_tier: str


def caller(subject: str, roles: list[str], tenant: str, clearance: str, model_tier: str) -> Caller:
    if clearance not in RANK or model_tier not in {"approved", "unapproved"}:
        raise ValueError("invalid clearance or model_tier")
    return Caller(subject, frozenset(roles), tenant, clearance, model_tier)


def _allowed(principal: Caller, item: dict, *, predicate: str | None = None) -> tuple[bool, str]:
    if item.get("tenant") != principal.tenant:
        return False, "tenant_mismatch"
    if predicate == "CONSUMES" and not ({"analyst", "platform-admin"} & principal.roles):
        return False, "relationship_denied"
    if RANK[item.get("classification", "internal")] > RANK[principal.clearance]:
        return False, "clearance_denied"
    if item.get("classification") in {"confidential", "restricted"} and principal.model_tier != "approved":
        return False, "model_tier_denied"
    if item.get("type") == "Dataset" and not ({"analyst", "platform-admin"} & principal.roles):
        return False, "rbac_node_type_denied"
    return True, "allowed"


def search_knowledge_base(query: str, principal: Caller) -> dict:
    terms = set(query.casefold().split())
    results, audit = [], []
    for document in DOCUMENTS:
        allowed, reason = _allowed(principal, document)
        audit.append({"resource": document["id"], "allowed": allowed, "reason": reason})
        score = len(terms & set((document["title"] + " " + document["text"]).casefold().split()))
        if allowed and score:
            results.append({"id": document["id"], "title": document["title"], "excerpt": document["text"], "score": score})
    return {"results": sorted(results, key=lambda result: result["score"], reverse=True), "audit": audit, "context_boundary": "Only results are eligible for LLM context."}


def traverse_authorized_graph(question: str, principal: Caller, max_hops: int = 2) -> dict:
    terms = set(question.casefold().replace("?", "").split())
    seeds = [node for node in NODES if any(term in node.casefold() for term in terms)]
    visible, audit = [], []
    frontier = set(seeds)
    seen = set()
    for _ in range(max_hops):
        next_frontier = set()
        for source, predicate, target in EDGES:
            if source not in frontier and target not in frontier:
                continue
            candidate = target if source in frontier else source
            allowed, reason = _allowed(principal, NODES[candidate], predicate=predicate)
            audit.append({"node": candidate, "predicate": predicate, "allowed": allowed, "reason": reason})
            if allowed:
                visible.append({"subject": source, "predicate": predicate, "object": target})
                next_frontier.add(candidate)
        seen |= frontier
        frontier = next_frontier - seen
    return {"seeds": seeds, "facts": visible, "audit": audit, "context_boundary": "Only facts with allowed=true may be passed to an LLM."}


def investigate_incident(service: str, question: str, principal: Caller) -> dict:
    graph = traverse_authorized_graph(f"{service} {question}", principal)
    kb = search_knowledge_base(f"{service} {question}", principal)
    trace_id = sha256(f"{principal.subject}:{service}:{question}".encode()).hexdigest()[:16]
    return {"trace_id": trace_id, "workflow": ["authorized_graph_retrieval", "authorized_knowledge_search", "grounded_synthesis"], "graph_facts": graph["facts"], "documents": kb["results"], "answer": "Investigation context assembled from authorized evidence only.", "audit": graph["audit"] + kb["audit"]}


def evaluate_retrieval(principal: Caller) -> dict:
    cases = [("Profile Service runbook", "runbook-profile"), ("privacy data access", "privacy-standard")]
    hits = [expected in {result["id"] for result in search_knowledge_base(query, principal)["results"]} for query, expected in cases]
    return {"cases": len(cases), "recall_at_3": sum(hits) / len(hits), "policy": {"principal": asdict(principal), "evaluation_uses_authorized_retrieval": True}}
