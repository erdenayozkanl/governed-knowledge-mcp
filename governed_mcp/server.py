from fastmcp import FastMCP
from .core import caller, evaluate_retrieval, investigate_incident, search_knowledge_base, traverse_authorized_graph

mcp = FastMCP("Governed Knowledge MCP")

def principal(subject: str, roles: list[str], tenant: str, clearance: str, model_tier: str):
    """Builds a caller identity; production deployments derive it from verified identity claims."""
    return caller(subject, roles, tenant, clearance, model_tier)

@mcp.tool()
def search_documents(query: str, subject: str, roles: list[str], tenant: str = "acme", clearance: str = "internal", model_tier: str = "approved") -> dict:
    """Search knowledge-base documents. Returns only policy-authorized chunks and audit decisions."""
    return search_knowledge_base(query, principal(subject, roles, tenant, clearance, model_tier))

@mcp.tool()
def query_graph(question: str, subject: str, roles: list[str], tenant: str = "acme", clearance: str = "internal", model_tier: str = "approved", max_hops: int = 2) -> dict:
    """Traverse an authorization-filtered knowledge graph; never exposes the full graph to the model."""
    return traverse_authorized_graph(question, principal(subject, roles, tenant, clearance, model_tier), max_hops)

@mcp.tool()
def investigate(service: str, question: str, subject: str, roles: list[str], tenant: str = "acme", clearance: str = "internal", model_tier: str = "approved") -> dict:
    """Runs a bounded agent workflow over authorized graph and knowledge-base evidence."""
    return investigate_incident(service, question, principal(subject, roles, tenant, clearance, model_tier))

@mcp.tool()
def evaluate(subject: str, roles: list[str], tenant: str = "acme", clearance: str = "internal", model_tier: str = "approved") -> dict:
    """Measures retrieval quality using the same authorization boundary as production tools."""
    return evaluate_retrieval(principal(subject, roles, tenant, clearance, model_tier))

if __name__ == "__main__":
    mcp.run(transport="stdio")
