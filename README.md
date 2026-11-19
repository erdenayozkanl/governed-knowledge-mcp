# Governed Knowledge MCP

A production-oriented Model Context Protocol server that turns a RAG knowledge base, a governed knowledge graph and an agent workflow into safe, auditable tools for LLM clients.

## Why this exists

MCP should not expose a database or an entire graph directly to an LLM. This server exposes bounded tools; every result crosses a policy decision before it can become model context.

```text
MCP client → tool request + identity claims
           → authorization policy
           → RAG / graph / agent adapter
           → allowed evidence + audit decisions
           → LLM context
```

## Tools

| Tool | Backing capability | Output boundary |
|---|---|---|
| `search_documents` | RAG-style knowledge search | Authorized chunks only |
| `query_graph` | Multi-hop GraphRAG | Authorized facts only |
| `investigate` | Agent workflow | Grounded evidence and trace ID |
| `evaluate` | Retrieval evaluation | Evaluation under the caller's policy |

## Governance model

- **RBAC:** roles limit sensitive graph node types.
- **ABAC:** tenant, classification and caller clearance are checked per resource.
- **ReBAC:** relationship traversal is controlled; for example, `CONSUMES` paths require analyst or platform-admin authority.
- **MBAC:** an unapproved model cannot receive confidential context even when the human caller has sufficient clearance.
- **Auditability:** every returned tool payload contains allow/deny decisions and reasons.

## Run locally

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m governed_mcp.server
```

The server uses MCP stdio transport. Add it to an MCP client using:

```json
{
  "mcpServers": {
    "governed-knowledge": {
      "command": "python",
      "args": ["-m", "governed_mcp.server"],
      "cwd": "/absolute/path/to/governed-knowledge-mcp"
    }
  }
}
```

Run tests with `pytest -q`. Container mode: `docker build -t governed-knowledge-mcp .`.

## Production next steps

Replace demo adapters with `atlas-rag`, `axiom-graph`, `forge-agents` and `signal-router` service clients; derive identity from signed JWT/OIDC claims; use a centralized policy engine (e.g. OPA); persist audit events immutably; add rate limiting, OpenTelemetry and per-tenant evaluation suites.
