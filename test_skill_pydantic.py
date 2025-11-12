"""
Test script to verify that skills now support Pydantic models.
"""

from pydantic import BaseModel
from agentfield import Agent


# Test 1: Skill with Pydantic model parameter
class IngestRequest(BaseModel):
    document_id: str
    path: str | None = None
    text: str | None = None


class IngestResult(BaseModel):
    document_id: str
    processed: bool


app = Agent(
    node_id="test-pydantic-skill",
    agentfield_server="http://localhost:8080",
)


@app.skill()
async def ingest_with_pydantic(request: IngestRequest) -> IngestResult:
    """Test skill using Pydantic model parameter."""
    print(f"Received request: {request}")
    print(f"Type of request: {type(request)}")
    print(f"document_id: {request.document_id}")
    print(f"path: {request.path}")
    print(f"text: {request.text}")

    return IngestResult(
        document_id=request.document_id,
        processed=True
    )


@app.skill()
async def ingest_with_plain_params(
    document_id: str,
    path: str | None = None,
    text: str | None = None
) -> IngestResult:
    """Test skill using plain parameters (backward compatibility)."""
    print(f"Received document_id: {document_id}")
    print(f"Received path: {path}")
    print(f"Received text: {text}")

    return IngestResult(
        document_id=document_id,
        processed=True
    )


if __name__ == "__main__":
    print("🧪 Testing Pydantic model support for skills")
    print("=" * 60)
    print("Skills registered:")
    print("  1. ingest_with_pydantic(request: IngestRequest)")
    print("  2. ingest_with_plain_params(document_id, path, text)")
    print("=" * 60)
    print("\nStarting agent...")
    app.run(auto_port=True)
