"""
Client script to test the Pydantic skill fix.
"""

import asyncio
from agentfield import Agent


async def main():
    client = Agent(
        node_id="test-client",
        agentfield_server="http://localhost:8080",
    )

    print("🧪 Testing Pydantic Model Support for Skills")
    print("=" * 60)

    # Test 1: Call skill with Pydantic model parameter
    print("\n1️⃣  Testing skill with Pydantic model parameter...")
    try:
        result = await client.call(
            "test-pydantic-skill.ingest_with_pydantic",
            request={
                "document_id": "doc-123",
                "path": "/tmp/test.txt",
                "text": None
            }
        )
        print(f"✅ Success! Result: {result}")
    except Exception as e:
        print(f"❌ Error: {e}")

    # Test 2: Call skill with plain parameters (backward compatibility)
    print("\n2️⃣  Testing skill with plain parameters...")
    try:
        result = await client.call(
            "test-pydantic-skill.ingest_with_plain_params",
            document_id="doc-456",
            path="/tmp/test2.txt",
            text="Hello World"
        )
        print(f"✅ Success! Result: {result}")
    except Exception as e:
        print(f"❌ Error: {e}")

    print("\n" + "=" * 60)
    print("Tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
