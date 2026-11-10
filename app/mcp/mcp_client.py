import asyncio
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def call_mcp_search(question: str) -> str:
    """
    Connects to the standalone MCP Server and calls the search_cve tool.
    """
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "app.mcp.mcp_server"],
        env={
            **os.environ, 
            "PYTHONPATH": "/app",
            "DATABASE_URL": os.getenv("DATABASE_URL"),
            "OLLAMA_URL": os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"),
        }
    )
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "search_cve", 
                    arguments={"question": question}
                )
                if result.content and len(result.content) > 0:
                    return result.content[0].text
                return "No results returned from MCP Server."
    except Exception as e:
        print(f"[MCP CLIENT ERROR] {e}")
        return f"MCP Connection Error: {e}"