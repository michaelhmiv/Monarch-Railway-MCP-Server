from monarch_mcp_server.app import configure_tool_metadata, mcp
from monarch_mcp_server.tool_metadata import TOOL_METADATA, tool_catalog


configure_tool_metadata()


def test_every_registered_tool_has_visible_metadata():
    registered = {tool.name for tool in mcp._tool_manager.list_tools()}

    assert len(registered) == 49
    assert registered == set(TOOL_METADATA)
    assert all(tool.title for tool in mcp._tool_manager.list_tools())
    assert all(tool.annotations for tool in mcp._tool_manager.list_tools())
    assert len(tool_catalog(mcp)) == len(registered)


def test_tool_catalog_has_unique_names_and_human_titles():
    catalog = tool_catalog(mcp)
    assert len({item["name"] for item in catalog}) == len(catalog)
    assert all(item["title"] != item["name"] for item in catalog)
