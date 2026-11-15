import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.backend import GhidraBackend
from ghidra_mcp.server import GUI_ONLY_TOOLS, create_server


def tool_names(mcp) -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


@pytest.mark.parametrize("capabilities", [None, {"gui_context"}])
def test_gui_tools_registered_when_available_or_unknown(capabilities):
    names = tool_names(create_server(GhidraBackend(), capabilities=capabilities))
    assert set(GUI_ONLY_TOOLS) <= names


def test_gui_tools_hidden_in_headless():
    names = tool_names(create_server(GhidraBackend(), capabilities=set()))
    assert not set(GUI_ONLY_TOOLS) & names
    assert {"get_program_info", "read_memory", "get_function_calls", "list_functions"} <= names


def test_backend_error_becomes_tool_error(fake_backend):
    fake_backend.fail("/decompile", 409, "AMBIGUOUS_NAME", "'f' matches 2 functions")
    mcp = create_server(GhidraBackend(fake_backend.url))
    with pytest.raises(ToolError, match="AMBIGUOUS_NAME"):
        asyncio.run(mcp.call_tool("decompile_function", {"name": "f"}))


def test_structured_result_is_passed_through(fake_backend):
    page = {"items": [{"name": "main", "address": "00401000"}], "offset": 0, "limit": 100,
            "total": 1, "has_more": False}
    fake_backend.ok("/functions", page)
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_functions", filter="ma") == page
    assert fake_backend.requests[-1][2]["filter"] == "ma"


def test_list_methods_is_alias_returning_names(fake_backend):
    fake_backend.ok("/functions", {"items": [{"name": "a", "address": "1"}, {"name": "b", "address": "2"}],
                                   "offset": 0, "limit": 100, "total": 2, "has_more": False})
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "list_methods") == {"result": ["a", "b"]}


def test_rename_variable_requires_function_identity():
    mcp = create_server(GhidraBackend("http://127.0.0.1:1/"))
    with pytest.raises(ToolError, match="MISSING_PARAMETER"):
        asyncio.run(mcp.call_tool("rename_variable", {"old_name": "a", "new_name": "b"}))


# --- hd2-extensions: program control ------------------------------------------------------


def test_program_control_tools_available_in_headless_and_gui():
    for caps in (set(), {"gui_context"}):
        names = tool_names(create_server(GhidraBackend(), capabilities=caps))
        assert {"create_function", "disassemble_at", "save_program"} <= names
    assert {"goto", "list_open_programs", "open_program"} <= set(GUI_ONLY_TOOLS)


def test_create_function_posts_address_and_optional_name(fake_backend):
    created = {"function": {"name": "FUN_10053cb0", "address": "10053cb0"}, "already_existed": False,
               "disassembled": True, "body_start": "10053cb0", "body_end": "10053d40",
               "instruction_count": 31}
    fake_backend.ok("/create_function", created)
    mcp = create_server(GhidraBackend(fake_backend.url))
    assert call(mcp, "create_function", address="0x10053cb0") == created
    method, path, params = fake_backend.requests[-1]
    assert (method, path) == ("POST", "/create_function")
    assert params["address"] == "0x10053cb0" and "name" not in params
    call(mcp, "create_function", address="0x10053cb0", name="Visual3_Load")
    assert fake_backend.requests[-1][2]["name"] == "Visual3_Load"


@pytest.mark.parametrize("tool,path,args", [
    ("disassemble_at", "/disassemble", {"address": "0x1000"}),
    ("save_program", "/save_program", {}),
    ("goto", "/goto", {"address": "0x1000"}),
    ("open_program", "/open_program", {"name": "LS3DF.dll"}),
])
def test_program_control_endpoints(fake_backend, tool, path, args):
    fake_backend.ok(path, {"ok": True})
    mcp = create_server(GhidraBackend(fake_backend.url), capabilities={"gui_context"})
    call(mcp, tool, **args)
    method, got_path, params = fake_backend.requests[-1]
    assert (method, got_path) == ("POST", path)
    assert params == args


def test_list_open_programs_is_get(fake_backend):
    fake_backend.ok("/open_programs", {"programs": [{"name": "LS3DF.dll", "project_path": "/LS3DF.dll", "current": True}]})
    mcp = create_server(GhidraBackend(fake_backend.url), capabilities={"gui_context"})
    call(mcp, "list_open_programs")
    assert fake_backend.requests[-1][:2] == ("GET", "/open_programs")
