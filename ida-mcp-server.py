import glob
import json
import os
import threading
try:
    import ida_bytes
    import ida_ua
    import ida_funcs
    import ida_hexrays
    import ida_name
    import ida_segment
    import idautils
    import idc
    import ida_idaapi
    import ida_kernwin
    import idaapi
except ImportError:
    print("This script must be run within IDA Pro with Python support.")
    raise

from typing import Dict, List, Any, Tuple
from functools import wraps
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.applications import Starlette
from starlette.routing import Mount
from mcp.server import Server
from fastmcp import FastMCP


# Initialize FastMCP server for IDA tools
mcp = FastMCP("IDA MCP Server", port=3000)

# Decorator that encapsulates function execution in the main thread
def execute_on_main_thread(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        result = []
        exception = []

        def run_function():
            try:
                result.append(f(*args, **kwargs))
            except Exception as e:
                exception.append(e)
            return 0

        ida_kernwin.execute_sync(run_function, ida_kernwin.MFF_FAST)

        if exception:
            raise exception[0]
        return result[0]
    return wrapper


@mcp.tool()
@execute_on_main_thread
def get_bytes(ea: int, size: int) -> List[int]:
    """Get bytes at specified address.

    Args:
        ea: Effective address to read from
        size: Number of bytes to read
    """
    try:
        return [ida_bytes.get_byte(ea + i) for i in range(size)]
    except Exception as e:
        print(f"Error in get_bytes: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
@execute_on_main_thread
def get_disasm(ea: int) -> str:
    """Get disassembly at specified address.

    Args:
        ea: Effective address to disassemble
    """
    return idc.generate_disasm_line(ea, 0)


@mcp.tool()
@execute_on_main_thread
def get_decompiled_func(ea: int) -> Dict[str, Any]:
    """Get decompiled pseudocode of function containing address.

    Args:
        ea: Effective address within the function
    """
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": "No function found at address"}

        decompiler = ida_hexrays.decompile(func.start_ea)
        if not decompiler:
            return {"error": "Failed to decompile function"}

        return {"code": str(decompiler)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
@execute_on_main_thread
def get_function_name(ea: int) -> str:
    """Get function name at specified address.

    Args:
        ea: Effective address of the function
    """
    return ida_name.get_name(ea)


@mcp.tool()
@execute_on_main_thread
def get_segments() -> List[Dict[str, Any]]:
    """Get all segments information.

    @return: List of segments (start, end, name, class, perm, bitness, align, comb, type, sel, flags)
    """
    segments = []
    n = 0
    seg = ida_segment.getnseg(n)
    while seg:
        segments.append(
            {
                "start": seg.start_ea,
                "end": seg.end_ea,
                "name": ida_segment.get_segm_name(seg),
                "class": ida_segment.get_segm_class(seg),
                "perm": seg.perm,
                "bitness": seg.bitness,
                "align": seg.align,
                "comb": seg.comb,
                "type": seg.type,
                "sel": seg.sel,
                "flags": seg.flags,
            }
        )
        n += 1
        seg = ida_segment.getnseg(n)
    return segments


@mcp.tool()
@execute_on_main_thread
def get_functions() -> List[Dict[str, Any]]:
    """Get all functions in the binary."""
    functions = []
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        functions.append({"address": func_ea, "name": func_name})
    return functions


@mcp.tool()
@execute_on_main_thread
def get_xrefs_to(ea: int) -> List[Dict[str, Any]]:
    """Get all cross references to specified address.

    Args:
        ea: Effective address to find references to
    """
    xrefs = []
    for xref in idautils.XrefsTo(ea, 0):
        xrefs.append({"from": xref.frm, "type": xref.type})
    return xrefs


@mcp.tool()
@execute_on_main_thread
def get_imports() -> dict[str, list[tuple[int, str, int]]]:
    """Get all imports in the binary.

    Args:
        None

    Returns:
        A dictionary where the keys are module names and the values are lists of tuples.
        Each tuple contains the address of the imported function, the name of the function,
        and the ordinal value of the function.
    """
    tree = {}
    nimps = idaapi.get_import_module_qty()

    for i in range(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            continue
        # Create a list for imported names
        items = []

        def imports_names_cb(ea, name, ordinal):
            items.append((ea, "" if not name else name, ordinal))
            # True -> Continue enumeration
            return True

        # Enum imported entries in this module
        idaapi.enum_import_names(i, imports_names_cb)

        if name not in tree:
            tree[name] = []
        tree[name].extend(items)

    return tree


@mcp.tool()
@execute_on_main_thread
def get_exports() -> List[Tuple[int, int, int, str]]:
    """Get all exports in the binary.

    @return: List of tuples (index, ordinal, ea, name)
    """
    return list(idautils.Entries())


@mcp.tool()
@execute_on_main_thread
def get_entry_point() -> List[int]:
    """Get a list of entry point of the binary."""
    try:
        import ida_entry
        entry_list = []
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            ord_i = ida_entry.get_entry_ordinal(i)
            entry_list.append(ida_entry.get_entry(ord_i))
        return entry_list
    except (ImportError, AttributeError):
        try:
            # Alternative method: idc.get_inf_attr to get
            import idc
            return [idc.get_inf_attr(idc.INF_START_EA)]
        except (ImportError, AttributeError):
            # Last alternative method: use cvar.inf
            return [idaapi.cvar.inf.start_ea]
    except Exception:
        return []


@mcp.tool()
@execute_on_main_thread
def make_function(ea: int) -> None:
    """Make a function at specified address."""
    ida_funcs.add_func(ea)


@mcp.tool()
@execute_on_main_thread
def undefine_function(ea: int) -> None:
    """Undefine a function at specified address."""
    ida_funcs.del_func(ea)


@mcp.tool()
@execute_on_main_thread
def get_dword_at(ea: int) -> int:
    """Get the dword at specified address."""
    return idc.get_dword(ea)


@mcp.tool()
@execute_on_main_thread
def get_word_at(ea: int) -> int:
    """Get the word at specified address."""
    return idc.get_word(ea)


@mcp.tool()
@execute_on_main_thread
def get_byte_at(ea: int) -> int:
    """Get the byte at specified address."""
    return idc.get_byte(ea)


@mcp.tool()
@execute_on_main_thread
def get_qword_at(ea: int) -> int:
    """Get the qword at specified address."""
    return idc.get_qword(ea)


@mcp.tool()
@execute_on_main_thread
def get_float_at(ea: int) -> float:
    """Get the float at specified address."""
    return idc.get_float(ea)


@mcp.tool()
@execute_on_main_thread
def get_double_at(ea: int) -> float:
    """Get the double at specified address."""
    return idc.get_double(ea)


@mcp.tool()
@execute_on_main_thread
def get_string_at(ea: int) -> str:
    """Get the string at specified address."""
    return idc.get_strlit_contents(ea)


@mcp.tool()
@execute_on_main_thread
def get_strings():
    strings = []
    for s in idautils.Strings():
        strings.append({"address": s.ea, "string": str(s)})
    return strings

@mcp.tool()
@execute_on_main_thread
def get_current_file_path():
    return idc.get_input_file_path()

@mcp.tool()
@execute_on_main_thread
def list_files_with_relative_path(relative_path: str = ""):
    base_dir = os.path.dirname(idc.get_input_file_path())
    if  ':' in relative_path or '..' in relative_path or '//' in relative_path:
        return json.dumps({"error": "Invalid relative path"})
    if relative_path is None or relative_path == "":
        return glob.glob(os.path.join(base_dir, "*"))
    else:
        return glob.glob(os.path.join(base_dir, relative_path, "*"))

@mcp.tool()
@execute_on_main_thread
def read_file(relative_path: str):
    base_dir = os.path.dirname(idc.get_input_file_path())
    if  ':' in relative_path or '..' in relative_path or '//' in relative_path:
        return json.dumps({"error": "Invalid relative path"})
    if relative_path is "":
        return json.dumps({"error": "Relative path is required"})
    with open(os.path.join(base_dir, relative_path), "r") as f:
        return f.read()

@mcp.tool()
@execute_on_main_thread
def write_file(relative_path: str, content: str):
    base_dir = os.path.dirname(idc.get_input_file_path())
    if  ':' in relative_path or '..' in relative_path or '//' in relative_path:
        return json.dumps({"error": "Invalid relative path"})
    if relative_path is "":
        return json.dumps({"error": "Relative path is required"})
    with open(os.path.join(base_dir, relative_path), "w") as f:
        f.write(content)

@mcp.tool()
@execute_on_main_thread
def read_binary(relative_path: str):
    base_dir = os.path.dirname(idc.get_input_file_path())
    if  ':' in relative_path or '..' in relative_path or '//' in relative_path:
        return json.dumps({"error": "Invalid relative path"})
    if relative_path is "":
        return json.dumps({"error": "Relative path is required"})
    with open(os.path.join(base_dir, relative_path), "rb") as f:
        return f.read()

@mcp.tool()
@execute_on_main_thread
def write_binary(relative_path: str , content: bytes):
    base_dir = os.path.dirname(idc.get_input_file_path())
    if  ':' in relative_path or '..' in relative_path or '//' in relative_path:
        return json.dumps({"error": "Invalid relative path"})
    if relative_path is "":
        return json.dumps({"error": "Relative path is required"})
    with open(os.path.join(base_dir, relative_path), "wb") as f:
        f.write(content)

@mcp.tool()
@execute_on_main_thread
def eval_pythoni(script: str):
    return eval(script)

@mcp.tool()
@execute_on_main_thread
def get_instruction_length(address: int) -> int:
    """
    Retrieves the length (in bytes) of the instruction at the specified address.

    Args:
        address: The address of the instruction.

    Returns:
        The length (in bytes) of the instruction.  Returns 0 if the instruction cannot be decoded.
    """
    try:
        # Create an insn_t object to store instruction information.
        insn = ida_ua.insn_t()

        # Decode the instruction.
        length = ida_ua.decode_insn(insn, address)
        if length == 0:
            print(f"Failed to decode instruction at address {hex(address)}")
            return 0

        return length
    except Exception as e:
        print(f"Error getting instruction length: {str(e)}")
        return 0

@mcp.prompt()
def binary_analysis_strategy() -> str:
    """
    Guild for analyzing the binary
    """
    return (
        "IDA Pro MCP Server Tools and Best Practices:\n\n."
        "Tools: \n"
        "- get_bytes: Get bytes at specified address.\n"
        "- get_disasm: Get disassembly at specified address.\n"
        "- get_decompiled_func: Get decompiled pseudocode of function containing address.\n"
        "- get_function_name: Get function name at specified address.\n"
        "- get_segments: Get all segments information.\n"
        "- get_functions: Get all functions in the binary.\n"
        "- get_xrefs_to: Get all cross references to a specified address.\n"
        "- get_imports: Get all imports in the binary.\n"
        "- get_exports: Get all exports in the binary.\n"
        "- get_entry_point: Get the entry point of the binary.\n"
        "- make_function: Make a function at specified address.\n"
        "- undefine_function: Undefine a function at specified address.\n"
        "- get_dword_at: Get the dword at specified address.\n"
        "- get_word_at: Get the word at specified address.\n"
        "- get_byte_at: Get the byte at specified address.\n"
        "- get_qword_at: Get the qword at specified address.\n"
        "- get_float_at: Get the float at specified address.\n"
        "- get_double_at: Get the double at specified address.\n"
        "- get_string_at: Get the string at specified address.\n"
        "- get_strings: Get all strings in the binary.\n"
        "- get_current_file_path: Get the current path of the binary.\n"
        "- list_files_with_relative_path: List all files in the specified relative path in the current directory.\n"
        "- read_file: Read the content of a file.\n"
        "- write_file: Write content to a file.\n"
        "- read_binary: Read the content of a binary file.\n"
        "- write_binary: Write content to a binary file.\n"
        "- eval_python: Evaluate a Python script in IDA Pro.\n"
        "- get_instruction_length: Get the length of the instruction at the specified address.\n"
        "Best Practices: \n"
        "- Initial Analysis Phase\n"
        "   1. Examine the Entry Point\n"
        "       - Use the get_entry_point() tool to locate the program's entry point\n"
        "       - Analyze the code at the entry point to understand the program's startup flow\n"
        "       - Look for unusual instructions or jumps\n"
        "   2. Analyze Import Table\n"
        "       - Use the get_imports() tool to view all imported functions\n"
        "       - Look for suspicious API functions, such as:\n"
        "           - File operations: CreateFile, WriteFile\n"
        "           - Network communication: socket, connect, InternetOpen\n"
        "           - Process manipulation: CreateProcess, VirtualAlloc\n"
        "           - Registry operations: RegOpenKey, RegSetValue\n"
        "           - Cryptography related: CryptEncrypt, CryptDecrypt\n"
        "   3. Review Strings\n"
        "       - Use the get_strings() tool to obtain all strings\n"
        "       - Pay attention to IP addresses, URLs, domain names, file paths\n"
        "       - Look for encrypted or obfuscated string patterns\n"
        "       - Analyze command line parameters and error messages\n"
        "   4. In-Depth Analysis Phase\n"
        "       - Track Key API Calls\n"
        "           - Use get_xrefs_to() to find cross-references to suspicious imported functions\n"
        "           - Use get_decompiled_func() to analyze functions that call these APIs\n"
        "           - Analyze how parameters and return values are handled\n"
        "   5. Identify Main Functional Blocks\n"
        "       - Use get_functions() to get a list of all functions\n"
        "       - Sort functions by size and complexity\n"
        "       - Decompile and analyze large, complex functions\n"
        "       - Look for suspicious function names or unnamed functions\n"
        "   6. Analyze Control Flow\n"
        "       - Observe conditional branches and loop structures\n"
        "       - Analyze function call graphs and execution paths\n"
        "       - Look for anti-debugging and anti-VM detection techniques\n"
        "       - Pay attention to unusual jumps and callback mechanisms\n"
        "   7. Identifying Malicious Behaviors\n"
        "       - Identify Common Malicious Functionality\n"
        "           - Persistence mechanisms: Registry modifications, startup items, service creation\n"
        "           - Data theft: File searching, keylogging, screen capturing\n"
        "           - Communication features: C&C communication, data exfiltration channels\n"
        "           - Evasion techniques: Obfuscation, packing, anti-analysis checks\n"
        "           - Destructive behaviors: File encryption, system damage\n"
        "   8. Analyze Algorithms and Encryption Routines\n"
        "       - Identify encryption and decryption functions\n"
        "       - Look for hardcoded keys and cryptographic constants\n"
        "       - Analyze how data is processed in memory\n"
        "   9. Analyze Network Communication\n"
        "       - Identify network communication functions\n"
        "       - Look for IP addresses, URLs, and domain names\n"
        "       - Analyze how data is sent and received over the network\n"
        "   10. Dump payloads if there is any decryption or encoding\n"
        "       - Generate decryption or decodeing script in python and ida python\n"
        "       - Use eval_python to execute the script in IDA Pro\n"
        "       - Dump payloads in the current directory\n"
        "   11. Document Analysis Results\n"
        "       - Add comments to key functions\n"
        "       - Rename functions to reflect their actual functionality\n"
        "       - Create a logical structure diagram of the code\n"
        "   12. Using Advanced Techniques\n"
        "       - Use IDA Pro's advanced features like IDAPython scripting, IDA SDK, and IDA API\n"
        "       - Implement custom analysis scripts to automate repetitive tasks\n"
        "       - Explore IDA Pro's plugin ecosystem for additional analysis capabilities\n"
    )


def create_starlette_app(mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette application that can serve the provided mcp server with SSE."""

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )
    ]
    return Starlette(
        debug=debug,
        middleware=middleware,
        routes=[
            Mount("/", app=mcp.sse_app()),
        ],
    )


class ModelContextProtocolPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = "IDA Model Context Protocol Server"
    help = "Provides REST API and SSE for IDA Pro analysis"
    wanted_name = "IDA MCP Server"
    wanted_hotkey = ""

    def init(self):
        try:
            print("Initializing IDA Model Context Protocol Server...")
            # app = create_starlette_app(mcp, debug=True)

            def run_server():
                try:
                    # 設置將異常轉換為 JSON 響應
                    mcp.run(transport="sse")
                    # uvicorn.run(app, host="localhost", port=3000, log_level="debug")
                except Exception as e:
                    print(f"Server error: {str(e)}")

            server_thread = threading.Thread(target=run_server)
            server_thread.daemon = True
            server_thread.start()
            print("Server started successfully!")
            return ida_idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Failed to start server: {str(e)}")
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        print("Terminating IDA Model Context Protocol Server...")


def PLUGIN_ENTRY():
    return ModelContextProtocolPlugin()


if __name__ == "__main__":
    PLUGIN_ENTRY()
