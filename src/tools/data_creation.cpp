#include "tools/tools.hpp"
#include <bytes.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <loader.hpp>

namespace ida_mcp::tools::data_creation {
    namespace {
        json handle_create_data(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            std::string type_str = params.value("type", "byte");
            flags64_t flags;
            asize_t size = 0;

            if (type_str == "byte") { flags = byte_flag(); size = 1; }
            else if (type_str == "word") { flags = word_flag(); size = 2; }
            else if (type_str == "dword") { flags = dword_flag(); size = 4; }
            else if (type_str == "qword") { flags = qword_flag(); size = 8; }
            else if (type_str == "float") { flags = float_flag(); size = 4; }
            else if (type_str == "double") { flags = double_flag(); size = 8; }
            else throw std::runtime_error("Unknown type: " + type_str + ". Use: byte/word/dword/qword/float/double");

            int count = params.value("count", 1);
            if (count < 1 || count > 65536) throw std::runtime_error("count must be 1-65536");

            bool ok = create_data(ea, flags, size * count, BADADDR);

            return json{
                {"address", format_ea(ea)},
                {"type", type_str},
                {"size", size * count},
                {"count", count},
                {"success", ok}
            };
        }

        json handle_create_string(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            asize_t length = params.value("length", 0);
            int strtype = params.value("string_type", 0); // STRTYPE_C = 0

            bool ok;
            if (length > 0) {
                ok = create_strlit(ea, length, strtype);
            } else {
                ok = create_strlit(ea, 0, strtype);
            }

            qstring str_content;
            if (ok) {
                size_t maxlen = get_max_strlit_length(ea, strtype, 0);
                get_strlit_contents(&str_content, ea, maxlen, strtype);
            }

            return json{
                {"address", format_ea(ea)},
                {"success", ok},
                {"content", ok && !str_content.empty() ? json(str_content.c_str()) : json(nullptr)},
                {"string_type", strtype}
            };
        }

        json handle_undefine(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            asize_t size = params.value("size", 1);
            if (size < 1 || size > 0x100000) throw std::runtime_error("size must be 1-1048576");

            bool ok = del_items(ea, DELIT_SIMPLE, size);

            return json{
                {"address", format_ea(ea)},
                {"size", size},
                {"success", ok}
            };
        }

        json handle_make_code(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            int length = create_insn(ea);

            return json{
                {"address", format_ea(ea)},
                {"success", length > 0},
                {"instruction_size", length}
            };
        }

        json handle_get_data_value(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            flags64_t flags = get_flags(ea);
            asize_t elsize = get_data_elsize(ea, flags);

            uval_t value = 0;
            bool ok = get_data_value(&value, ea, elsize);

            return json{
                {"address", format_ea(ea)},
                {"value", ok ? json(value) : json(nullptr)},
                {"value_hex", ok ? json(format_ea(value)) : json(nullptr)},
                {"element_size", elsize},
                {"is_code", is_code(flags)},
                {"is_data", is_data(flags)},
                {"success", ok}
            };
        }

        json handle_get_file_offset(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            qoff64_t offset = get_fileregion_offset(ea);

            return json{
                {"address", format_ea(ea)},
                {"file_offset", offset != -1 ? json(offset) : json(nullptr)},
                {"file_offset_hex", offset != -1 ? json(format_ea(offset)) : json(nullptr)},
                {"found", offset != -1}
            };
        }

        json handle_get_ea_from_file_offset(const json &params) {
            qoff64_t offset = params["offset"].get<uint64_t>();

            ea_t ea = get_fileregion_ea(offset);

            return json{
                {"file_offset", offset},
                {"address", ea != BADADDR ? json(format_ea(ea)) : json(nullptr)},
                {"found", ea != BADADDR}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "create_data";
            def.description = "Create a data item at address (byte/word/dword/qword/float/double)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"type", {{"type", "string"}, {"description", "Data type: byte/word/dword/qword/float/double"}}},
                    {"count", {{"type", "integer"}, {"description", "Number of elements (default 1)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_create_data);
        }
        {
            mcp::ToolDefinition def;
            def.name = "create_string";
            def.description = "Create a string literal at address. Auto-detects length if not specified.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"length", {{"type", "integer"}, {"description", "String length (0=auto-detect)"}}},
                    {"string_type", {{"type", "integer"}, {"description", "0=C string, 1=Pascal, 2=LEN2, 3=Unicode (default 0)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_create_string);
        }
        {
            mcp::ToolDefinition def;
            def.name = "undefine";
            def.description = "Undefine (delete) items at address range, turning them back to raw bytes";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Start hex address"}}},
                    {"size", {{"type", "integer"}, {"description", "Number of bytes to undefine (default 1)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_undefine);
        }
        {
            mcp::ToolDefinition def;
            def.name = "make_code";
            def.description = "Force-create an instruction at address (analyze bytes as code)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_make_code);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_data_value";
            def.description = "Read the data value at an address according to its defined type";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_data_value);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_file_offset";
            def.description = "Convert a virtual address to its file offset in the original binary";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Virtual address (hex)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_file_offset);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_address_from_file_offset";
            def.description = "Convert a file offset to its virtual address";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"offset", {{"type", "integer"}, {"description", "File offset"}}}
                }},
                {"required", json::array({"offset"})}
            };
            server.register_tool(def, handle_get_ea_from_file_offset);
        }
    }
}
