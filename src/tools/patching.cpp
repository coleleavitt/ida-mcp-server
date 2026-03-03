#include "tools/tools.hpp"
#include <bytes.hpp>

namespace ida_mcp::tools::patching {
    namespace {
        json patch_byte_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            int value = params["value"].get<int>();
            if (value < 0 || value > 255) {
                throw std::runtime_error("Byte value must be 0-255");
            }

            bool success = patch_byte(ea, static_cast<uchar>(value));

            return json{
                {"address", format_ea(ea)},
                {"value", value},
                {"success", success}
            };
        }

        json patch_word_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            int value = params["value"].get<int>();
            if (value < 0 || value > 0xFFFF) {
                throw std::runtime_error("Word value must be 0-65535");
            }

            bool success = patch_word(ea, static_cast<uint16>(value));

            return json{
                {"address", format_ea(ea)},
                {"value", value},
                {"success", success}
            };
        }

        json patch_dword_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            uint32 value = params["value"].get<uint32>();
            bool success = patch_dword(ea, value);

            return json{
                {"address", format_ea(ea)},
                {"value", value},
                {"success", success}
            };
        }

        json patch_qword_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            uint64 value = params["value"].get<uint64>();
            bool success = patch_qword(ea, value);

            return json{
                {"address", format_ea(ea)},
                {"value", value},
                {"success", success}
            };
        }

        json patch_bytes_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            std::string hex_str = params["bytes"].get<std::string>();

            std::string clean_hex;
            for (char c: hex_str) {
                if (c != ' ' && c != '\t') {
                    clean_hex += c;
                }
            }

            if (clean_hex.length() % 2 != 0) {
                throw std::runtime_error("Hex string must have even length");
            }

            std::vector<uchar> bytes;
            for (size_t i = 0; i < clean_hex.length(); i += 2) {
                std::string byte_str = clean_hex.substr(i, 2);
                uchar byte = static_cast<uchar>(std::stoul(byte_str, nullptr, 16));
                bytes.push_back(byte);
            }

            if (bytes.empty()) {
                throw std::runtime_error("Empty byte array");
            }

            // patch_bytes doesn't return success/failure - verify by reading back
            patch_bytes(ea, bytes.data(), bytes.size());

            // Verify the patch was applied correctly
            bool success = true;
            for (size_t i = 0; i < bytes.size(); i++) {
                if (get_byte(ea + i) != bytes[i]) {
                    success = false;
                    break;
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"size", bytes.size()},
                {"success", success}
            };
        }

        json get_original_byte_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            uchar original = get_original_byte(ea);
            uchar current = get_byte(ea);
            bool is_patched = (original != current);

            return json{
                {"address", format_ea(ea)},
                {"original_byte", original},
                {"current_byte", current},
                {"is_patched", is_patched}
            };
        }

        json revert_byte_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            uchar original = get_original_byte(ea);
            bool success = patch_byte(ea, original);

            return json{
                {"address", format_ea(ea)},
                {"reverted_to", original},
                {"success", success}
            };
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "patch_byte";
            def.description = "Patch a single byte at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"value", {{"type", "integer"}, {"description", "Byte value (0-255)"}}}
                    }
                },
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, patch_byte_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "patch_word";
            def.description = "Patch a 16-bit word at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"value", {{"type", "integer"}, {"description", "Word value (0-65535)"}}}
                    }
                },
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, patch_word_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "patch_dword";
            def.description = "Patch a 32-bit dword at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"value", {{"type", "integer"}, {"description", "Dword value"}}}
                    }
                },
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, patch_dword_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "patch_qword";
            def.description = "Patch a 64-bit qword at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"value", {{"type", "integer"}, {"description", "Qword value"}}}
                    }
                },
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, patch_qword_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "patch_bytes";
            def.description = "Patch multiple bytes at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"bytes", {{"type", "string"}, {"description", "Hex bytes (e.g., '90 90 90' or '909090')"}}}
                    }
                },
                {"required", json::array({"address", "bytes"})}
            };
            server.register_tool(def, patch_bytes_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "get_original_byte";
            def.description = "Get the original (unpatched) byte at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_original_byte_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "revert_byte";
            def.description = "Revert a patched byte to its original value";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, revert_byte_impl);
        }
    }
}
