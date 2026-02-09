#include "tools/tools.hpp"
#include <bytes.hpp>
#include <ida.hpp>
#include <sstream>
#include <iomanip>

namespace ida_mcp::tools::read_bytes {
    namespace {
        // Helper: Check if running on ARM64E (supports PAC)
        bool is_arm64e() {
            qstring procname = inf_get_procname();
            return inf_is_64bit() && (procname.find("ARM") != qstring::npos ||
                                      procname.find("arm") != qstring::npos ||
                                      procname.find("AARCH64") != qstring::npos);
        }

        // Helper: Strip PAC bits from ARM64E pointer
        // On ARM64E, top bits [63:48] may contain PAC signature
        uint64_t strip_pac_bits(uint64_t ptr) {
            // ARM64E uses top byte for PAC authentication
            // Virtual addresses use bits [0:47] for user space
            // Kernel addresses use bits [0:47] with bit 55 sign-extended

            // Check if this looks like a kernel pointer (bit 55 set)
            if (ptr & (1ULL << 55)) {
                // Kernel pointer - sign extend from bit 55
                return ptr | 0xFF80000000000000ULL;
            } else {
                // User pointer - zero top bits
                return ptr & 0x0000FFFFFFFFFFFFULL;
            }
        }

        // Helper: Detect if pointer value likely has PAC bits
        bool likely_has_pac(uint64_t ptr) {
            // If top byte is non-zero but not all 1s or all 0s, likely has PAC
            uint8_t top_byte = (ptr >> 56) & 0xFF;
            return top_byte != 0x00 && top_byte != 0xFF &&
                   ((ptr & 0x00FFFFFFFFFFFFFFULL) != 0);
        }

        json handle_read_bytes(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            size_t size = params.value("size", 16);

            // Limit size to prevent excessive memory usage
            size = std::min(size, size_t(4096));
            if (size == 0) {
                throw std::runtime_error("Size must be > 0");
            }

            // Check if address is valid
            if (!::is_loaded(ea)) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not loaded");
            }

            // Read bytes
            std::vector<uint8_t> buf(size);
            size_t bytes_read = get_bytes(buf.data(), size, ea, GMB_READALL);

            if (bytes_read == 0) {
                throw std::runtime_error("Failed to read bytes from " + format_ea(ea));
            }

            buf.resize(bytes_read);

            // Create hex dump
            std::vector<std::string> hex_lines;
            std::vector<std::string> ascii_lines;

            for (size_t i = 0; i < buf.size(); i += 16) {
                size_t chunk_size = std::min(size_t(16), buf.size() - i);
                ea_t offset = ea + i;

                // Hex representation
                std::ostringstream hex_ss;
                for (size_t j = 0; j < chunk_size; j++) {
                    hex_ss << std::hex << std::setw(2) << std::setfill('0')
                            << static_cast<int>(buf[i + j]);
                    if (j < chunk_size - 1) hex_ss << " ";
                }

                // ASCII representation
                std::ostringstream ascii_ss;
                for (size_t j = 0; j < chunk_size; j++) {
                    uint8_t byte = buf[i + j];
                    ascii_ss << (byte >= 32 && byte < 127 ? static_cast<char>(byte) : '.');
                }

                hex_lines.push_back(hex_ss.str());
                ascii_lines.push_back(ascii_ss.str());
            }

            // Convert to base64 for binary transfer
            std::string base64_data;
            static const char *base64_chars =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            for (size_t i = 0; i < buf.size(); i += 3) {
                uint32_t val = buf[i] << 16;
                if (i + 1 < buf.size()) val |= buf[i + 1] << 8;
                if (i + 2 < buf.size()) val |= buf[i + 2];

                base64_data += base64_chars[(val >> 18) & 0x3F];
                base64_data += base64_chars[(val >> 12) & 0x3F];
                base64_data += (i + 1 < buf.size()) ? base64_chars[(val >> 6) & 0x3F] : '=';
                base64_data += (i + 2 < buf.size()) ? base64_chars[val & 0x3F] : '=';
            }

            return json{
                {"address", format_ea(ea)},
                {"size", bytes_read},
                {"hex_lines", hex_lines},
                {"ascii_lines", ascii_lines},
                {"base64", base64_data}
            };
        }

        json handle_read_pointer_table(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            size_t count = params.value("count", 8);

            // Limit count
            count = std::min(count, size_t(256));

            // Determine pointer size
            int pointer_size = 0;
            if (params.contains("pointer_size")) {
                pointer_size = params["pointer_size"].get<int>();
            } else {
                pointer_size = inf_is_64bit() ? 8 : 4;
            }

            if (pointer_size != 4 && pointer_size != 8) {
                throw std::runtime_error("Pointer size must be 4 or 8");
            }

            bool is_arm64e_binary = is_arm64e();
            json pointers = json::array();

            for (size_t i = 0; i < count; i++) {
                ea_t ptr_ea = ea + (i * pointer_size);

                if (!::is_loaded(ptr_ea)) {
                    break;
                }

                uint64_t ptr_value;
                if (pointer_size == 8) {
                    ptr_value = get_qword(ptr_ea);
                } else {
                    ptr_value = get_dword(ptr_ea);
                }

                uint64_t original_ptr = ptr_value;
                bool has_pac = false;

                // For ARM64E, check and strip PAC bits if present
                if (is_arm64e_binary && pointer_size == 8) {
                    has_pac = likely_has_pac(ptr_value);
                    if (has_pac) {
                        ptr_value = strip_pac_bits(ptr_value);
                    }
                }

                // Check if pointer points to valid address
                bool valid_pointer = ::is_loaded(ptr_value);

                // Try to get name at pointer target
                qstring name;
                if (valid_pointer) {
                    get_ea_name(&name, ptr_value);
                }

                // Check if it's a function
                func_t *func = nullptr;
                if (valid_pointer) {
                    func = get_func(ptr_value);
                }

                json ptr_json = json{
                    {"index", i},
                    {"address", format_ea(ptr_ea)},
                    {"value", format_ea(ptr_value)},
                    {"valid", valid_pointer},
                    {"name", name.empty() ? nullptr : json(name.c_str())},
                    {"is_function", func != nullptr}
                };

                // Add PAC information if detected
                if (has_pac) {
                    ptr_json["pac_detected"] = true;
                    ptr_json["original_value"] = format_ea(original_ptr);
                    ptr_json["pac_bits"] = format_ea(original_ptr & 0xFF00000000000000ULL);
                }

                pointers.push_back(ptr_json);
            }

            json result = json{
                {"address", format_ea(ea)},
                {"count", pointers.size()},
                {"pointer_size", pointer_size},
                {"pointers", pointers}
            };

            if (is_arm64e_binary) {
                result["arm64e"] = true;
                result["pac_aware"] = true;
            }

            return result;
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // read_bytes
        {
            mcp::ToolDefinition def;
            def.name = "read_bytes";
            def.description = "Read raw bytes from address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex start address"}
                            }
                        },
                        {
                            "size", {
                                {"type", "number"},
                                {"description", "Bytes to read"},
                                {"default", 16}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_read_bytes);
        }

        // read_pointer_table
        {
            mcp::ToolDefinition def;
            def.name = "read_pointer_table";
            def.description = "Read pointer table";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex start address"}
                            }
                        },
                        {
                            "count", {
                                {"type", "number"},
                                {"description", "Pointer count"},
                                {"default", 8}
                            }
                        },
                        {
                            "pointer_size", {
                                {"type", "number"},
                                {"description", "Pointer size bytes"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_read_pointer_table);
        }
    }
} // namespace ida_mcp::tools::read_bytes
