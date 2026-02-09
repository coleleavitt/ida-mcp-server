#include "tools/tools.hpp"
#include <bytes.hpp>
#include <segment.hpp>
#include <loader.hpp>
#include <lines.hpp>
#include <nalt.hpp>

namespace ida_mcp::tools::memory {
    namespace {
        // Helper: Check if this is a Mach-O binary
        bool is_macho_binary() {
            return inf_get_filetype() == f_MACHO;
        }

        // Helper: Classify Mach-O section type
        const char* classify_macho_section(const std::string& seg_name) {
            // Objective-C sections
            if (seg_name.find("__objc_classlist") != std::string::npos) return "objc_class_list";
            if (seg_name.find("__objc_catlist") != std::string::npos) return "objc_category_list";
            if (seg_name.find("__objc_protolist") != std::string::npos) return "objc_protocol_list";
            if (seg_name.find("__objc_selrefs") != std::string::npos) return "objc_selector_refs";
            if (seg_name.find("__objc_msgrefs") != std::string::npos) return "objc_message_refs";
            if (seg_name.find("__objc_classrefs") != std::string::npos) return "objc_class_refs";
            if (seg_name.find("__objc_superrefs") != std::string::npos) return "objc_super_refs";
            if (seg_name.find("__objc_ivar") != std::string::npos) return "objc_ivars";
            if (seg_name.find("__objc_data") != std::string::npos) return "objc_data";
            if (seg_name.find("__objc_const") != std::string::npos) return "objc_const_authenticated";
            if (seg_name.find("__objc_methname") != std::string::npos) return "objc_method_names";
            if (seg_name.find("__objc_classname") != std::string::npos) return "objc_class_names";
            if (seg_name.find("__objc_methtype") != std::string::npos) return "objc_method_types";

            // Swift sections
            if (seg_name.find("__swift5_typeref") != std::string::npos) return "swift_type_refs";
            if (seg_name.find("__swift5_reflstr") != std::string::npos) return "swift_reflection_strings";
            if (seg_name.find("__swift5_fieldmd") != std::string::npos) return "swift_field_metadata";
            if (seg_name.find("__swift5_assocty") != std::string::npos) return "swift_associated_types";
            if (seg_name.find("__swift5_proto") != std::string::npos) return "swift_protocols";
            if (seg_name.find("__swift5_types") != std::string::npos) return "swift_type_metadata";
            if (seg_name.find("__swift5_capture") != std::string::npos) return "swift_capture_descriptors";

            // Common Mach-O sections
            if (seg_name.find("__text") != std::string::npos) return "code";
            if (seg_name.find("__TEXT") != std::string::npos) return "text_segment";
            if (seg_name.find("__stubs") != std::string::npos) return "import_stubs";
            if (seg_name.find("__stub_helper") != std::string::npos) return "stub_helper";
            if (seg_name.find("__cstring") != std::string::npos) return "c_strings";
            if (seg_name.find("__const") != std::string::npos) return "constants";
            if (seg_name.find("__DATA_CONST") != std::string::npos) return "data_const_authenticated";
            if (seg_name.find("__DATA") != std::string::npos) return "data_segment";
            if (seg_name.find("__data") != std::string::npos) return "data";
            if (seg_name.find("__bss") != std::string::npos) return "bss_uninitialized";
            if (seg_name.find("__got") != std::string::npos) return "global_offset_table";
            if (seg_name.find("__la_symbol_ptr") != std::string::npos) return "lazy_symbol_pointers";
            if (seg_name.find("__nl_symbol_ptr") != std::string::npos) return "non_lazy_symbol_pointers";
            if (seg_name.find("__mod_init_func") != std::string::npos) return "module_init_functions";
            if (seg_name.find("__mod_term_func") != std::string::npos) return "module_term_functions";
            if (seg_name.find("__LINKEDIT") != std::string::npos) return "linkedit_metadata";
            if (seg_name.find("__auth_ptr") != std::string::npos) return "authenticated_pointers";
            if (seg_name.find("__auth_got") != std::string::npos) return "authenticated_got";

            return nullptr;
        }

        json handle_get_address_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            // Check if address is valid
            bool is_loaded_addr = ::is_loaded(ea);
            bool is_mapped_addr = ::is_mapped(ea);

            if (!is_loaded_addr && !is_mapped_addr) {
                return json{
                    {"address", format_ea(ea)},
                    {"valid", false},
                    {"mapped", false},
                    {"note", "Address is not within any loaded segment"}
                };
            }

            // Get segment info
            segment_t *seg = getseg(ea);
            qstring seg_name;
            ea_t seg_start = BADADDR;
            ea_t seg_end = BADADDR;
            json permissions;

            if (seg != nullptr) {
                get_segm_name(&seg_name, seg);
                seg_start = seg->start_ea;
                seg_end = seg->end_ea;

                // Get permissions
                bool is_readable = true; // All loaded segments are readable in IDA
                bool is_writable = (seg->perm & SEGPERM_WRITE) != 0;
                bool is_executable = (seg->perm & SEGPERM_EXEC) != 0;

                permissions = json{
                    {"read", is_readable},
                    {"write", is_writable},
                    {"execute", is_executable}
                };
            } else {
                seg_name = "unknown";
                permissions = json::object();
            }

            // Check if address contains code or data
            flags64_t flags = get_flags(ea);
            bool is_code_flag = is_code(flags);
            bool is_data_flag = is_data(flags);

            const char *address_type = "unexplored";
            if (is_code_flag) {
                address_type = "code";
            } else if (is_data_flag) {
                address_type = "data";
            }

            // Segment classification
            bool is_code_seg = (seg != nullptr) && ((seg->perm & SEGPERM_EXEC) != 0);
            bool is_data_seg = (seg != nullptr) && ((seg->perm & SEGPERM_WRITE) != 0);

            json result = json{
                {"address", format_ea(ea)},
                {"valid", is_loaded_addr},
                {"mapped", is_mapped_addr},
                {
                    "segment", {
                        {"name", seg_name.c_str()},
                        {"start", format_ea(seg_start)},
                        {"end", format_ea(seg_end)}
                    }
                },
                {"permissions", permissions},
                {"type", address_type},
                {
                    "segment_classification", {
                        {"code_segment", is_code_seg},
                        {"data_segment", is_data_seg}
                    }
                }
            };

            // Add Mach-O section type classification if applicable
            if (is_macho_binary() && seg != nullptr) {
                std::string seg_name_str = seg_name.c_str();
                const char* section_type = classify_macho_section(seg_name_str);

                if (section_type != nullptr) {
                    json macho_info = json::object();
                    macho_info["section_type"] = section_type;

                    // Add special notes for authenticated pointer sections
                    if (seg_name_str.find("__auth") != std::string::npos ||
                        seg_name_str.find("__objc_const") != std::string::npos ||
                        seg_name_str.find("__DATA_CONST") != std::string::npos) {
                        macho_info["has_authenticated_pointers"] = true;
                        macho_info["requires_pac_stripping"] = true;
                    }

                    // Add runtime detection
                    if (seg_name_str.find("__objc") != std::string::npos) {
                        macho_info["runtime"] = "objective-c";
                    } else if (seg_name_str.find("__swift") != std::string::npos) {
                        macho_info["runtime"] = "swift";
                    }

                    result["macho"] = macho_info;
                }
            }

            // Get source file and line number information (if available)
            range_t source_bounds;
            const char *source_file = get_sourcefile(ea, &source_bounds);
            if (source_file != nullptr && source_file[0] != '\0') {
                json source_info = json::object();
                source_info["file"] = source_file;
                source_info["file_bounds_start"] = format_ea(source_bounds.start_ea);
                source_info["file_bounds_end"] = format_ea(source_bounds.end_ea);

                // Try to get line number using netnode (NALT_LINNUM = 9)
                netnode n(ea);
                uval_t linenum = n.altval(9);  // NALT_LINNUM
                if (linenum != 0) {
                    source_info["line_number"] = static_cast<uint64_t>(linenum);
                }

                result["source_info"] = source_info;
            }

            return result;
        }

        json handle_is_address_valid(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool is_loaded_addr = ::is_loaded(ea);
            bool is_mapped_addr = ::is_mapped(ea);
            bool valid = is_loaded_addr || is_mapped_addr;

            return json{
                {"address", format_ea(ea)},
                {"valid", valid},
                {"loaded", is_loaded_addr},
                {"mapped", is_mapped_addr}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_address_info
        {
            mcp::ToolDefinition def;
            def.name = "get_address_info";
            def.description = "Get address info and permissions";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_address_info);
        }

        // is_address_valid
        {
            mcp::ToolDefinition def;
            def.name = "is_address_valid";
            def.description = "Check if address is valid";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_is_address_valid);
        }
    }
} // namespace ida_mcp::tools::memory
