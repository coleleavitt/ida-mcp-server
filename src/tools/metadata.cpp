#include "tools/tools.hpp"
#include <ida.hpp>
#include <loader.hpp>
#include <segment.hpp>

namespace ida_mcp::tools::metadata {
    namespace {
        const char *compiler_id_to_name(comp_t comp_id) {
            switch (comp_id) {
                case COMP_UNK: return "Unknown";
                case COMP_MS: return "Microsoft Visual C++";
                case COMP_BC: return "Borland C++";
                case COMP_WATCOM: return "Watcom C/C++";
                case COMP_GNU: return "GNU C/C++";
                case COMP_VISAGE: return "Visual Age C++";
                case COMP_BP: return "Delphi";
                default: return "Other/Unknown";
            }
        }

        const char *filetype_to_name(filetype_t ft) {
            switch (ft) {
                case f_EXE_old: return "MS DOS EXE";
                case f_COM_old: return "MS DOS COM";
                case f_BIN: return "Binary";
                case f_DRV: return "MS DOS driver";
                case f_WIN: return "New Executable (NE)";
                case f_HEX: return "Intel Hex Object";
                case f_MEX: return "MOS Technology Hex Object";
                case f_LX: return "Linear Executable (LX)";
                case f_LE: return "Linear Executable (LE)";
                case f_NLM: return "Netware Loadable Module (NLM)";
                case f_COFF: return "Common Object File Format (COFF)";
                case f_PE: return "Portable Executable (PE)";
                case f_OMF: return "Object Module Format (OMF)";
                case f_SREC: return "R-records";
                case f_ZIP: return "ZIP file";
                case f_OMFLIB: return "Library of OMF Modules";
                case f_AR: return "ar library";
                case f_LOADER: return "file is loaded using LOADER DLL";
                case f_ELF: return "Executable and Linkable Format (ELF)";
                case f_W32RUN: return "Watcom DOS32 Extender (W32RUN)";
                case f_AOUT: return "Linux a.out (AOUT)";
                case f_PRC: return "PalmPilot program file";
                case f_EXE: return "MS DOS EXE";
                case f_COM: return "MS DOS COM";
                case f_AIXAR: return "AIX ar library";
                case f_MACHO: return "Mac OS X (Mach-O)";
                default: return "Unknown file type";
            }
        }

        json handle_get_binary_metadata(const json &params) {
            // Get processor/architecture name
            qstring procname = inf_get_procname();

            // Get file type
            filetype_t filetype = inf_get_filetype();
            const char *filetype_name = filetype_to_name(filetype);

            // Get compiler info
            comp_t comp_id = inf_get_cc_id();
            const char *compiler_name = compiler_id_to_name(comp_id);

            // Get bitness
            int bitness = inf_is_64bit() ? 64 : (inf_is_32bit_or_higher() ? 32 : 16);

            // Get byte order
            bool is_be = inf_is_be();

            // Get start address
            ea_t start_ea = inf_get_start_ea();

            // Get min/max addresses
            ea_t min_ea = inf_get_min_ea();
            ea_t max_ea = inf_get_max_ea();

            json result = json{
                {"processor", procname.c_str()},
                {"filetype", filetype_name},
                {"filetype_id", static_cast<int>(filetype)},
                {"compiler", compiler_name},
                {"compiler_id", static_cast<int>(comp_id)},
                {"bitness", bitness},
                {"is_64bit", inf_is_64bit()},
                {"is_32bit", inf_is_32bit_or_higher()},
                {"is_big_endian", is_be},
                {"start_address", format_ea(start_ea)},
                {"min_address", format_ea(min_ea)},
                {"max_address", format_ea(max_ea)}
            };

            // Add ARM-specific information if this is an ARM binary
            std::string proc_str = procname.c_str();
            if (proc_str.find("ARM") != std::string::npos ||
                proc_str.find("arm") != std::string::npos ||
                proc_str.find("AARCH64") != std::string::npos ||
                proc_str.find("aarch64") != std::string::npos) {

                json arm_info = json::object();

                // Detect ARM64 vs ARM32
                bool is_arm64 = inf_is_64bit() || proc_str.find("64") != std::string::npos ||
                               proc_str.find("AARCH64") != std::string::npos;
                arm_info["is_arm64"] = is_arm64;
                arm_info["is_arm32"] = !is_arm64;

                if (is_arm64) {
                    // ARM64-specific features
                    arm_info["supports_pac"] = true;  // ARM64E pointer authentication
                    arm_info["supports_bti"] = true;  // Branch Target Identification
                    arm_info["supports_mte"] = true;  // Memory Tagging Extension
                    arm_info["supports_atomics"] = true; // LSE atomics
                    arm_info["architecture"] = "ARMv8-A or later";
                } else {
                    arm_info["architecture"] = "ARMv7 or earlier";
                }

                result["arm"] = arm_info;
            }

            // Add Mach-O specific information if this is a Mach-O binary
            if (filetype == f_MACHO) {
                json macho_info = json::object();
                macho_info["is_macho"] = true;

                // Detect platform by checking segment names
                segment_t *seg = get_first_seg();
                bool has_linkedit = false;
                bool has_data_const = false;
                bool has_objc = false;
                bool has_swift = false;
                bool has_function_starts = false;
                bool has_data_in_code = false;
                bool has_encrypted = false;

                // Count text segments without execute permission (potential encryption)
                int text_segments_no_exec = 0;

                while (seg != nullptr) {
                    qstring seg_name;
                    if (get_segm_name(&seg_name, seg) > 0) {
                        std::string name_str = seg_name.c_str();
                        if (name_str.find("__LINKEDIT") != std::string::npos) has_linkedit = true;
                        if (name_str.find("__DATA_CONST") != std::string::npos) has_data_const = true;
                        if (name_str.find("__objc") != std::string::npos) has_objc = true;
                        if (name_str.find("__swift") != std::string::npos) has_swift = true;

                        // Detect encrypted segments: __TEXT without execute permission
                        if (name_str.find("__TEXT") != std::string::npos) {
                            if ((seg->perm & SEGPERM_EXEC) == 0) {
                                text_segments_no_exec++;
                                has_encrypted = true;
                            }
                        }

                        // Detect function starts: presence of __LINKEDIT suggests load commands
                        // (LC_FUNCTION_STARTS data is stored in __LINKEDIT)
                        if (name_str.find("__LINKEDIT") != std::string::npos && seg->size() > 0) {
                            has_function_starts = true;
                        }

                        // Detect data-in-code: check for __DATA_CONST or __const sections
                        if (name_str.find("__const") != std::string::npos ||
                            name_str.find("__DATA_CONST") != std::string::npos) {
                            has_data_in_code = true;
                        }
                    }
                    seg = get_next_seg(seg->end_ea);
                }

                macho_info["has_linkedit"] = has_linkedit;
                macho_info["has_data_const"] = has_data_const;  // Indicates modern Mach-O
                macho_info["has_objc_sections"] = has_objc;
                macho_info["has_swift_sections"] = has_swift;

                // LC_FUNCTION_STARTS detection (heuristic: __LINKEDIT present)
                if (has_function_starts) {
                    macho_info["likely_has_function_starts"] = true;
                    macho_info["function_starts_info"] = "LC_FUNCTION_STARTS likely present (__LINKEDIT found)";
                }

                // LC_DATA_IN_CODE detection (heuristic: const sections)
                if (has_data_in_code) {
                    macho_info["likely_has_data_in_code"] = true;
                    macho_info["data_in_code_info"] = "LC_DATA_IN_CODE likely present (const sections found)";
                }

                // Encrypted segment detection
                if (has_encrypted) {
                    macho_info["has_encrypted_segments"] = true;
                    macho_info["encrypted_text_segments"] = text_segments_no_exec;
                    macho_info["encryption_info"] = "Binary may be encrypted (cryptid != 0)";
                }

                // __DATA_CONST suggests iOS 13+ or macOS 10.15+ with hardened runtime
                if (has_data_const) {
                    macho_info["likely_hardened_runtime"] = true;
                }

                // Detect if likely iOS vs macOS by segment patterns
                if (has_objc || has_swift) {
                    macho_info["likely_platform"] = "iOS/macOS/tvOS (Objective-C/Swift runtime)";
                }

                result["macho"] = macho_info;
            }

            return result;
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "get_binary_metadata";
        def.description = "Get binary metadata";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()}
        };

        server.register_tool(def, handle_get_binary_metadata);
    }
} // namespace ida_mcp::tools::metadata
