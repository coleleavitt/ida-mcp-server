#include "tools/tools.hpp"
#include <segment.hpp>
#include <ida.hpp>
#include <loader.hpp>

namespace ida_mcp::tools::segments {
    namespace {
        // Helper: Check if this is a Mach-O binary
        bool is_macho_binary() {
            return inf_get_filetype() == f_MACHO;
        }

        // Helper: Check if segment name suggests Mach-O sections (starts with __)
        bool likely_has_sections(const std::string& seg_name) {
            return seg_name.find("__") == 0 || seg_name == "__TEXT" ||
                   seg_name == "__DATA" || seg_name == "__DATA_CONST" ||
                   seg_name == "__LINKEDIT" || seg_name == "__OBJC";
        }

        // Helper: Parse Mach-O section information from segment
        json enumerate_macho_sections(segment_t *seg) {
            json sections = json::array();

            // For Mach-O, sections are often encoded in segment comments or can be
            // detected by parsing the actual Mach-O structure. Since we don't have
            // direct API access, we'll identify common iOS/macOS section patterns
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            std::string seg_name_str = seg_name.c_str();

            // Common Mach-O section patterns to detect
            struct section_pattern {
                const char* segment;
                const char* section;
                const char* description;
            };

            const section_pattern objc_sections[] = {
                {"__DATA", "__objc_classlist", "Objective-C class list"},
                {"__DATA", "__objc_catlist", "Objective-C category list"},
                {"__DATA", "__objc_protolist", "Objective-C protocol list"},
                {"__DATA", "__objc_selrefs", "Objective-C selector references"},
                {"__DATA", "__objc_msgrefs", "Objective-C message references"},
                {"__DATA", "__objc_classrefs", "Objective-C class references"},
                {"__DATA", "__objc_superrefs", "Objective-C super references"},
                {"__DATA", "__objc_ivar", "Objective-C instance variables"},
                {"__DATA", "__objc_data", "Objective-C data"},
                {"__DATA_CONST", "__objc_const", "Objective-C constants (authenticated pointers)"},
                {"__TEXT", "__objc_methname", "Objective-C method names"},
                {"__TEXT", "__objc_classname", "Objective-C class names"},
                {"__TEXT", "__objc_methtype", "Objective-C method types"},
                {nullptr, nullptr, nullptr}
            };

            const section_pattern swift_sections[] = {
                {"__TEXT", "__swift5_typeref", "Swift type references"},
                {"__TEXT", "__swift5_reflstr", "Swift reflection strings"},
                {"__TEXT", "__swift5_fieldmd", "Swift field metadata"},
                {"__TEXT", "__swift5_assocty", "Swift associated types"},
                {"__TEXT", "__swift5_proto", "Swift protocols"},
                {"__TEXT", "__swift5_types", "Swift type metadata"},
                {"__DATA", "__swift5_capture", "Swift capture descriptors"},
                {nullptr, nullptr, nullptr}
            };

            // Try to find matching sections by checking if subsegments exist
            for (const auto* patterns : {objc_sections, swift_sections}) {
                for (int i = 0; patterns[i].segment != nullptr; i++) {
                    if (seg_name_str.find(patterns[i].segment) != std::string::npos) {
                        // Try to find this section name as a segment
                        qstring section_fullname;
                        section_fullname = patterns[i].segment;
                        section_fullname += ",";
                        section_fullname += patterns[i].section;

                        segment_t *section_seg = get_segm_by_name(section_fullname.c_str());
                        if (section_seg != nullptr) {
                            sections.push_back(json{
                                {"section_name", patterns[i].section},
                                {"description", patterns[i].description},
                                {"start", format_ea(section_seg->start_ea)},
                                {"end", format_ea(section_seg->end_ea)},
                                {"size", section_seg->end_ea - section_seg->start_ea}
                            });
                        }
                    }
                }
            }

            return sections;
        }
    } // anonymous namespace

    // List all memory segments in the binary
    static json list_segments(const json &params) {
        json segs = json::array();
        bool is_macho = is_macho_binary();

        segment_t *seg = get_first_seg();
        while (seg != nullptr) {
            ea_t start = seg->start_ea;
            ea_t end = seg->end_ea;

            // Get segment name
            qstring name;
            std::string name_str;
            if (get_segm_name(&name, seg) > 0) {
                name_str = name.c_str();
            } else {
                qstring formatted_name;
                formatted_name.sprnt("seg_%llX", static_cast<uint64>(start));
                name_str = formatted_name.c_str();
            }

            json seg_info = json{
                {"name", name_str},
                {"start", format_ea(start)},
                {"end", format_ea(end)},
                {"size", end - start},
                {"perm_r", (seg->perm & SEGPERM_READ) != 0},
                {"perm_w", (seg->perm & SEGPERM_WRITE) != 0},
                {"perm_x", (seg->perm & SEGPERM_EXEC) != 0}
            };

            // Add Mach-O section information if applicable
            if (is_macho && likely_has_sections(name_str)) {
                json sections = enumerate_macho_sections(seg);
                if (!sections.empty()) {
                    seg_info["macho_sections"] = sections;
                    seg_info["is_macho_segment"] = true;
                }
            }

            segs.push_back(seg_info);
            seg = get_next_seg(end);
        }

        json result = json{
            {"segments", segs},
            {"total_segments", segs.size()}
        };

        if (is_macho) {
            result["is_macho"] = true;
        }

        return result;
    }

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "list_segments";
        def.description = "List memory segments";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()}
        };
        server.register_tool(def, list_segments);
    }
} // namespace ida_mcp::tools::segments
