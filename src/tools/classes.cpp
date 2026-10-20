// Language-level class model of Hex-Rays 9.5 (Java/Kotlin/Go/Rust/Swift...):
// what the Classes view shows. hexrays.hpp:9249-9394.

#include "tools/tools.hpp"

#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#include <lines.hpp>
#endif

namespace ida_mcp::tools::classes {
#ifdef HAS_HEXRAYS
    namespace {
        const char *kind_name(class_kind_t kind) {
            switch (kind) {
                case CK_CLASS: return "class";
                case CK_STRUCT: return "struct";
                case CK_INTERFACE: return "interface";
                case CK_ENUM: return "enum";
                case CK_UNION: return "union";
                case CK_ANNOTATION: return "annotation";
            }
            return "unknown";
        }

        json flag_names(uint32 flags) {
            static const std::pair<uint32, const char *> names[] = {
                {CLF_PUBLIC, "public"}, {CLF_PROTECTED, "protected"}, {CLF_PRIVATE, "private"},
                {CLF_INTERNAL, "internal"}, {CLF_STATIC, "static"}, {CLF_FINAL, "final"},
                {CLF_ABSTRACT, "abstract"}, {CLF_SYNTHETIC, "synthetic"}, {CLF_EXTERNAL, "external"},
                {CLF_HIDDEN, "hidden"}, {CLF_METHOD, "method"}, {CLF_CTOR, "ctor"},
                {CLF_CLASS_INIT, "class_init"}, {CLF_ENUM_CONST, "enum_const"},
            };
            json out = json::array();
            for (const auto &[bit, name]: names)
                if ((flags & bit) != 0)
                    out.push_back(name);
            return out;
        }

        json type_text(const tinfo_t &tif) {
            qstring out;
            if (tif.empty() || !tif.print(&out))
                return nullptr;
            return out.c_str();
        }

        json ea_json(ea_t ea) {
            return ea == BADADDR ? json(nullptr) : json(format_ea(ea));
        }

        json lines_json(const qstrvec_t &lines) {
            json out = json::array();
            for (const qstring &line: lines)
                out.push_back(line.c_str());
            return out;
        }

        json class_json(const class_t &cls) {
            return json{
                {"name", cls.name.c_str()},
                {"outer", cls.outer.empty() ? json(nullptr) : json(cls.outer.c_str())},
                {"kind", kind_name(cls.kind)},
                {"ea", ea_json(cls.ea)},
                {"flags", flag_names(cls.flags)},
                {"type", type_text(cls.tif)}
            };
        }

        json member_json(const class_member_t &m) {
            json out = {
                {"name", m.name.c_str()},
                {"ea", ea_json(m.ea)},
                {"flags", flag_names(m.flags)},
                {"type", type_text(m.type)}
            };
            if (!m.typestr.empty()) out["typestr"] = m.typestr.c_str();
            if (!m.value.empty()) out["value"] = m.value.c_str();
            if (!m.decl.empty()) out["decl"] = m.decl.c_str();
            if (!m.attrs.empty()) out["attrs"] = lines_json(m.attrs);
            return out;
        }

        void require_hexrays() {
            if (!init_hexrays_plugin())
                throw std::runtime_error("Hexrays decompiler not available (check license)");
        }

        const char *const no_class_model =
            "No class model: Hex-Rays reports none for this database's processor or language "
            "(the class model covers Java/Kotlin/Go/Rust/Swift programs)";

        bool bool_param(const json &params, const char *key, bool fallback) {
            return params.contains(key) && params[key].is_boolean() ? params[key].get<bool>() : fallback;
        }

        std::optional<ea_t> optional_ea(const json &params, const char *key) {
            if (!params.contains(key))
                return std::nullopt;
            if (!params[key].is_string())
                throw std::runtime_error(std::string(key) + " must be a hex address string");
            auto ea = parse_ea(params[key].get<std::string>());
            if (!ea)
                throw std::runtime_error(std::string("Invalid address in ") + key);
            return ea;
        }
    }

    static json list_classes(const json &params) {
        require_hexrays();
        class_filter_t filter;
        if (params.contains("name") && params["name"].is_string())
            filter.name = params["name"].get<std::string>().c_str();
        if (auto ea = optional_ea(params, "member_address"))
            filter.ea = *ea;
        if (bool_param(params, "toplevel_only", false))
            filter.flags |= GCL_TOPLEVEL_ONLY;
        if (bool_param(params, "include_hidden", false))
            filter.flags |= GCL_INCLUDE_HIDDEN;

        classes_t found;
        if (!get_classes(&found, &filter))
            throw std::runtime_error(no_class_model);

        const int64 offset = std::max<int64>(0, params.value("offset", int64(0)));
        const int64 count = std::max<int64>(1, params.value("count", int64(100)));
        const auto total = static_cast<int64>(found.size());
        const int64 end = std::min(total, offset + count);

        json items = json::array();
        for (int64 i = offset; i < end; ++i)
            items.push_back(class_json(found[static_cast<size_t>(i)]));
        return json{
            {"total", total},
            {"offset", offset},
            {"classes", items},
            {"next_offset", end < total ? json(end) : json(nullptr)}
        };
    }

    static json get_class(const json &params) {
        require_hexrays();
        if (!params.contains("name") || !params["name"].is_string())
            throw std::runtime_error("Missing required parameter: name");
        class_t cls;
        cls.name = params["name"].get<std::string>().c_str();
        if (auto ea = optional_ea(params, "ea"))
            cls.ea = *ea;

        class_info_t info;
        if (!get_class_info(&info, cls, bool_param(params, "text", true) ? 0 : GCI_NO_TEXT)) {
            // get_class_info() fails both for an unknown class and without a
            // class model; get_classes() tells the two apart.
            classes_t unused;
            if (!get_classes(&unused))
                throw std::runtime_error(no_class_model);
            throw std::runtime_error("Class not found: " + params["name"].get<std::string>());
        }

        json fields = json::array();
        for (const class_member_t &m: info.fields)
            fields.push_back(member_json(m));
        json methods = json::array();
        for (const class_member_t &m: info.methods)
            methods.push_back(member_json(m));

        json result = class_json(info.cls);
        result["source_file"] = info.source_file.empty() ? json(nullptr) : json(info.source_file.c_str());
        result["type_params"] = info.type_params.empty() ? json(nullptr) : json(info.type_params.c_str());
        result["enclosing_method"] = info.enclosing_method.empty() ? json(nullptr) : json(info.enclosing_method.c_str());
        result["supertypes"] = lines_json(info.supertypes);
        result["interfaces"] = lines_json(info.interfaces);
        result["attrs"] = lines_json(info.attrs);
        result["nested"] = lines_json(info.nested);
        result["decl"] = lines_json(info.decl);
        result["fields"] = fields;
        result["methods"] = methods;

        if (bool_param(params, "render", false)) {
            int flags = 0;
            if (!bool_param(params, "bodies", false)) flags |= RCF_NO_BODIES;
            if (!bool_param(params, "nested", true)) flags |= RCF_NO_NESTED;
            if (!bool_param(params, "attrs", true)) flags |= RCF_NO_ATTRS;
            qstrvec_t lines;
            if (!render_class(&lines, info.cls, flags))
                throw std::runtime_error("render_class refused the class (hidden classes are not rendered)");
            qstring text;
            for (size_t i = 0; i < lines.size(); ++i) {
                if (i > 0) text.append('\n');
                qstring clean;
                tag_remove(&clean, lines[i]);
                text.append(clean);
            }
            result["rendered"] = text.c_str();
        }
        return result;
    }
#endif

    void register_tools(mcp::McpServer &server) {
#ifdef HAS_HEXRAYS
        {
            mcp::ToolDefinition def;
            def.name = "list_classes";
            def.description = "List the program's language-level classes as the Hex-Rays Classes view "
                    "shows them (Java/Kotlin/Go/Rust/Swift). Errors if there is no class model.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"name", {{"type", "string"}, {"description", "Wildcard (* ?) on the fully qualified name"}}},
                    {"member_address", {{"type", "string"}, {"description", "Only the class with a member (method or static field) at this hex address"}}},
                    {"toplevel_only", {{"type", "boolean"}, {"default", false}}},
                    {"include_hidden", {{"type", "boolean"}, {"default", false}}},
                    {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0}}},
                    {"count", {{"type", "integer"}, {"minimum", 1}, {"default", 100}}}
                }}
            };
            server.register_tool(def, list_classes);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_class";
            def.description = "Get one class from the Hex-Rays class model: supertypes, interfaces, "
                    "fields and methods (with addresses and types), optionally rendered as the class view shows it.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"name", {{"type", "string"}, {"description", "Fully qualified class name"}}},
                    {"ea", {{"type", "string"}, {"description", "Class metadata address; disambiguates duplicate names"}}},
                    {"text", {{"type", "boolean"}, {"default", true}, {"description", "Include declaration, attribute and value text"}}},
                    {"render", {{"type", "boolean"}, {"default", false}, {"description", "Add the class rendered as source text"}}},
                    {"bodies", {{"type", "boolean"}, {"default", false}, {"description", "render: decompile method bodies (slow)"}}},
                    {"nested", {{"type", "boolean"}, {"default", true}, {"description", "render: include nested classes"}}},
                    {"attrs", {{"type", "boolean"}, {"default", true}, {"description", "render: include attribute lines"}}}
                }},
                {"required", json::array({"name"})}
            };
            server.register_tool(def, get_class);
        }
#else
        (void)server;
#endif
    }
} // namespace ida_mcp::tools::classes
