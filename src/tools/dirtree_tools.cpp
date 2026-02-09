#include "tools/tools.hpp"
#include <dirtree.hpp>

namespace ida_mcp::tools::dirtree_tools {
    namespace {
        dirtree_t *resolve_tree(const std::string &tree_name) {
            dirtree_id_t id = DIRTREE_END;
            if (tree_name == "funcs" || tree_name == "functions")
                id = DIRTREE_FUNCS;
            else if (tree_name == "names")
                id = DIRTREE_NAMES;
            else if (tree_name == "imports")
                id = DIRTREE_IMPORTS;
            else if (tree_name == "local_types" || tree_name == "ltypes")
                id = DIRTREE_LOCAL_TYPES;
            else if (tree_name == "bookmarks")
                id = DIRTREE_IDAPLACE_BOOKMARKS;
            else if (tree_name == "bpts" || tree_name == "breakpoints")
                id = DIRTREE_BPTS;
            else
                throw std::runtime_error("Unknown dirtree: " + tree_name +
                                         ". Valid: funcs, names, imports, local_types, bookmarks, bpts");

            dirtree_t *dt = get_std_dirtree(id);
            if (dt == nullptr)
                throw std::runtime_error("Dirtree not available: " + tree_name);
            return dt;
        }

        static json list_directory(const json &params) {
            if (!params.contains("tree") || !params["tree"].is_string())
                throw std::runtime_error("Missing required parameter: tree");

            dirtree_t *dt = resolve_tree(params["tree"].get<std::string>());

            std::string path = "/";
            if (params.contains("path") && params["path"].is_string())
                path = params["path"].get<std::string>();

            direntry_t de = dt->resolve_path(path.c_str());
            if (!de.valid() || !de.isdir)
                throw std::runtime_error("Path not found or not a directory: " + path);

            ssize_t count = dt->get_dir_size(de.idx);

            json entries = json::array();
            dirtree_iterator_t it;
            std::string pattern = (path == "/") ? "/*" : (path + "/*");
            if (dt->findfirst(&it, pattern.c_str())) {
                do {
                    direntry_t cur_de = dt->resolve_cursor(it.cursor);
                    if (!cur_de.valid())
                        continue;
                    json entry;
                    qstring name = dt->get_entry_name(cur_de, DTN_DISPLAY_NAME);
                    entry["name"] = name.c_str();
                    entry["is_dir"] = cur_de.isdir;
                    if (!cur_de.isdir)
                        entry["inode"] = static_cast<uint64_t>(cur_de.idx);
                    else
                        entry["dir_index"] = static_cast<uint64_t>(cur_de.idx);
                    entries.push_back(entry);
                } while (dt->findnext(&it));
            }

            return json{
                {"path", path},
                {"entry_count", count},
                {"entries", entries}
            };
        }

        static json make_directory(const json &params) {
            if (!params.contains("tree") || !params["tree"].is_string())
                throw std::runtime_error("Missing required parameter: tree");
            if (!params.contains("path") || !params["path"].is_string())
                throw std::runtime_error("Missing required parameter: path");

            dirtree_t *dt = resolve_tree(params["tree"].get<std::string>());
            dterr_t err = dt->mkdir(params["path"].get<std::string>().c_str());
            if (err != DTE_OK)
                throw std::runtime_error(std::string("mkdir failed: ") + dirtree_t::errstr(err));

            return json{{"created", params["path"]}};
        }

        static json remove_directory(const json &params) {
            if (!params.contains("tree") || !params["tree"].is_string())
                throw std::runtime_error("Missing required parameter: tree");
            if (!params.contains("path") || !params["path"].is_string())
                throw std::runtime_error("Missing required parameter: path");

            dirtree_t *dt = resolve_tree(params["tree"].get<std::string>());
            dterr_t err = dt->rmdir(params["path"].get<std::string>().c_str());
            if (err != DTE_OK)
                throw std::runtime_error(std::string("rmdir failed: ") + dirtree_t::errstr(err));

            return json{{"removed", params["path"]}};
        }

        static json rename_entry(const json &params) {
            if (!params.contains("tree") || !params["tree"].is_string())
                throw std::runtime_error("Missing required parameter: tree");
            if (!params.contains("from") || !params["from"].is_string())
                throw std::runtime_error("Missing required parameter: from");
            if (!params.contains("to") || !params["to"].is_string())
                throw std::runtime_error("Missing required parameter: to");

            dirtree_t *dt = resolve_tree(params["tree"].get<std::string>());
            dterr_t err = dt->rename(
                params["from"].get<std::string>().c_str(),
                params["to"].get<std::string>().c_str());
            if (err != DTE_OK)
                throw std::runtime_error(std::string("rename failed: ") + dirtree_t::errstr(err));

            return json{{"from", params["from"]}, {"to", params["to"]}};
        }

        static json move_entry(const json &params) {
            if (!params.contains("tree") || !params["tree"].is_string())
                throw std::runtime_error("Missing required parameter: tree");
            if (!params.contains("path") || !params["path"].is_string())
                throw std::runtime_error("Missing required parameter: path");

            dirtree_t *dt = resolve_tree(params["tree"].get<std::string>());
            const char *p = params["path"].get<std::string>().c_str();
            bool do_unlink = params.contains("unlink") && params["unlink"].is_boolean() && params["unlink"].get<bool>();

            dterr_t err = do_unlink ? dt->unlink(p) : dt->link(p);
            if (err != DTE_OK)
                throw std::runtime_error(std::string("link/unlink failed: ") + dirtree_t::errstr(err));

            return json{{"path", params["path"]}, {"linked", !do_unlink}};
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "dirtree_list";
            def.description =
                    "List entries in an IDA directory tree folder. Trees: funcs, names, imports, local_types, bookmarks, bpts";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "tree",
                            {
                                {"type", "string"},
                                {"description", "Tree name: funcs, names, imports, local_types, bookmarks, bpts"}
                            }
                        },
                        {"path", {{"type", "string"}, {"description", "Directory path (default: /)"}}}
                    }
                },
                {"required", json::array({"tree"})}
            };
            server.register_tool(def, list_directory);
        } {
            mcp::ToolDefinition def;
            def.name = "dirtree_mkdir";
            def.description = "Create a new folder in an IDA directory tree";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"tree", {{"type", "string"}, {"description", "Tree name"}}},
                        {"path", {{"type", "string"}, {"description", "Folder path to create"}}}
                    }
                },
                {"required", json::array({"tree", "path"})}
            };
            server.register_tool(def, make_directory);
        } {
            mcp::ToolDefinition def;
            def.name = "dirtree_rmdir";
            def.description = "Remove a folder from an IDA directory tree";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"tree", {{"type", "string"}, {"description", "Tree name"}}},
                        {"path", {{"type", "string"}, {"description", "Folder path to remove"}}}
                    }
                },
                {"required", json::array({"tree", "path"})}
            };
            server.register_tool(def, remove_directory);
        } {
            mcp::ToolDefinition def;
            def.name = "dirtree_rename";
            def.description = "Rename an entry in an IDA directory tree";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"tree", {{"type", "string"}, {"description", "Tree name"}}},
                        {"from", {{"type", "string"}, {"description", "Current path"}}},
                        {"to", {{"type", "string"}, {"description", "New path"}}}
                    }
                },
                {"required", json::array({"tree", "from", "to"})}
            };
            server.register_tool(def, rename_entry);
        } {
            mcp::ToolDefinition def;
            def.name = "dirtree_move";
            def.description = "Link or unlink an entry in an IDA directory tree (move into/out of folders)";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"tree", {{"type", "string"}, {"description", "Tree name"}}},
                        {"path", {{"type", "string"}, {"description", "Entry path"}}},
                        {
                            "unlink",
                            {
                                {"type", "boolean"},
                                {"description", "If true, unlink from folder. Default: false (link/add)"}
                            }
                        }
                    }
                },
                {"required", json::array({"tree", "path"})}
            };
            server.register_tool(def, move_entry);
        }
    }
}
