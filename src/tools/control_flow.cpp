#include "tools/tools.hpp"
#include <gdl.hpp>
#include <funcs.hpp>
#include <queue>
#include <set>
#include <algorithm>

namespace ida_mcp::tools::control_flow {
    namespace {
        // Convert block type to string
        const char *block_type_to_string(fc_block_type_t type) {
            switch (type) {
                case fcb_normal: return "normal";
                case fcb_indjump: return "indirect_jump";
                case fcb_ret: return "return";
                case fcb_cndret: return "conditional_return";
                case fcb_noret: return "noreturn";
                case fcb_enoret: return "external_noreturn";
                case fcb_extern: return "external";
                case fcb_error: return "error";
                default: return "unknown";
            }
        }

        // Get function flowchart with basic blocks
        json get_function_flowchart(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            // Build flowchart
            int flags = 0;
            if (params.contains("no_external_blocks") && params["no_external_blocks"].get<bool>()) {
                flags |= FC_NOEXT;
            }
            if (params.contains("call_ends_block") && params["call_ends_block"].get<bool>()) {
                flags |= FC_CALL_ENDS;
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, flags);

            json result;
            result["function_start"] = format_ea(pfn->start_ea);
            result["function_end"] = format_ea(pfn->end_ea);
            result["block_count"] = qfc.size();
            result["proper_blocks"] = qfc.nproper;

            // Build blocks array
            json blocks = json::array();
            for (int i = 0; i < qfc.size(); i++) {
                const qbasic_block_t &bb = qfc.blocks[i];
                fc_block_type_t btype = qfc.calc_block_type(i);

                json block;
                block["id"] = i;
                block["start_ea"] = format_ea(bb.start_ea);
                block["end_ea"] = format_ea(bb.end_ea);
                block["size"] = bb.size();
                block["type"] = block_type_to_string(btype);
                block["is_return"] = qfc.is_ret_block(i);
                block["is_noreturn"] = qfc.is_noret_block(i);

                // Successors
                json succs = json::array();
                for (int j = 0; j < qfc.nsucc(i); j++) {
                    succs.push_back(qfc.succ(i, j));
                }
                block["successors"] = succs;
                block["successor_count"] = qfc.nsucc(i);

                // Predecessors
                json preds = json::array();
                for (int j = 0; j < qfc.npred(i); j++) {
                    preds.push_back(qfc.pred(i, j));
                }
                block["predecessors"] = preds;
                block["predecessor_count"] = qfc.npred(i);

                blocks.push_back(block);
            }

            result["blocks"] = blocks;

            return result;
        }

        // Get basic block containing an address
        json get_basic_block_at(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

            // Find the block containing this address
            int block_id = -1;
            for (int i = 0; i < qfc.size(); i++) {
                const qbasic_block_t &bb = qfc.blocks[i];
                if (bb.contains(ea)) {
                    block_id = i;
                    break;
                }
            }

            if (block_id == -1) {
                return json{
                    {"found", false},
                    {"address", format_ea(ea)}
                };
            }

            const qbasic_block_t &bb = qfc.blocks[block_id];
            fc_block_type_t btype = qfc.calc_block_type(block_id);

            json result;
            result["found"] = true;
            result["address"] = format_ea(ea);
            result["block_id"] = block_id;
            result["start_ea"] = format_ea(bb.start_ea);
            result["end_ea"] = format_ea(bb.end_ea);
            result["size"] = bb.size();
            result["type"] = block_type_to_string(btype);
            result["is_return"] = qfc.is_ret_block(block_id);
            result["is_noreturn"] = qfc.is_noret_block(block_id);

            // Successors
            json succs = json::array();
            for (int j = 0; j < qfc.nsucc(block_id); j++) {
                int succ_id = qfc.succ(block_id, j);
                const qbasic_block_t &succ_bb = qfc.blocks[succ_id];
                json succ;
                succ["id"] = succ_id;
                succ["start_ea"] = format_ea(succ_bb.start_ea);
                succ["end_ea"] = format_ea(succ_bb.end_ea);
                succs.push_back(succ);
            }
            result["successors"] = succs;

            // Predecessors
            json preds = json::array();
            for (int j = 0; j < qfc.npred(block_id); j++) {
                int pred_id = qfc.pred(block_id, j);
                const qbasic_block_t &pred_bb = qfc.blocks[pred_id];
                json pred;
                pred["id"] = pred_id;
                pred["start_ea"] = format_ea(pred_bb.start_ea);
                pred["end_ea"] = format_ea(pred_bb.end_ea);
                preds.push_back(pred);
            }
            result["predecessors"] = preds;

            return result;
        }

        // Find all paths between two blocks
        json find_block_paths(const json &params) {
            auto ea_opt = parse_ea(params["function_address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            int from_block = params["from_block"].get<int>();
            int to_block = params["to_block"].get<int>();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

            if (from_block < 0 || from_block >= qfc.size() ||
                to_block < 0 || to_block >= qfc.size()) {
                throw std::runtime_error("Invalid block IDs");
            }

            // Simple DFS to find all paths
            json paths = json::array();
            std::vector<int> current_path;
            std::vector<bool> visited(qfc.size(), false);

            std::function<void(int)> dfs = [&](int node) {
                current_path.push_back(node);
                visited[node] = true;

                if (node == to_block) {
                    // Found a path
                    json path = json::array();
                    for (int block_id: current_path) {
                        const qbasic_block_t &bb = qfc.blocks[block_id];
                        json block_info;
                        block_info["id"] = block_id;
                        block_info["start_ea"] = format_ea(bb.start_ea);
                        block_info["end_ea"] = format_ea(bb.end_ea);
                        path.push_back(block_info);
                    }
                    paths.push_back(path);
                } else {
                    // Continue search
                    for (int i = 0; i < qfc.nsucc(node); i++) {
                        int succ = qfc.succ(node, i);
                        if (!visited[succ]) {
                            dfs(succ);
                        }
                    }
                }

                current_path.pop_back();
                visited[node] = false;
            };

            dfs(from_block);

            return json{
                {"from_block", from_block},
                {"to_block", to_block},
                {"path_count", paths.size()},
                {"paths", paths}
            };
        }

        // Check if a block is reachable from another
        json is_block_reachable(const json &params) {
            auto ea_opt = parse_ea(params["function_address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            int from_block = params["from_block"].get<int>();
            int to_block = params["to_block"].get<int>();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

            if (from_block < 0 || from_block >= qfc.size() ||
                to_block < 0 || to_block >= qfc.size()) {
                throw std::runtime_error("Invalid block IDs");
            }

            // BFS to check reachability
            std::vector<bool> visited(qfc.size(), false);
            std::queue<int> queue;
            queue.push(from_block);
            visited[from_block] = true;

            bool reachable = false;
            int distance = -1;

            while (!queue.empty() && !reachable) {
                auto level_size = static_cast<int>(queue.size());
                distance++;

                for (int i = 0; i < level_size; i++) {
                    int node = queue.front();
                    queue.pop();

                    if (node == to_block) {
                        reachable = true;
                        break;
                    }

                    for (int j = 0; j < qfc.nsucc(node); j++) {
                        int succ = qfc.succ(node, j);
                        if (!visited[succ]) {
                            visited[succ] = true;
                            queue.push(succ);
                        }
                    }
                }
            }

            return json{
                {"from_block", from_block},
                {"to_block", to_block},
                {"reachable", reachable},
                {"distance", reachable ? distance : -1}
            };
        }

        // Get entry and exit blocks
        json get_entry_exit_blocks(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

            // Entry block is always block 0
            json result;
            result["entry_block"] = 0;

            const qbasic_block_t &entry_bb = qfc.blocks[0];
            result["entry_start"] = format_ea(entry_bb.start_ea);
            result["entry_end"] = format_ea(entry_bb.end_ea);

            // Find all exit blocks (return/noreturn blocks)
            json exit_blocks = json::array();
            for (int i = 0; i < qfc.size(); i++) {
                if (qfc.is_ret_block(i) || qfc.is_noret_block(i)) {
                    const qbasic_block_t &bb = qfc.blocks[i];
                    fc_block_type_t btype = qfc.calc_block_type(i);

                    json exit_block;
                    exit_block["id"] = i;
                    exit_block["start_ea"] = format_ea(bb.start_ea);
                    exit_block["end_ea"] = format_ea(bb.end_ea);
                    exit_block["type"] = block_type_to_string(btype);
                    exit_blocks.push_back(exit_block);
                }
            }

            result["exit_block_count"] = exit_blocks.size();
            result["exit_blocks"] = exit_blocks;

            return result;
        }

        // Get dominators (blocks that must be executed before reaching target)
        json get_block_dominators(const json &params) {
            auto ea_opt = parse_ea(params["function_address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            int block_id = params["block_id"].get<int>();

            func_t *pfn = get_func(ea);
            if (pfn == nullptr) {
                throw std::runtime_error("No function at address");
            }

            qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

            if (block_id < 0 || block_id >= qfc.size()) {
                throw std::runtime_error("Invalid block ID");
            }

            // Simple dominator analysis: a block X dominates Y if all paths from entry to Y go through X
            std::vector<std::set<int> > dominators(qfc.size());

            // Initialize: each block is dominated by all blocks
            for (int i = 0; i < qfc.size(); i++) {
                for (int j = 0; j < qfc.size(); j++) {
                    dominators[i].insert(j);
                }
            }

            // Entry block is only dominated by itself
            dominators[0].clear();
            dominators[0].insert(0);

            // Iterative algorithm
            bool changed = true;
            while (changed) {
                changed = false;
                for (int i = 1; i < qfc.size(); i++) {
                    std::set<int> new_dom;
                    new_dom.insert(i); // Block always dominates itself

                    // Intersection of predecessors' dominators
                    bool first_pred = true;
                    for (int j = 0; j < qfc.npred(i); j++) {
                        int pred = qfc.pred(i, j);
                        if (first_pred) {
                            new_dom.insert(dominators[pred].begin(), dominators[pred].end());
                            first_pred = false;
                        } else {
                            std::set<int> temp;
                            std::set_intersection(
                                new_dom.begin(), new_dom.end(),
                                dominators[pred].begin(), dominators[pred].end(),
                                std::inserter(temp, temp.begin())
                            );
                            new_dom = temp;
                        }
                    }

                    new_dom.insert(i); // Add self

                    if (new_dom != dominators[i]) {
                        dominators[i] = new_dom;
                        changed = true;
                    }
                }
            }

            // Return dominators for the requested block
            json doms = json::array();
            for (int dom_id: dominators[block_id]) {
                if (dom_id != block_id) {
                    // Exclude self
                    const qbasic_block_t &bb = qfc.blocks[dom_id];
                    json dom;
                    dom["id"] = dom_id;
                    dom["start_ea"] = format_ea(bb.start_ea);
                    dom["end_ea"] = format_ea(bb.end_ea);
                    doms.push_back(dom);
                }
            }

            return json{
                {"block_id", block_id},
                {"dominator_count", doms.size()},
                {"dominators", doms}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_function_flowchart
        {
            mcp::ToolDefinition def;
            def.name = "get_function_flowchart";
            def.description = "Get function control flow graph";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "no_external_blocks", {
                                {"type", "boolean"},
                                {"description", "Exclude external blocks"}
                            }
                        },
                        {
                            "call_ends_block", {
                                {"type", "boolean"},
                                {"description", "Calls end blocks"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_function_flowchart);
        }

        // get_basic_block_at
        {
            mcp::ToolDefinition def;
            def.name = "get_basic_block_at";
            def.description = "Get basic block at address";
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
            server.register_tool(def, get_basic_block_at);
        }

        // find_block_paths
        {
            mcp::ToolDefinition def;
            def.name = "find_block_paths";
            def.description = "Find execution paths between blocks";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "from_block", {
                                {"type", "integer"},
                                {"description", "Source block ID"}
                            }
                        },
                        {
                            "to_block", {
                                {"type", "integer"},
                                {"description", "Target block ID"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "from_block", "to_block"})}
            };
            server.register_tool(def, find_block_paths);
        }

        // is_block_reachable
        {
            mcp::ToolDefinition def;
            def.name = "is_block_reachable";
            def.description = "Check block reachability";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "from_block", {
                                {"type", "integer"},
                                {"description", "Source block ID"}
                            }
                        },
                        {
                            "to_block", {
                                {"type", "integer"},
                                {"description", "Target block ID"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "from_block", "to_block"})}
            };
            server.register_tool(def, is_block_reachable);
        }

        // get_entry_exit_blocks
        {
            mcp::ToolDefinition def;
            def.name = "get_entry_exit_blocks";
            def.description = "Get entry and exit blocks";
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
            server.register_tool(def, get_entry_exit_blocks);
        }

        // get_block_dominators
        {
            mcp::ToolDefinition def;
            def.name = "get_block_dominators";
            def.description = "Get block dominators";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "block_id", {
                                {"type", "integer"},
                                {"description", "Block ID to analyze"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "block_id"})}
            };
            server.register_tool(def, get_block_dominators);
        }
    }
} // namespace ida_mcp::tools::control_flow
