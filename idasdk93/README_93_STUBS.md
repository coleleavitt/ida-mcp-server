# IDA SDK 9.3 Stubs

This is IDA SDK 9.2 with additional stub headers for 9.3 new APIs.

## New APIs added in `include/ida93_new_apis.hpp`:

### Dirtree bulk operations
- `dirtree_bulk_move()` - Move multiple items at once
- `dirtree_bulk_remove()` - Remove multiple items at once  
- `dirtree_make_cursor()` - Create a cursor
- `dirtree_add_event_handler()` / `dirtree_remove_event_handler()` - Event hooks
- `reset_dirtree()` - Reset tree

### Event system (unified API)
- `bind_event_handler()` / `unbind_event_handler()` - New callback binding
- `event_source_dispatch()` - Dispatch events

### Deref chain (stack view dereferencing)
- `generate_deref_chain()` - Generate pointer dereference chain
- `get_deref_color()` - Get color for deref display

### Vault/Teams
- `vault_*` functions - Team server integration
- `vcred_*` functions - Vault credentials
- `lsite_*` functions - Local site operations

### Type system
- `tinfo_t__build_anon_type_name()` - Anonymous type naming
- `udm_t__compare_with()` - Compare UDT members
- `udt_type_data_t__deduplicate_members()` - Deduplicate members

### Misc
- `get_import_entry()` - Direct import table access
- `get_install_root()` - Get IDA installation root
- `get_nlist_demangled_name()` - Mach-O nlist demangling
- `indexer_match_all_async()` - Async search
- `bookmarks_t_get_by_inode()` - Bookmark lookup

## To fill in real signatures:

1. Open `libida.so` in IDA
2. Jump to function address (see ida93_new_apis.hpp for addresses)
3. Decompile with F5
4. Update the signature in the header

## Addresses of new functions:

```
dirtree_bulk_move:       0x77a230
dirtree_bulk_remove:     0x77cbd0
dirtree_make_cursor:     0x777740
generate_deref_chain:    0x3feb70
get_deref_color:         0x3feb20
bind_event_handler:      0x82cdd0
get_import_entry:        0x627910
get_vault_server:        0x8c2e00
```
