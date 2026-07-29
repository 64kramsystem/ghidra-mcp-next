# Structure editing

Use `get_struct_layout` before changing a structure.

- `create_struct` creates a new layout.
- `add_struct_field`, `modify_struct_field`, and `remove_struct_field` edit fields.
- `resize_struct` changes the total length.
- `rename_data_type` and `delete_data_type` manage the resulting type.

Example:

```text
create_struct(name="Widget", fields=[{"name":"tag","type":"byte","offset":0}])
add_struct_field(struct_name="Widget", field_name="flags", field_type="uint", offset=16)
resize_struct(name="Widget", new_size=96)
get_struct_layout(struct_name="Widget")
```

Shrinking fails when retained fields would extend past the new end unless the endpoint's explicit force option is used. Inspect the final layout rather than assuming filler or alignment.

For a C++ member function, create the structure first, set the prototype, then associate the function with the class:

```text
set_function_prototype(function_address="0x401000", prototype="int __thiscall Widget_OnClick(uint msg)")
set_function_this_type(function_address="0x401000", this_type="Widget *")
```

`set_function_this_type` moves the function into the matching Ghidra class namespace so the decompiler can derive the automatic `this` parameter.
