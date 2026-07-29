# Multiple open programs

A Ghidra GUI project can have several programs open. Most program-scoped endpoints accept `program`; pass it explicitly whenever more than one program is open.

```text
list_open_programs()
get_current_program_info(program="filezilla")
decompile_function(address="0x401000", program="filezilla")
save_program(program="filezilla")
```

Without `program`, the service uses the active CodeBrowser program. Tab focus is convenient for one program but is not a coordination mechanism between clients.

The stdio bridge selects a Ghidra process by exact project name, PID, or Unix-domain socket. It does not guess partial names, switch transports, replay failed mutations, or select a program.

Useful lifecycle operations are:

- `import_file`
- `open_program` and `close_program`
- `list_open_programs`
- `save_program` and `save_all_programs`

After a transport failure, inspect Ghidra and call `refresh_connection`. A failed POST has an uncertain outcome and must be checked before retrying.
