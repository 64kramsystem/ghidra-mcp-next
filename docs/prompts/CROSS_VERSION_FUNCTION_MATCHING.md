# Cross-Version Function Matching

Use this workflow to compare functions in two open local programs. Matching
produces evidence only; the analyst decides whether and how to annotate either
program.

## Prepare the programs

```text
list_open_programs()
switch_program(program="target-v1")
analyze_program(program="target-v1")
switch_program(program="target-v2")
analyze_program(program="target-v2")
```

Pass explicit program selectors from this point onward. Confirm language,
compiler family, image base, and analysis completeness before interpreting a
score.

## Exact hash pass

For a known function:

```text
get_function_hash(program="target-v1", address="0x...")
get_function_hash(program="target-v2", address="0x...")
```

For a broader inventory:

```text
get_bulk_function_hashes(program="target-v1", ...)
get_bulk_function_hashes(program="target-v2", ...)
```

An equal hash is strong evidence for equal normalized bytes under the tool's
hash semantics, not proof of identical calling context or behavior.

## Feature signatures and fuzzy matching

Inspect one function's feature signature:

```text
get_function_signature(program="target-v1", address="0x...")
```

Then request candidates in the other program:

```text
find_similar_functions_fuzzy(
  source_program="target-v1",
  target_program="target-v2",
  source_address="0x..."
)
```

For a bounded set:

```text
bulk_fuzzy_match(
  source_program="target-v1",
  target_program="target-v2",
  ...
)
```

Treat similarity as a ranking signal. Validate candidates with strings, callees,
callers, constants, datatype use, control flow, and decompiler output.

## Function diff

For the best candidate:

```text
diff_functions(
  program_a="target-v1",
  address_a="0x...",
  program_b="target-v2",
  address_b="0x..."
)
```

Record both confirming and contradicting evidence. Compiler optimization,
inlining, thunks, and split/merged functions can make a correct relationship
look structurally different.

## Optional local BSim

BSim is useful when dependencies can be rebuilt with symbols, such as
libfilezilla or wxWidgets around a proprietary FileZilla target. Enable trusted
scripts and supply a URL explicitly:

```text
run_ghidra_script(
  script_name="BSimQueryFunction.java",
  args=["0x401000", "file:/absolute/path/to/local-bsim"]
)
```

The four scripts are `BSimTestConnection`, `BSimIngestProgram`,
`BSimQueryFunction`, and `BSimBulkQuery`. Query scripts are read-only. BSim is
optional and should not delay string/xref/decompiler work on proprietary code
that has no comparison corpus.

## Decision record

For every accepted match, record:

- source/target program and address;
- hash/signature/similarity evidence;
- strings, constants, and call-context evidence;
- important differences; and
- confidence and unresolved alternatives.

Apply any annotation manually with the normal mutation endpoints, using names
appropriate to the target program. Re-read and save that explicit program after
the change.
