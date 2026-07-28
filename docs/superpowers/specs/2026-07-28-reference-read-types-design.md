# `batch_update_references` read semantics — design

Date: 2026-07-28  
Status: revised after Claude review

## Motivation

`add_memory_reference` and `remove_reference` can already manipulate
case-insensitive Ghidra `RefType` names one reference at a time.
`batch_update_references`, however, accepts only six curated aliases. An
overlay audit therefore cannot use the safe path—bounded batching, dry-run
preview, one transaction, exact-identity matching, primary-transition
validation, and the `allow_non_user_removal` gate—for analyzer-created
`READ`, `READ_WRITE`, indirect-data, or conditional-flow references.

The motivating C64 program has direct VIC-II, SID, and CIA operands whose
analyzer references currently target the physical-RAM occupant at
`$D000-$DFFF`. Correcting them to the I/O overlay must preserve whether each
instruction reads, writes, or reads and writes the register.

## Contract

The `add.type` schema remains a closed enum, expanded to the complete set from
`RefTypeFactory.getMemoryRefTypes()` (using lowercase `getName()` values) plus
the existing `call` and `jump` aliases. This preserves useful MCP schema
guidance while accepting every reference type Ghidra permits
`ReferenceManager.addMemoryReference` to create.

The `remove.type` schema becomes a nonblank string. Removal accepts any
case-insensitive public static Ghidra `RefType` field name or `getName()`
value, plus the existing aliases. This deliberate asymmetry lets callers name
an exact reference already stored by Ghidra—even an internal or legacy type
that the endpoint would refuse to create—without allowing unsafe new
references.

This makes types emitted by `get_references_into_range`, listing, and address
encoding searches directly acceptable as batch input. Existing callers remain
valid. In particular, the resolver must accept both field name
`EXTERNAL_REF` and emitted name `EXTERNAL`.

All existing behavior remains unchanged:

- reference identity still includes source, destination, operand index, and
  exact Ghidra reference type;
- added references remain `USER_DEFINED`;
- removing analyzer/imported references still requires
  `allow_non_user_removal=true`;
- primary-reference validation, dry-run behavior, transactionality, overlay
  address qualification, and response shapes are unchanged.

Responses retain the endpoint's established lowercase vocabulary:
lowercase `getName()` for every type except `UNCONDITIONAL_CALL` and
`UNCONDITIONAL_JUMP`, which remain `call` and `jump`. Thus batch responses stay
lowercase while listing/xref tools emit uppercase; both are accepted as input.
Every returned `type` must itself be accepted by a later add/remove request.
Parser errors distinguish the closed valid-memory add set from the permissive
exact-type removal set.

`operand_index=-1` remains legal for all types, including `READ` and
`READ_WRITE`, matching the pre-existing freedom for `WRITE`. Add records keep
the current one-reference-per-source/operand slot rule, so a caller that needs
combined access uses `READ_WRITE`, not separate `READ` and `WRITE` records.

No C64-specific retarget endpoint or automatic overlay inference is added.
The caller remains responsible for exact source/destination addresses and for
deciding which bank occupant is correct. `describe_jump_table` keeps its
separate closed `computed_jump|jump` vocabulary.

## Implementation

Hoist the case-insensitive reflective `RefType` resolver currently private to
`XrefCallGraphService` into shared service utility code. Match both public
static field names and each constant's `getName()` so `EXTERNAL_REF` /
`EXTERNAL` round-trips. `add_memory_reference` continues its existing
permissive behavior; the shared resolver only fixes its latent `EXTERNAL`
name mismatch. `batch_update_references` separately validates add types
against `RefTypeFactory.getMemoryRefTypes()` while leaving remove permissive.

After checking existing aliases, add/remove parsing uses the shared resolver.
Update their distinct error messages. Collapse `wireType` to the contract's
uniform rule: `call`/`jump` for the two unconditional aliases, otherwise
lowercase `getName()`.

The add nested schema enumerates aliases plus the complete valid-memory set;
an offline test compares it mechanically with
`RefTypeFactory.getMemoryRefTypes()`. The remove schema is a described
nonblank string. GUI and headless parity is structural: both transports
publish the same annotation-scanned schema and execute the same service and
parser; the Python bridge forwards records without a type allowlist.
Validator and test code must copy the array returned by
`RefTypeFactory.getMemoryRefTypes()` before sorting or otherwise mutating it;
Ghidra exposes its live internal array.

Regenerate `tests/endpoints.json` as a guard. Its compact catalog does not
store nested enum values, so the expected result is byte-identical; any diff
indicates an unrelated contract change. Run the catalog parity tests and
document the expanded safe-batch capability in the Unreleased changelog,
including that Ghidra's four override reference types can intentionally alter
decompiler call/jump interpretation as well as navigation.

## Verification

Use test-first coverage:

1. Parser/schema tests require the add enum to equal the alias set union the
   lowercase names from `RefTypeFactory.getMemoryRefTypes()`, require remove
   to be a nonblank string, accept canonical `READ`, `READ_WRITE`, and an
   indirect type, accept both `EXTERNAL_REF` and `EXTERNAL` for removal,
   preserve the jump-table parser restriction, and reject unknown names.
   For every addable type, an offline closed-loop assertion checks
   `parseAddReferenceType(wireType(type)) == type`. For every public static
   `RefType`/`FlowType` constant, a removal loop checks
   `parseRemoveReferenceType(wireType(type)) == type`; field-name and
   `getName()` maps must also be collision-free.
2. A Ghidra fixture test starts with a primary `ANALYSIS` `READ` reference to
   a physical-space target, previews then atomically removes it and adds a
   primary `USER_DEFINED` `READ` reference to an explicitly qualified overlay
   target, and checks response type/source/non-user-removal fields.
3. The fixture also covers refusal without
   `allow_non_user_removal`, repeat-add idempotence without duplication,
   repeat-remove's intentional exact-reference error, `READ` versus an
   existing `READ_WRITE` incompatibility, add-slot exclusivity, exact
   `READ_WRITE` add/remove, and in-bounds versus out-of-bounds overlay target
   resolution. An in-bounds qualified target must remain overlay-qualified;
   an out-of-bounds qualified overlay target must be rejected instead of
   silently creating a reference in the base-space occupant. The retarget
   assertion also proves the old physical-space reference is gone.
4. Before implementation, run the focused tests and confirm that they fail
   because the closed schema/parser rejects the new types.
5. After implementation, run the focused fixture tests with
   `ghidra.test.install.dir=/Users/saverio/local/ghidra`, regenerate the
   endpoint catalog, run catalog parity tests, and complete the repository's
   standard Java/Python/package/diff gates.

## Non-goals

- Inferring C64 banking state.
- Bulk address-space translation by numeric offset.
- Changing reference-removal safety defaults.
- Expanding `describe_jump_table` beyond jump reference types.
