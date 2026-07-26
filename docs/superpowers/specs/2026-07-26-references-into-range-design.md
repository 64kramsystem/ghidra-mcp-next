# get_references_into_range — design

Date: 2026-07-26
Status: implemented, then amended after review — see [Review amendments](#review-amendments)

## Motivation

An overlay/banked-memory sweep needs to ask "which references land anywhere in
this address span". The API has no way to express it. Answering "every reference
whose target falls in `$9680`–`$98FF`" took four `get_bulk_xrefs` calls over a
hand-generated list of all 640 addresses in the span.

The result was complete and verifiable, so this is an ergonomics gap rather than
a capability gap — but it is a recurring query shape, not a one-off. Any target
with overlays or banked memory asks it constantly, because the whole point is
distinguishing two occupants of the same 16-bit addresses.

## Decision: GHIDRA_MCP_ALLOW_SCRIPTS stays off

`run_script_inline` would have answered the sweep in one call and returned
"Script execution disabled. Set GHIDRA_MCP_ALLOW_SCRIPTS=1". The gate stays
unset. Recorded here with the reasoning, because this is the document a future
session should read before reaching for `run_script_inline` again.

- The gate cost effort, not a finding. `get_bulk_xrefs` answered the same
  question exhaustively across all 640 addresses. Enabling scripts would have
  provided a faster path to something already reachable.
- The durable fix for "that was tedious" is this tool. A tool with a defined
  contract is reviewable, testable, and returns structured output. An inline
  Java blob is none of those, and every future session would reinvent a
  slightly different version of the same loop.
- Enabling it in `.mcp.json` would make arbitrary Java execution against the
  Ghidra process a standing property of the project, permanently, to save
  effort on a task being tooled properly anyway. The gate's own error text —
  "executes arbitrary Java against the Ghidra process" — is accurate.
- Project precedent: the previous capability gap, byte patching, was closed by
  specifying `patch_bytes` rather than scripting around it, and the tool landed.
- Specific hazard: the authoritative artifact is the Ghidra program database,
  and this project's convention is unusual and easy to break — labels only,
  zero functions, an overlay whose extent encodes a real claim about what a
  snapshot lost. An inline script that inadvertently creates functions or
  disturbs the overlay would corrupt exactly what the commit history protects.
- A narrower second flag for reviewed `ghidra_scripts/` files was considered and
  rejected: a file there executes with the same privileges as an inline string,
  the only difference being provenance, and it presumes a stream of ad-hoc
  scripts worth managing. The demand so far is one query shape.

## Contract

`GET /get_references_into_range`, in `XrefCallGraphService`, category `xref`,
alongside `get_bulk_xrefs`. Read-only with scalar parameters, so no request
body — unlike `get_bulk_xrefs`, which is POST only because it takes an array.

### Parameters

| name | required | notes |
| --- | --- | --- |
| `start` | yes | inclusive |
| `end` | yes | inclusive |
| `limit` | no | `1`–`10000`, default `2000` |
| `program` | no | existing selector convention |

Both endpoints resolve through `ServiceUtils.parseAddress`. Errors:

- `start` > `end` — rejected, rather than silently returning empty.
- endpoints resolving into different address spaces — rejected; a range across
  spaces has no meaning.
- an unresolvable endpoint — carries the `parseAddress` message unchanged.

Deliberately excluded: reference-type filter, offset/cursor pagination, and any
summary block beyond `count`. The output is a flat list; a caller tallies it.

### Bare, unqualified ranges resolve to the physical space

`get_references_into_range("9680", "98ff")` means `ram:9680`–`ram:98ff`, and
does not error, even when an overlay occupies those offsets.

This follows Ghidra's own convention, which the server already documents in
tool descriptions: plain hex resolves to the default physical space. Bare
`9680` means `ram:9680` everywhere else in the API, and `get_bulk_xrefs`
accepted bare `9695`, `96a1`, `9700` and resolved them to RAM. A range query
that alone refused bare input would be a local exception to a global rule, and
callers would have to remember which tools are strict.

The stricter behaviour elsewhere is confined to writes: `batch_set_comments`
rejects `0x9700` with "Ambiguous unqualified address ... maps to multiple
program address spaces". Refusing to guess before mutating the program is
right. A read-only query has no such stakes, and the cost of being wrong is one
re-run with a qualifier.

Unioning both occupants by default was rejected outright: it destroys the
distinction the query exists to make, handing back a mixture of loader and
player references — precisely the conflation being resolved. It also silently
changes meaning as overlays are added or resized, so the same call returns
different counts across sessions for reasons unrelated to the program's
references.

Two fields make the resolution visible instead of assumed:

- `resolved_range` is **always** present, overlap or not. Its value is in being
  unconditional. Anyone reading the result, or a later transcript, sees
  `ram:9680 - ram:98ff` and knows which occupant was queried without inferring
  it.
- `overlapping_spaces` is **always** present, `[]` when nothing overlaps, so
  callers can test it unconditionally. It is the discovery mechanism: a caller
  who queries `9680`–`98ff` not knowing a second occupant exists is told so in
  the same response, and learns that a second query would be meaningful. That
  is strictly better than an error, which reports a problem but delivers no
  data.

`overlapping_spaces` means **other spaces occupying those offsets, excluding
the queried one**. Querying `ram:9680-98ff` reports `["SND_PLAYER"]`; querying
`SND_PLAYER::9680-98ff` reports `["ram"]`, not `["SND_PLAYER"]`, which would be
useless. The underlying physical space counts as an occupant, so the field is
symmetric rather than overlay-only.

### Response

Excerpt — two of the eleven rows the pre-retarget sweep would return:

```json
{
  "resolved_range": "ram:9680 - ram:98ff",
  "overlapping_spaces": ["SND_PLAYER"],
  "count": 11,
  "truncated": false,
  "references": [
    {"from": "ram:0733", "from_symbol": "LAB_0730", "from_symbol_offset": 3,
     "from_kind": "instruction", "from_instruction": "STA $9700,Y",
     "to": "ram:9700", "type": "WRITE",
     "source_kind": "analysis", "operand_index": 0},

    {"from": "ram:0733", "from_symbol": "LAB_0730", "from_symbol_offset": 3,
     "from_kind": "instruction", "from_instruction": "STA $9700,Y",
     "to": "ram:9701", "type": "WRITE",
     "source_kind": "analysis", "operand_index": 0}
  ]
}
```

Addresses, instructions, labels and destinations above are observed program
state, taken from the `get_bulk_xrefs` output of the sweep: `$0733 STA $9700,Y`
records writes to both `$9700` and `$9701` because Ghidra emits one reference per
resolved destination for an indexed store, and `$0739 STA $9800,Y` does the same
for `$9800`/`$9801`. The `source_kind` and `operand_index` values shown are
illustrative of the field shape, not read from the program.

`$0730` carries the **default** label `LAB_0730`, which was visible in the
listing before any comment was set. The name `INSTALL_DISK_LOADER` exists only
as plate **comment** text, written via `batch_set_comments`, never as a symbol
rename. `COPY_LOADER_PAGE` appears not to be a symbol in the program at all.

This pins a requirement, and it is a trap worth stating loudly: **`from_symbol`
reports symbols only.** Plate comment text is not a symbol and must never appear
there, however much more informative it looks. A test asserting
`from_symbol == "INSTALL_DISK_LOADER"` will fail. `LAB_0730` is also the more
valuable fixture, because it exercises the default-label path rather than the
user-defined one.

### The two JSR rows: what is known, and what is not

The remaining rows include the `JSR $96a1` sites at `$0703` and `$15CC`. Both
are omitted from the example rather than invented, and **neither
`from_symbol` value is known**. Recorded precisely, because a guessed name here
would poison the tests written against this spec.

`$0703` — surrounding code was read in full via `get_listing_range` over
`$06F0`–`$0760`. There is no label at `$0703` itself, and no label anywhere in
the preceding bytes back through `$06F0`: the code units at `$06F0`, `$06F2`,
`$06F4`, `$06F6`, `$06F8`, `$06FB`, `$06FD`, `$06FF` and `$0701` all returned
`"labels": []`. The nearest labels in that window are *after* `$0703` — `$0706`
carries the default offcut label `LAB_0706+1` at `$0707`, and `$070F` is the
user-defined `ENTER_GAMEPLAY_DISPLAY`. So the nearest preceding label lies at or
before `$06EF`, outside the range read, and is unknown.

This makes `$0703` a genuinely useful fixture for the block-bounded backward
walk: a source with no label for at least 19 bytes behind it.

For context only, not as symbol data: EOL comments describe the region as the
tail of an initialisation routine — screen/colour cursor setup, marking system
init complete in `$5E`, bank to `$35`, calls to the two sound-init entries, bank
back to `$36`, `CLI`, `RTS`. Plate comments elsewhere refer to the routine as
`INIT_GAME`, but no symbol of that name was observed at any address, so there is
no address/offset pair to cite.

`$15CC` — nothing observed. It appeared only as a `search_instructions` row
(`JSR 0x96a1`, bytes `20a196`) and in the xref results; its surrounding listing
was never read. The one nearby observation is `$15D4 JSR $070F`, the call into
`ENTER_GAMEPLAY_DISPLAY`, which is consistent with `$15CC` sitting in the
title-to-game transition — but that is inference from comments, not an observed
label.

**Counts to get right when writing the first test.** The sweep found **nine
sites**, but this tool's flat list returns **eleven references**, because the
indexed stores at `$0733` and `$0739` each record two destinations — directly
observed in the `get_bulk_xrefs` output, so the figure is solid. Post-retarget, a
query for `ram:9680`–`ram:98ff` returns **seven**, having lost the four player
sites at `$0703`, `$0706`, `$15CC` and `$A884` to `SND_PLAYER::`; this was
confirmed by a verification query returning empty for `9695`, `96a1` and `96da`.
Nine is the wrong number for every one of those cases.

### Field semantics

- **Ordered by `from`** first. Classification follows the source: you are asking
  what the code at `$0730` is doing, and the answer comes from reading around it.
  Sorting by source clusters `$0733` and `$0739` adjacently, which is how they get
  understood — both halves of one page-copy loop. Sorted by target they would be
  far apart.

  **Reuse `ReferenceOrdering.outgoing()`** (`ReferenceOrdering.java:25`) rather
  than hand-rolling the comparator. It already sorts by from-address,
  to-address, reference type name, operand index, then source kind — a total
  order that leaves no ties for equal `from`/`to`, which an earlier draft of this
  spec left unspecified. It is package-private in `com.xebyte.core`, so
  `XrefCallGraphService` can use it directly — and already uses part of it:
  `get_xrefs_to` calls `ReferenceOrdering.takeStored`
  (`XrefCallGraphService.java:63`). The comparator and `sourceKind` are currently
  used by `ListingRangeService` (`ListingRangeService.java:986`, `:654`, `:667`),
  so `get_listing_range` and this endpoint will report `source_kind` identically.
- `to` and `from` are plain strings, **space-qualified** whenever the program has
  any overlay space or more than one physical space. The invariant is *every
  address that could be ambiguous is qualified*; an unqualified address in an
  **ambiguous** program would defeat the tool's purpose.

  **This endpoint needs its own formatter; `addressToJson` will not do it.**
  `ServiceUtils.addressToJson` (`ServiceUtils.java:649`) returns bare hex unless
  the address is itself in an overlay or external space, or
  `getPhysicalSpaceCount(program) > 1` — and `getPhysicalSpaceCount`
  (`ServiceUtils.java:673`) explicitly skips overlay spaces. So on the program
  this tool exists for — one physical space plus an overlay — a `ram:0733`
  source would come back as bare `0733`, exactly the ambiguity the sweep needed
  removed. Believing otherwise was an error in an earlier draft of this spec.

  Rule: when `getOverlaySpaceCount(program) > 0 || getPhysicalSpaceCount(program)
  > 1`, format with `address.toString(true)`; otherwise `address.toString(false)`.

  Reviewed alternative: format with `toString(true)` unconditionally, which is
  simpler still. Rejected because it would prefix every row with `ram:` on
  single-space firmware programs that have no ambiguity to resolve, diverging
  from every other endpoint's output for no gain. The condition is one boolean
  computed once per request, not per row.
- `count` is **references matched**, not sites. One indexed store contributing
  two destination references counts 2, and the two references appear as adjacent
  rows sharing the same source address. That adjacency is the point: a human
  reading the rows sees one instruction and can classify it as a single site,
  while `count` still reports 2. Grouping by target would instead scatter that
  one instruction under two keys, where it reads like two independent findings.
- `truncated` plus `count` makes the cap visible instead of silent. When the
  cap bites, `count` still reports matches found, so `count` exceeds
  `references.length`.
- `from_symbol` resolves in one explicit precedence order, because "exact label,
  else preceding label, and functions where they exist" left the tie
  unspecified:

  1. the primary symbol **at** `from`;
  2. the function **containing** `from`;
  3. the nearest preceding primary label or function entry, walking back no
     further than the containing memory block.

  `from_symbol_offset` is the byte delta from whichever of those matched. Both
  fields are **omitted** when nothing precedes the source in its block.

  This is label-based rather than function-based by design. A labels-only
  program has zero Ghidra functions, so a `from_function` field would be empty
  on every row.
- `from_kind` is `instruction`, `data`, or `undefined`. `from_instruction`
  carries the rendered instruction, or for a data source — a pointer-table entry
  — the code unit representation, and is **omitted** for `undefined`, meaning no
  containing `CodeUnit` exists at the source. References can be recorded from
  mapped-but-undefined addresses, so this case must not render as an empty
  string. The rendered instruction is the single most useful thing
  when classifying: `JSR $9700` versus `STA $9700,Y` is the whole
  loader-versus-player distinction at a glance, and without it every row costs
  a `get_listing_range` round trip.
- `source_kind` comes from **`ReferenceOrdering.sourceKind(reference.getSource())`**
  (`ReferenceOrdering.java:54`), which already returns the lowercased enum name
  and maps null to `""`. Do not write a new mapping. Ghidra 12.1.2's `SourceType`
  has five values — `DEFAULT`, `ANALYSIS`, `AI`, `IMPORTED`, `USER_DEFINED` — so an
  earlier draft naming only three would have frozen an incomplete enum and
  mislabelled imported references. This is the audit axis. After a retarget, what
  distinguishes an intended reference from an auto-generated one is exactly
  this: an address can briefly hold both a `default` reference to `ram:9695`
  and a `user_defined` one to `SND_PLAYER::9695`, and the cleanup is removing
  the former. A tool for auditing cross-space references that cannot show
  whether a reference was deliberately placed is missing the discriminator.
  `get_listing_range` already exposes it.
- `operand_index` from `Reference.getOperandIndex()`. The workflow is query →
  classify → retarget, and both `add_memory_reference` and `remove_reference`
  consume it. Without it, every act-on-a-finding step needs a
  `get_listing_range` round trip to recover it.

### Tool description must state the limit of the query

This returns **recorded references only**. Untyped bytes that happen to encode
an in-range address produce no `Reference` and will not appear. A reader could
easily take "every reference into range" as "every encoded address in range"
and quietly miss an untyped pointer table. Exhaustiveness needs a second,
independent pass — enumerating every `JSR`/`JMP` and decoding targets from
instruction bytes; the two methods agreeing is what makes a result exhaustive.

## Implementation

One `refMgr.getReferenceDestinationIterator(addressSet, true)` pass over the
resolved set, then `getReferencesTo` per hit destination, so destinations with
no references never appear.

`overlapping_spaces` is computed from **memory blocks**, not address spaces. An
overlay space in Ghidra spans the full range of the space it shadows —
`get_current_program_info` reports such an overlay as `0000`–`ffff`, identical
to RAM — so intersecting on space min/max would report every overlay for every
query, making the field a constant. The real extent lives on the block.

Iterate **all** blocks from `program.getMemory().getBlocks()`, not only overlay
blocks, and for each candidate:

1. skip it when its address space is the queried space;
2. require `candidateSpace.getPhysicalSpace()` to equal
   `querySpace.getPhysicalSpace()`, so unrelated physical spaces never appear;
3. intersect the block's offset interval with the requested offset interval,
   comparing endpoints as `Address.getOffsetAsBigInteger()` — a natural
   implementation using signed `long` can compare wrongly in high-half 64-bit
   spaces;
4. emit distinct space names in deterministic (sorted) order.

Filtering candidates by `isOverlay()` — as an earlier draft of this spec did —
cannot satisfy the symmetry rule above: an overlay-space query must be able to
report the underlying `ram`, and `ram` is not an overlay. Iterating all blocks
and excluding the queried space handles physical-to-overlay, overlay-to-physical
and sibling-overlay overlap with one rule.

Address parsing happens on the HTTP worker thread **before** entering
`threadingStrategy.executeRead`, per the `parseAddress` threading contract:
`SwingThreadingStrategy` transfers execution to the EDT inside `execute*`, and
a `ThreadLocal` set there is invisible to the caller.

## Tests

Offline tests first, in `XrefCallGraphServiceValidationTest` or a sibling if it
grows too large.

Validation and range handling:

- `start` > `end` rejected.
- endpoints in different spaces rejected.
- unresolvable endpoint carries the `parseAddress` message.
- `limit=0` and a negative `limit` rejected; `limit=10000` accepted and
  `limit=10001` rejected. Pin the bounds rather than letting them fall out of the
  loop.
- references placed **exactly at `start` and exactly at `end`** both appear, and
  one immediately outside each endpoint does not. The contract calls the bounds
  inclusive; nothing currently tests it.

Result set:

- destinations with no references are absent.
- an indexed store with two resolved destinations yields two rows, adjacent and
  sharing a source address.
- ordering matches `ReferenceOrdering.outgoing()` end to end — assert the full
  expected sequence, not merely that tied rows survived.
- two references with identical source **and** destination but differing
  **`operand_index`** both appear, rather than one shadowing the other. Their
  types may differ too, but do **not** build a type-only pair: Ghidra identifies
  a reference by source, destination and operand index, so changing only the type
  updates the existing reference instead of creating a second one, and such a
  test would assert something impossible.

Range echo and overlap:

- `resolved_range` present, and `overlapping_spaces` present as `[]`, on an
  overlay-free program.
- an overlay **block** intersecting the requested offsets is reported; a
  non-overlapping overlay is not.
- a **physical** query reports overlapping overlay spaces.
- an **overlay** query reports the underlying physical space, and any
  sibling-overlay overlap. This is the direction the `isOverlay()` filter got
  wrong, so it is the direction most worth testing.
- the queried space never appears in its own `overlapping_spaces`.
- an unrelated physical space that shares offsets but not a
  `getPhysicalSpace()` root does **not** appear.
- with overlay spaces created in **non-lexical insertion order**, the emitted
  array is exactly the sorted sequence. "Deterministic order" is otherwise
  untested and would pass on accidental insertion order.
- one **high-half 64-bit** block and query range, so that a signed-`long`
  intersection actually fails. Every other overlap case here uses low addresses,
  where signed and unsigned comparison agree and the
  `getOffsetAsBigInteger()` requirement is unenforced.

Per-reference payload — the four fields settled above, which are the most
likely to be silently dropped in the JSON mapper:

- `source_kind`: **table-test `ReferenceOrdering.sourceKind` against all five
  `SourceType` values** plus null. Testing only one extra value (say `imported`)
  would still pass an implementation hardcoded for four and missing `AI`, and a
  table test over the enum is far cheaper than constructing five full program
  references. One end-to-end assertion through the endpoint — `user_defined`
  versus `default` — then covers the wiring.
- `operand_index` round-trips, including the `-1` case.
- `from_kind`/`from_instruction`: a **data** source (pointer-table entry)
  yields `data` plus a code unit representation, not an empty string. The
  instruction case passes trivially; the data case is where it breaks.
- a source address with **no containing `CodeUnit`** yields
  `from_kind: "undefined"` with `from_instruction` absent.
- `from_symbol`/`from_symbol_offset` omitted when nothing precedes the source
  in its block. Test the omission, because absent versus `null` versus `""`
  drifts.
- `from_symbol` reports a **default** label (`LAB_0730`-style) as itself, and a
  plate comment on that address does **not** substitute for or override it. The
  real program has exactly this case: `$0730` is labelled `LAB_0730` with a
  plate comment reading `INSTALL_DISK_LOADER`.
- **the precedence rule is actually exercised**, which omission plus exact-label
  tests do not do:
  - a source carrying an **exact primary label** *inside* a function returns the
    label, per rule 1 beating rule 2;
  - a source inside a function that also has a *nearer preceding label* returns
    the containing **function**, per rule 2 beating rule 3;
  - a label in the **previous memory block** is never returned, even when it is
    the nearest preceding symbol by address.

Cap semantics:

- a case where `truncated` is `true` and `count` exceeds `references.length`.
  Without it, `count` and array length stay accidentally equal in every test
  and the distinction is never exercised.

Overlay-qualified output, which is the entire reason the tool exists:

- on an overlay program, `from`/`to` come back space-qualified —
  `SND_PLAYER::9747`, not `9747`.
- **the case `addressToJson` gets wrong**: exactly one physical space plus an
  overlay, querying the physical space. A `ram:0733` source must render as
  `ram:0733`, not bare `0733`. This is the real program's shape, and reusing
  `addressToJson` would silently fail it, so the fixture must have an overlay
  even when the assertion is about a physical address.
- **the conditional rule is distinguished from unconditional qualification.**
  Every formatter test above passes for an implementation that just calls
  `toString(true)` everywhere, so add:
  - one physical space, **no** overlay: `from`/`to` assert as bare `0733`, *not*
    `ram:0733`;
  - **multiple physical spaces**, no overlay: addresses assert as qualified.
- a query whose range lies **inside** an overlay block:
  `SND_PLAYER::9680`–`SND_PLAYER::98ff` returns the references recorded in the
  overlay space, with `overlapping_spaces` reporting `ram`. Otherwise the
  symmetric direction is unimplemented by omission.

## Integration

Per the repo's endpoint-change checklist:

1. Offline tests above, first.
2. Implement in `XrefCallGraphService`.
3. **Register the route in `EndpointRegistry.registerXrefCallGraphEndpoints()`**
   (`EndpointRegistry.java:761`), alongside `get_xrefs_to`/`get_xrefs_from`.
   Adding the annotated service method alone is not sufficient — the shared
   registry is what preserves GUI/headless parity, and omitting this step is the
   most likely way for the endpoint to appear complete while being unreachable.
4. Regenerate and inspect the catalog: `mvn test -Dtest=RegenerateEndpointsJson
   -Dregenerate=true`, then `EndpointsJsonParityTest`, then
   `uv run pytest tests/unit/test_endpoint_catalog.py -v --no-cov`.
5. Confirm the bridge normalizes the name to `get_references_into_range` in the
   `xref` group, and that GUI and headless share the path.
6. `CHANGELOG.md` under `Unreleased`, plus the maintained xref docs.
7. Gates: `uv run pytest tests/unit/ -v --no-cov`, `mvn test`,
   `mvn clean compile -q`, `git diff --check`.

Live verification against the real program requires the prepared Ghidra
instance and is reported as unexecuted otherwise. As of this spec it **has not
been run**, and the session state it would have used is gone: the VICE process
was terminated and `vice_disconnect` released the binding.

Re-establishing that state is not cheap, so budget for it rather than assuming
it is a quick check. Last time it took a launch, a stuck autostart that had to be
nudged by writing `$0D` to the keyboard buffer at `$0277` with the count at
`$C6`, and several minutes of real-time loading before the title screen was
reachable. Two prerequisites: the connector needs the Ghidra Debugger tool and
the `UNIX_SHELL:vice-c64.sh` launch offer present before `vice_connect` will
bind.

One trap for whoever redoes it: `LAB_0730` is the copy-loop **body**, so an
execute checkpoint there fires 256 times. `$073F` is the address to break on for
"after the copy."

Note on step 7: the full `mvn test` run has a known-flaky jump-table failure, a
pre-existing fixture race. If it is the only red, it is not a signal about this
change.

## Review amendments

Reviewed after implementation, two ways: a Codex pass over the spec, the implementation and the tests, and a live run of the endpoint against the real Neverending Story program. The live run is what the section above budgeted for and it did get done. Both are recorded here because they found different things, which is the point of running both.

### The live run confirmed the numbers

A physical query for `RAM:9680`–`RAM:98ff` returned **exactly seven** references from five sites — the figure this spec predicted post-retarget, matching the hand-built sweep. An overlay query for `SND_PLAYER::9680`–`SND_PLAYER::98ff` returned 93, of which the 42 RAM-sourced rows are exactly the cross-space edge count derived by hand. Truncation behaved as specified: with `limit=5`, `count` reported 93 and `truncated` was true, so the cap never masquerades as the total.

### Corrected: the field literals in this spec were wrong

The worked example above gives `"ram:0733"`, `"ram:9680 - ram:98ff"`, `["ram"]` and `"STA $9700,Y"`. The endpoint emits `RAM:0733`, `RAM:9680 - RAM:98ff`, `["RAM"]` and `STA 0x9700,Y` on that program. Address rendering follows `Address.toString`, which uses the space name as the program declares it — the case is the program's, not a normalisation this endpoint applies. Operands follow the language module: Ghidra's 6502 renders `0x9700`, not the `$9700` a hand-written listing would use. Treat the shapes above as illustrative and these as the literals.

### Added: `from_symbol_relation`, and separate names for proximity

The three-rule precedence for `from_symbol` was specified but the result was not distinguishable from outside. Rule 3 walks back "no further than the containing memory block", and on a program laid out as one 53 KiB RAM block that bound never bites: the live run produced `PART_FILENAME+461` and `PART_FILENAME+475` for SID-player code, attributing it to a five-byte disk-loader filename buffer, and `SND_VOICE3_CMD_TABLE+131` for an address 103 bytes past a 28-byte table. Those are indistinguishable from the correct `SND_VOICE1_CMD_TABLE+4` by name and offset alone.

Every row now carries `from_symbol_relation`: `at` for rule 1, `containing` for rule 2, `preceding` for rule 3.

A qualifier alone was not enough. A caller that keeps reading `from_symbol` and `from_symbol_offset` and ignores the rest can still print `PART_FILENAME+475`, and agent callers cherry-pick fields routinely. So containment and proximity have **different field names**: `from_symbol` with `from_symbol_offset` is emitted only for `at` and `containing`, where the offset really indexes into the named thing, and the rule-3 guess is `nearest_preceding_symbol` with `nearest_preceding_distance`. A caller has to ask for the weaker thing by name.

This matters on every row of a labels-only program, not just the pathological ones: with zero Ghidra functions there is no rule-2 match, so the live sweep returned `preceding` for all seven of its rows.

Deliberately not done: pruning a preceding symbol once the walk passes the end of its code unit. That would drop the useful cases along with the misleading ones — a label on code is a 1–3 byte instruction, so `SND_V1_FREQ_PULSE_STEP+166` would vanish too. Naming the relation keeps the information and removes the ambiguity.

### Added: `scope`

Every response now carries `scope: "recorded_references_only"`. The caveat belonged in the tool description, but a stored result or a transcript of one no longer has that description in view, and `count: 7` reads as "there are 7" unless the response itself says what was counted.

### Corrected: what a second pass can prove

The section "Tool description must state the limit of the query" claimed the two methods agreeing "is what makes a result exhaustive". That is too strong. Enumerating `JSR`/`JMP` and decoding targets finds missed control flow; it does not find untyped data pointers, and it does not independently verify absolute loads and stores the analyzer left unresolved. In the sweep that motivated this endpoint, decoding every `JSR` and `JMP` still left the three dispatch tables to be reasoned about separately. The honest claim, and the one the tool description now makes, is that the result is complete for what the reference database currently holds, and that a wider sweep raises confidence without proving exhaustiveness.

### Added: symbol-resolved operand rendering

`from_instruction` came from `CodeUnit.toString()`, which renders an operand as a bare number even where a symbol exists for its target. On this endpoint that is the difference between a row that answers "which occupant does this site mean" and one that restates the bytes. It now goes through the same `CodeUnitFormat` configuration `CompleteListingWriter` uses, with `ShowBlockName.NON_LOCAL` to keep the overlay qualifier on the operand.

Two corrections, both from deploying the build and querying the real program rather than reading the code. First, the obvious call — `CodeUnitFormat.getRepresentationString(CodeUnit)` — does **not** resolve an operand across address spaces: `RAM:$9910 JMP $97A9` into the overlay came back as a bare `JMP 97a9`, no symbol and not even an `0x`, which is worse than the `toString()` being replaced. Rendering **operand by operand**, exactly as the full-listing writer does, yields `JMP SND_PLAYER:SND_V1_STREAM_ADVANCE3`. Second, the operand resolves through the **primary** reference, and four sites in the target program had non-primary cross-space references, so they rendered as bare offsets whatever the formatter did. That was a defect in the program, not in this endpoint, and it masked the fix on the first site tried.

For a reference recorded from the interior of an aggregate — a dispatch-table entry, the usual case for a jump table — the whole unit rendered as just `dw[15]`, naming the array and none of its slots. The primitive at `from` is rendered instead.

### Fixed: the registry contract had drifted from the annotation

`EndpointRegistry` advertised "List recorded references whose destination falls in an inclusive address range", omitted the limit semantics, and marked `start`/`end` optional. Live runtimes use `AnnotationScanner`, so nothing was broken in transport, but `generateSchema()` would have published a weaker contract — one that reads as an exhaustive sweep. Registry and annotation now agree, `start`/`end` are required via a new `qStrReq` helper, and `tests/endpoints.json` carries the annotation's description.

### Fixed: the tests mocked away the property under test

The fixture's `getReferenceDestinationIterator` stub ignored the `AddressSetView` it was handed and returned every fixture destination, leaving the endpoint's own `inRange` filter as the only thing under test. The space dimension of that filter — whether a RAM query can see an overlay destination — is the whole reason this endpoint exists, and nothing pinned it. The stub now honours the set, including its space test, and two tests occupy the *same* offset `$9700` in both spaces and assert each query returns only its own occupant, with the overlay case including both a cross-space and a player-internal caller so the query cannot be filtering on the source space instead.

The empty-range test asserted only `resolved_range` and `overlapping_spaces`; it now also pins `count == 0`, `truncated == false` and `references == []`.

That first attempt was itself checked by mutation, and did not hold up: deleting the space comparison from `inRange` left every test passing. Making the fixture faithful is what caused it — a faithful iterator filters by space and offset itself, so the endpoint's own filter never sees anything to reject and no test can observe it. Fixing a fixture that reimplemented what it verified introduced the opposite problem in the same commit.

The fixture therefore has an opt-in over-delivering mode: the iterator ignores the set it is handed and returns every destination, leaving `inRange` as the only thing between the caller and the wrong occupant. Two tests use it, one per half of the guarantee, and each kills exactly one mutant — delete the space comparison and the space test fails, replace the offset comparison with `true` and the offset test fails. The default stays faithful, since modelling a lenient Ghidra everywhere would be the opposite lie. A third test pins what the endpoint actually controls when the source *is* faithful: it captures the `AddressSetView` handed to `getReferenceDestinationIterator` and asserts the space and both bounds, because asking for the wrong space is then the way this endpoint returns another occupant's references, and nothing was checking the request.

The lesson worth keeping: a test that asserts the right property is not the same as a test that would fail if the property broke. Only mutation told them apart here.

### Still open: no guaranteed path from incomplete to complete

Pagination was excluded by design and `limit` caps at 10,000. Splitting the destination range does not rescue a caller if a single address carries more than 10,000 incoming references. The cap is honest — `count` and `truncated` say so — but there is no route through this endpoint to the full list in that case. Left as a design decision rather than patched: it needs a cursor contract, which is a larger change than this review.
