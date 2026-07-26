# get_references_into_range — design

Date: 2026-07-26
Status: approved, not yet implemented

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
| `limit` | no | default 2000 |
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
state: `$0733 STA $9700,Y` records writes to both `$9700` and `$9701` because
Ghidra emits one reference per resolved destination for an indexed store,
`$0739 STA $9800,Y` does the same for `$9800`/`$9801`, and `$0730` carries the
default label `LAB_0730`. The `source_kind` and `operand_index` values shown are
illustrative of the field shape, not read from the program.

The remaining rows include the two `JSR $96a1` sites at `$0703` and `$15CC`.
They are omitted here rather than invented: their nearest-preceding labels were
not available when this spec was written, and both must be read from the program
before any of these rows is used as a test fixture.

**Counts to get right when writing the first test.** The sweep found **nine
sites**, but this tool's flat list returns **eleven references**, because the
indexed stores at `$0733` and `$0739` each record two destinations. And
post-retarget, a query for `ram:9680`–`ram:98ff` returns **seven**, since the
four player sites now resolve into `SND_PLAYER::`. Nine is the wrong number for
every one of those cases.

### Field semantics

- **Ordered by `from`** (space, then offset), ties broken by `to`.
  Classification follows the source: you are asking what the code at `$0730` is
  doing, and the answer comes from reading around it. Sorting by source
  clusters `$0733` and `$0739` adjacently, which is how they get understood —
  both halves of one page-copy loop. Sorted by target they would be far apart.
- `to` and `from` are plain strings, **space-qualified** whenever the program
  has overlays or more than one physical space, per `addressToJson`'s existing
  rule. An unqualified address in the output would defeat the tool's purpose.
- `count` is **references matched**, not sites. One indexed store contributing
  two destination references counts 2. Grouping by target would make that one
  instruction appear under two keys and read like two findings; flat, with the
  source visible, it is obviously one indexed store and gets counted once.
- `truncated` plus `count` makes the cap visible instead of silent. When the
  cap bites, `count` still reports matches found, so `count` exceeds
  `references.length`.
- `from_symbol` is the primary label at `from`, else the nearest preceding
  label, walking back no further than the containing memory block;
  `from_symbol_offset` is the byte delta. Where functions exist, a containing
  function supplies the name. Both fields are **omitted** when nothing precedes
  the source in its block.

  This is label-based rather than function-based by design. A labels-only
  program has zero Ghidra functions, so a `from_function` field would be empty
  on every row.
- `from_kind` is `instruction` or `data`. `from_instruction` carries the
  rendered instruction, or for a data source — a pointer-table entry — the code
  unit representation. The rendered instruction is the single most useful thing
  when classifying: `JSR $9700` versus `STA $9700,Y` is the whole
  loader-versus-player distinction at a glance, and without it every row costs
  a `get_listing_range` round trip.
- `source_kind` is `user_defined`, `default`, or `analysis`, from
  `Reference.getSource()`. This is the audit axis. After a retarget, what
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
query, making the field a constant. The real extent lives on the overlay block.
Iterate `program.getMemory().getBlocks()`, filter `isOverlay()`, intersect
block start/end against the requested offsets, and emit the distinct space
names, excluding the queried space.

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

Result set:

- destinations with no references are absent.
- an indexed store with two resolved destinations yields two rows.
- ordering is by `from`.

Range echo and overlap:

- `resolved_range` present, and `overlapping_spaces` present as `[]`, on an
  overlay-free program.
- an overlay **block** intersecting the requested offsets is reported; a
  non-overlapping overlay is not.

Per-reference payload — the four fields settled above, which are the most
likely to be silently dropped in the JSON mapper:

- `source_kind` distinguishes a `user_defined` reference from a `default` one.
- `operand_index` round-trips, including the `-1` case.
- `from_kind`/`from_instruction`: a **data** source (pointer-table entry)
  yields `data` plus a code unit representation, not an empty string. The
  instruction case passes trivially; the data case is where it breaks.
- `from_symbol`/`from_symbol_offset` omitted when nothing precedes the source
  in its block. Test the omission, because absent versus `null` versus `""`
  drifts.

Cap semantics:

- a case where `truncated` is `true` and `count` exceeds `references.length`.
  Without it, `count` and array length stay accidentally equal in every test
  and the distinction is never exercised.

Overlay-qualified output, which is the entire reason the tool exists:

- on an overlay program, `from`/`to` come back space-qualified —
  `SND_PLAYER::9747`, not `9747`. `addressToJson`'s rule is conditional on the
  program having overlays, so an offline fixture without one cannot catch a
  regression here.
- a query whose range lies **inside** an overlay block:
  `SND_PLAYER::9680`–`SND_PLAYER::98ff` returns the references recorded in the
  overlay space, with `overlapping_spaces` reporting `ram`. Otherwise the
  symmetric direction is unimplemented by omission.

## Integration

Per the repo's endpoint-change checklist:

1. Offline tests above, first.
2. Implement in `XrefCallGraphService`.
3. Regenerate and inspect the catalog: `mvn test -Dtest=RegenerateEndpointsJson
   -Dregenerate=true`, then `EndpointsJsonParityTest`, then
   `uv run pytest tests/unit/test_endpoint_catalog.py -v --no-cov`.
4. Confirm the bridge normalizes the name to `get_references_into_range` in the
   `xref` group, and that GUI and headless share the path.
5. `CHANGELOG.md` under `Unreleased`, plus the maintained xref docs.
6. Gates: `uv run pytest tests/unit/ -v --no-cov`, `mvn test`,
   `mvn clean compile -q`, `git diff --check`.

Live verification against the real program requires the prepared Ghidra
instance and is reported as unexecuted otherwise.

Note on step 6: the full `mvn test` run has a known-flaky jump-table failure, a
pre-existing fixture race. If it is the only red, it is not a signal about this
change.
