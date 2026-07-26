# analyze_coverage — design

Date: 2026-07-26
Status: proposed (revised 2026-07-27 after review)

## Motivation

A reverse-engineering project is finished when no bytes are left unexplained. The API
cannot report how far from that a program is.

`find_code_gaps` looks like the tool for it and is not: it reports ranges "not covered by
any function body". A project that deliberately creates no function objects — labels,
comments and data only, which is a legitimate and recurring convention for 6502 snapshots
— gets its entire image reported as a gap. `find_next_undefined_function` has the same
premise. Neither answers "how many bytes are undefined, and where".

The cost of that hole, measured on a real target: a C64 memory-snapshot project believed
itself near completion, with a documented list of remaining unknowns scoped to one
subsystem. Deriving actual coverage required `export_full_listing` to a 953 KB file and an
ad-hoc Python parse of every code-unit line. The answer was **30,020 of 53,888 bytes
undefined**, in 28 runs, the largest 21,427 bytes, none of them in the documented unknowns
list. The project's own completion criterion had never been measurable through the API.

## Contract

`GET /analyze_coverage`, in a new `CoverageService`, category `analysis`. Read-only,
scalar parameters only, so no request body.

A new service rather than a method on an existing one: `ListingRangeService` is explicitly a
bounded range reader with cursor semantics, while this is a whole-program aggregate over
listing, memory, symbols, comments and references; and `AnalysisService` is already 5,384
lines of catch-all. Extracting the rest of `AnalysisService` is not in scope.

### Parameters

| name | required | notes |
| --- | --- | --- |
| `program` | no | existing selector convention |
| `min_run_length` | no | any positive `long`, default `1`; runs shorter than this are excluded from the page but still counted. No fixed ceiling — an earlier draft capped it at `0x1000000`, which is a 24-bit-target assumption in an endpoint that must also serve 32- and 64-bit programs. Values above the program's initialized byte count are accepted and simply match nothing |
| `limit` | no | `1`–`10000`, default `100`; applies to `undefined_runs` |
| `offset` | no | default `0`; applies to `undefined_runs` |
| `marker_limit` | no | `1`–`10000`, default `100`; applies to `unknown_markers` |
| `marker_offset` | no | default `0` |
| `unknown_marker_prefix` | no | default `TODO`; case-sensitive literal |
| `generic_prefixes` | no | comma-separated, default `DAT_,SUB_,LAB_,FUN_,UNK_` |

`unknown_marker_prefix` exists so the endpoint stays general. Scanning for a literal `TODO`
is one project's convention; hard-coding it would import that convention into a tool that
knows nothing about the project.

### Response

Two namespaces, because exact byte facts and convention-based audits are different kinds of
claim and must not read as one metric:

```json
{
  "program": "neverending_story.bin",
  "program_modification_number": 4213,
  "memory_coverage": {
    "spaces": [
      {"space": "RAM", "blocks": 1, "total": 53248,
       "instruction": 5855, "data": 17373, "undefined": 30020,
       "undefined_pct": 56.38},
      {"space": "SND_PLAYER", "blocks": 1, "total": 640, "overlay": true,
       "instruction": 639, "data": 1, "undefined": 0, "undefined_pct": 0.0}
    ],
    "uninitialized_ranges": [],
    "undefined_runs": {
      "items": [
        {"start": "RAM:42e2", "end": "RAM:9694", "length": 21427,
         "preceding_label": {"address": "RAM:42b6", "name": "ROOM_TEXT_28",
                             "distance": 44},
         "following_label": {"address": "RAM:9695", "name": "SND_TICK",
                             "distance": 1},
         "primary_labels_in_run": {"count": 2,
           "samples": [{"address": "RAM:5188", "name": "DAT_5188"},
                       {"address": "RAM:528a", "name": "DAT_528a"}]},
         "incoming_reference_count": 70}
      ],
      "all_count": 28, "eligible_count": 28,
      "below_min": {"count": 0, "bytes": 0},
      "offset": 0, "limit": 100, "returned": 28, "has_more": false
    }
  },
  "annotation_backlog": {
    "generic_symbols": {
      "totals": {"DAT_": 133, "LAB_": 292, "SUB_": 2, "FUN_": 0, "UNK_": 0},
      "samples": {"DAT_": ["RAM:1caf", "RAM:528a"], "SUB_": ["RAM:1605"]}
    },
    "unknown_markers": {
      "items": [
        {"address": "RAM:0460", "kind": "label", "text": "TODO_UNKNOWN_BYTE_0460"},
        {"address": "RAM:11a7", "kind": "eol_comment", "text": "TODO: classify the …"}
      ],
      "all_count": 34, "offset": 0, "limit": 100, "returned": 34,
      "has_more": false
    }
  }
}
```

Field rules:

- **Classification predicate.** `Instruction` → instruction. `Data` whose datatype
  satisfies `Undefined.isUndefined(dataType)` → **undefined**. Any other `Data` → data.
  Address gaps holding no stored code unit → undefined.
- **`Data.isDefined()` is the wrong predicate and must not be used.** It returns `true` for
  an explicitly applied `undefined1`…`undefined8`, returning `false` only for
  `DefaultDataType`. `Undefined.isUndefined(...)` is the intended API and also covers arrays
  of undefined types.
- **That predicate is load-bearing, not cosmetic.** On the motivating target, three
  apparently separate runs (`$42E2`–`$5187`, `$5189`–`$5289`, `$528B`–`$9694`) are one
  21,427-byte run once the two explicit `undefined1` units at `$5188` and `$528A` are
  classified correctly. Getting it wrong reports the largest unclassified region in the
  program as 17,418 bytes, split in three.
- Every byte of every initialized address falls in exactly one of `instruction`, `data`,
  `undefined`, and the three sum to `total` per space.
- **Initialization comes from `Memory.getAllInitializedAddressSet()`, not
  `MemoryBlock.isInitialized()`**, which returns `false` for byte-mapped and bit-mapped
  blocks even where the underlying bytes are initialized. Each block is intersected with
  that set; the complement is reported in `uninitialized_ranges` and never counted as
  undefined.
- **Overlay spaces get their own row**, flagged `overlay: true`. On banked or overlaid
  targets a blended percentage is meaningless.
- **Runs close at both kinds of boundary**, and the two are independent:
  - **every memory-block boundary**, even where adjacent initialized blocks coalesce inside
    an `AddressSet` — closing only on the set's boundaries would merge two blocks' runs;
  - **every initialized-range boundary inside a block**, so a run never bridges an
    uninitialized hole and silently claims bytes that do not exist.
- `preceding_label` / `following_label` are objects with address, name and distance, or
  `null` at a block edge. Bare names are omitted deliberately: this repository already
  learned on `get_references_into_range` that a nearest label hundreds of bytes away reads
  as containment when only the name is shown.
- **Runs do not split at labels**, because a label does not classify a byte and splitting
  would fragment exactly the regions this endpoint exists to surface.
  `primary_labels_in_run` is **inclusive of the run's first and last byte**, so a label at
  either end is disclosed rather than falling between "inside" and the outside neighbours.
- Statistics, `all_count`, `below_min` and the `generic_symbols` totals are always computed
  over the whole program, independent of paging. Each paged collection carries its own
  `offset`, `limit`, `returned` and `has_more`; there is no top-level `truncated`, which
  would conflate rows skipped before the page with rows remaining after it.
- **Envelope invariants**, which the tests assert directly:
  `all_count == eligible_count + below_min.count`, `returned == items.length`, and
  `has_more == (offset + returned < eligible_count)`. For markers, which have no
  `min_run_length` filter and therefore no `eligible_count`:
  `has_more == (marker_offset + returned < all_count)`.
- **Ordering is total for every collection**, since all of them are paged or sampled:
  `undefined_runs` by length descending then space name then address; `unknown_markers` by
  space name, then address, then kind in the fixed order `label`, `plate`, `pre`, `eol`,
  `post`, `repeatable`, then `text`, and for two labels at one address by namespace then
  name — a complete order, so a label and a comment at the same address never tie;
  `generic_symbols.samples` and `primary_labels_in_run.samples` by space name then address.
- `uninitialized_ranges` items are `{"block": name, "start": addr, "end": addr, "length":
  n}`, ordered by space name then start address.
- **The response echoes `program_modification_number`.** The before/after check below
  guarantees one request is internally consistent; the echo is what lets a caller notice
  that two `offset` pages came from different program revisions.
- `unknown_markers` covers labels whose name starts with the prefix and comments of every
  type (`eol`, `pre`, `post`, `plate`, `repeatable`) containing it, with `kind` identifying
  which. Comment text is truncated to 200 characters with a trailing `…`.
- `samples` holds at most 20 addresses per prefix.

### Errors

- `min_run_length`, `limit`, `offset`, `marker_limit`, `marker_offset` out of range —
  rejected with the permitted range.
- `generic_prefixes` empty after trimming — rejected.
- `unknown_marker_prefix` empty after trimming — rejected. An empty prefix matches every
  label and every comment, turning the backlog into a dump of the whole program.
- No program selected and multiple open — existing `ServiceUtils.getProgramOrError`
  message, unchanged.

### Deliberately excluded

- **Comment-density or "documented" scoring.** Heuristic scores invite arguing with the
  metric instead of reading the listing.
- **Per-function coverage.** That is `find_code_gaps`, and its premise is what this
  endpoint exists to avoid.
- **Suggestions.** No "this run looks like text/graphics" classification: deciding what a
  run is belongs to the analyst, and a guess in the coverage report would put an unverified
  claim into the artifact being checked.
- **Mutation.** Read-only.

## Implementation

`CoverageService` with `ProgramProvider`/`ThreadingStrategy` injection so GUI and headless
share it.

1. Compute `Memory.getAllInitializedAddressSet()` once and intersect per block.
2. **Do not walk `listing.getCodeUnits(...)` across every address**: Ghidra synthesizes one
   default undefined unit per uncovered address, making that walk proportional to every
   undefined byte. Merge `listing.getInstructions(range, true)` and
   `listing.getDefinedData(range, true)` and derive undefined stretches arithmetically from
   the gaps between stored units — the pattern `ListingRangeService.RangeIndex` already
   uses.
3. Accumulate per-space byte counts while merging undefined stretches into runs; close a
   run at a space or initialized-set boundary.
4. Annotate each run: preceding/following primary symbol with distance, inclusive
   in-run primary labels, and incoming references restricted to the run.
5. One `SymbolTable` pass for generic prefixes and marker labels; one
   `getCommentAddressIterator` pass per comment type for marker comments.
6. Sort, page, assemble.

The read spans several passes, so it captures `program.getModificationNumber()` before and
after and fails rather than returning a torn aggregate if the program changed underneath.

## Testing

Synthetic fixtures are authoritative for classification behaviour.

- **Classification:** explicit `undefined1`, `undefined2` and an array of undefined
  alongside real `byte`/`word` data, asserting the undefined ones land in `undefined` and
  the real ones in `data`; a program with zero functions; instructions adjacent to stored
  data with gaps between.
- **Memory shape:** a byte-mapped block whose `isInitialized()` is `false` while its bytes
  are initialized, asserting it is counted; a partially initialized block, asserting the
  uninitialized part appears in `uninitialized_ranges` and not in `undefined`.
- **Runs:** merging across explicit undefined units; not splitting at labels; labels at the
  first byte, an interior byte and the last byte all appearing in
  `primary_labels_in_run`; runs stopping at space boundaries; **two abutting initialized
  blocks not merging**, which fails if the implementation closes runs only on the
  initialized set; ties in length ordered deterministically across spaces; incoming
  references counted at both run endpoints.
- **Mutation-directed:** fixtures whose totals and exact run endpoints change under
  `Data.isDefined`, under block merging, under exclusive (rather than inclusive) endpoint
  labels, and under `MemoryBlock.isInitialized` — one failing test per wrong choice, so each
  decision above is pinned by something that would break.
- **Marker ordering:** markers inserted in reverse address order, and a page boundary
  falling between a label and a comment at the same address.
- **Paging:** `min_run_length` moving rows into `below_min` without changing `all_count`;
  a mid-list offset; an offset past the end; `has_more` correctness; statistics identical
  across pages; independent marker paging.
- **Markers:** a `TODO` label, a plate comment, an `eol` comment, a non-matching lowercase
  `todo`, and 200-character truncation.
- **Concurrency:** a modification landing mid-read fails the call rather than returning
  mixed numbers.
- **Catalog and wiring:** `RegenerateEndpointsJson`, `EndpointsJsonParityTest`,
  `test_endpoint_catalog.py`, `ServiceFactory`, TCP plugin, UDS `ServerManager`, headless
  handler, annotation scanner, GUI/headless parity, maintained docs, `CHANGELOG.md`.
- **Integration:** assert response fields and shape, not merely HTTP 200.

### The C64 numbers are acceptance evidence, not a regression gate

The figures in the response example above come from the motivating project. They are **not**
pinned as a test. Coverage of a live analyst project is *supposed* to change — typing the
21 KB of illustration data in that very project will move `undefined` by more than 21,000
bytes, and a gate would then fail for the best possible reason.

They are recorded here as dated acceptance evidence, to be reproduced once by hand at
implementation time and reported in the changelog entry:

- snapshot `neverending_story.bin`, sha256 to be recorded with the result
- Ghidra 12.1.2, program database as of commit `99b465c`
- `RAM`: instruction 5855, data 17373, undefined 30020 (56.38%)
- `SND_PLAYER`: instruction 639, data 1, undefined 0
- 28 undefined runs, largest `RAM:42e2`–`RAM:9694` of 21427 bytes
- `DAT_` 133, `LAB_` 292, `SUB_` 2; 34 unknown markers

One caveat on that derivation: it classifies instructions by a three-uppercase-letter
mnemonic in the exported listing rather than by code-unit type. The undefined figures are
robust to that (`??` and `undefined\d*` are unambiguous in the export), but a disagreement
confined to the instruction/data split should be checked against the listing before the
endpoint is assumed wrong.
