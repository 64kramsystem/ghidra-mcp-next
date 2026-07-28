# `export_full_listing`: a complete disassembly listing export

Date: 2026-07-25
Status: implemented, with the known gaps listed under "Not yet delivered"

## Not yet delivered

Recorded here rather than left implied by the rest of this document:

- **Structured data components are not traversed.** For a structure, Ghidra's top-level
  `getDefaultValueRepresentation()` is normally empty, and the writer does not walk `Data`
  components, so field names, component types and component values are absent. Ghidra's own
  exporter recurses (`ProgramTextWriter.processSubData`). Until this is fixed, "drops nothing"
  is accurate for instructions, comments, labels, references and flat data, **not** for
  structured data. Relevant to C64 vector tables and structured register data.
- **Data operands** use `Data.getDefaultValueRepresentation()` rather than `CodeUnitFormat`,
  so a pointer or vector may render numerically even where an overlay label exists.
- **No program modification-number guard.** `ListingRangeService` pins one; this writer does
  not, so a concurrent edit mid-export is neither detected nor rejected. It takes no read lock
  either, matching `export_ascii_listing`.
- **Outgoing references** are not emitted; only incoming ones, direct and offcut.
- **Comment-body integrity is not checked**, only per-record cardinality: a record whose text
  was mangled or partially emitted still counts as one emitted record.
- Tests not yet written: end-of-address-space bounds, base and overlay units at the same
  numeric offset, more than 64 incoming references, injected reference omission, short memory
  read, output-stream failure, PETSCII/control-character rendering.
- The whole-program run against `neverending_story.bin` through the deployed plugin is
  **unverified**; it needs a Ghidra restart to load the new jar.

## Problem, measured on a real program

Verified against the live `neverending_story` project (C64, 6502, Ghidra 12.1.2) by exporting
the whole program with the existing `export_ascii_listing` — 53,969 lines, 4.8 MB — and
comparing against the program itself.

**1,164 lines in that export are clipped.** By category:

| Loss | Count | Example |
|---|---|---|
| EOL comments clipped at 40 chars | 173 | `;Swap the hidden loader into executio...` — actual text is `Swap the hidden loader into execution space.` |
| Plate/repeatable comments clipped | 111 | `…into $CC00-$C...*` — actual text continues `$CC00-$CFFF, then executes it at $CC00.` |
| Byte field clipped at 12 chars | 285 | `000000010...` for a `db[32]` |

**References are silently dropped, and the header misreports the count.** `RAM:0002`
(`SCRATCH_BYTE`) has 28 direct references. The export emits `XREF[21]` and lists 21,
omitting `14a0(W) 14a6(R) 15e8(W) 15ed(R) 15fd(R) 1229(W) 122c(R)`. Across the whole export
the direct-xref distribution climbs to 20 and 21 and then stops dead — the empirical
signature of `ReferenceLineDispenser.getXRefList`'s hardcoded `int maxXrefs = 20` requested
as `maxXrefs + 1`.

The four mechanisms in the Ghidra source:

1. **Field clipping.** `ProgramTextWriter` passes fields through
   `AbstractLineDispenser.clip()`, which replaces the tail with `...`.
2. **EOL comment ceiling.** `ProgramTextWriter.addComments` builds
   `new EolComments(cu, true, 6 /* arbitrary */, eolOption)`; `loadEols` feeds the code
   unit's own EOL comment through `addStrings`, which stops at the 6-line budget.
3. **Reference ceiling.** `maxXrefs = 20`, as measured above.
4. **Unreachable widths.** Stack variable name/datatype/storage/comment widths (15/15/8/20)
   are `ProgramTextOptions` fields `getOptions()` never publishes.

Widening the nine configurable widths addresses only mechanism 1. That is why the
`field_widths` approach was abandoned: it would have produced an export that looks fixed
while still dropping 7 references from `RAM:0002` and truncating any 7-line EOL comment.

## Goal and non-goals

A listing where nothing is dropped, enforced at runtime rather than asserted in docs.

Non-goals: not reassemblable source (a later mode); not byte-compatible with Ghidra's
format; no change to `export_ascii_listing`; no change to `AsciiExporter`.

## Architecture

One new tool, `export_full_listing` (POST), in `ExportService` — reusing that class's tested
pipeline unchanged (path validation, `GHIDRA_MCP_FILE_ROOT`, sibling-temporary write,
atomic publication, cleanup on failure) via a second `ExportRunner` implementation. The
`AsciiExporter` runner is untouched.

**The annotation gathering is reused, not rewritten.** `ListingRangeService.RangeIndex`
already collects labels, comments and references into typed `UnitMetadata` /
`LabelRecord` / `CommentRecord` records, driven from `listing.getCommentAddressIterator`,
`getReferenceSourceIterator` and `getReferenceDestinationIterator`. Those iterators
enumerate every address carrying an annotation, **including offcut addresses** inside a
multi-byte instruction. Writing a second walker would duplicate tested code and re-earn its
bugs — in particular the offcut case, which `WORK_PTR`'s real `XREF[21,60]` header shows is
live in this program (60 offcut references).

The `Map<String,Object>` conversion in `ListingRangeService` happens only at `renderUnit`,
so reuse happens at the typed-record level. No JSON round-trip and no map casts.

`RangeIndex` becomes package-visible for this; it is already `static final class`.

| Unit | Responsibility |
|---|---|
| `ExportService` | parameters, paths, publication, error mapping (existing) |
| `CompleteListingWriter` | render typed records to text; no file/path/MCP knowledge |
| `ListingRangeService.RangeIndex` | annotation gathering (existing, reused) |

### No paging

`ListingRangeService`'s cursor and `max_units` / `max_bytes` machinery exists because a JSON
response must be bounded. A file export has no such constraint: it streams unit by unit to
the temporary file. Paging, cursors and completeness flags are therefore absent from this
design. `max_incoming_refs_per_unit` is passed unlimited.

### Operands must be formatted, not taken from `operand_text`

`ListingRangeService.operandText` uses `instruction.getDefaultOperandRepresentation(index)`,
which is deliberately raw: at `RAM:03a0` it yields `0x03a6` where the listing should read
`JSR SWAP_FASTLOADER_IMAGE`. The writer therefore constructs a `CodeUnitFormat` with the
same options Ghidra's own exporter uses — `ShowBlockName.NON_LOCAL`,
`ShowNamespace.NON_LOCAL`, register-variable markup — and calls
`getOperandRepresentationString`, then does not clip the result.

`ShowBlockName.NON_LOCAL` is load-bearing here: this program has an overlay space
(`SND_PLAYER::9680–98ff`), and operands crossing into it must stay block-qualified.

## Completeness guarantee

Reduced from the original independent-second-pass design, because gathering is now shared
with tested, offcut-correct code. Two checks remain:

1. **Emit-side equality.** The writer counts records handed to it by `collectMetadata` and
   records it emitted, per kind, and fails if they differ. This catches the realistic
   remaining bug: a comment kind or reference direction the renderer forgets. Comment kinds
   are enumerated with `CommentType.values()`, following `ListingRangeService`, so a kind
   added by a future Ghidra release is counted rather than silently skipped.
2. **Coverage.** The walk must reach the end of every requested range. A gap means a skipped
   code unit and fails the export.

On either failure: `Response.Err` naming the shortfall, temporary file deleted, existing
destination untouched. Nothing is ever partially published.

## Output format

Governing rule: **columns are minimum widths, never maximums.** A long operand pushes the
comment column right; nothing is shortened. No clip step exists in the writer.

- **Provenance header** — program name, SHA-256, MD5, language id, compiler spec, exported
  ranges, Ghidra version. No timestamp, so repeated exports of an unchanged program are
  byte-identical and diffable.
- **Per memory block** — name, range, permissions, initialized. Overlay blocks included.
- **Per code unit** — plate comment (boxed, one output line per authored line) →
  pre-comments → labels, namespace-qualified, primary marked → `XREF[n]:` listing *every*
  reference, wrapped at `xref_wrap_column`, with offcut references in their own labelled
  group → the address / bytes / mnemonic / operand line carrying the first EOL comment line,
  further authored EOL lines on aligned continuations → post-comments.
- **Function entries** — signature, parameters and locals with name, datatype, storage, and comments; multiline comments continue on aligned assembly-comment lines.
- **Undefined bytes** — emitted as data lines, so every address in range is accounted for.
- **Trailing symbol index** — sorted label to address.

Authored newlines are never re-flowed, so aligned bit tables and ASCII diagrams survive.
Empty and whitespace-only listing-comment lines remain present as a bare `;`; an offcut blank line retains its location marker. Variable comments containing no content are omitted. Trailing spaces and tabs are removed from all comment output, while other control bytes remain verbatim.
Only the machine-generated xref list wraps.

## Parameters

| Name | Source | Default | Notes |
|---|---|---|---|
| `output_path` | body | required | resolved within `GHIDRA_MCP_FILE_ROOT` |
| `start` | body | absent | inclusive; must accompany `end`, same address space |
| `end` | body | absent | inclusive |
| `overwrite` | body | `false` | replaces destination only after success |
| `program` | query | active | standard selector |
| `xref_wrap_column` | body | `100` | accepted 40–500 |

Whole-program export uses `program.getMemory()`, which includes overlay blocks — matching
what `export_ascii_listing` already reports for this program.

## Testing

Real-Ghidra tests in `ExportServiceGhidraTest`, each targeting a measured loss:

1. A 7-line EOL comment survives in full (mechanism 2).
2. Twenty-five references to one address all appear (mechanism 3; `RAM:0002` has 28).
3. A 40-character label is not clipped (mechanism 1).
4. A long operand is not clipped, and resolves to a symbol rather than a raw address.
5. Long parameter/local metadata is not clipped (mechanism 4).
6. A 32-byte data unit's bytes are not clipped (measured: 285 occurrences).
7. Offcut comments and offcut references are emitted.
8. Operands into an overlay block stay block-qualified.
9. Undefined bytes appear as data lines covering the whole range.
10. An injected defect — a renderer that skips one comment — fails the export with nothing
    published, proving the emit-side check bites.
11. Two exports of an unchanged program are byte-identical.

Run with:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
GHIDRA_INSTALL_DIR=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
mvn -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest=ExportServiceGhidraTest test
```

Offline tests in `ExportServiceTest`: parameter validation, `xref_wrap_column` bounds,
publication safety, and that the Ascii runner's payload gains no new fields.

Final acceptance is on the real program: export `neverending_story.bin`, and confirm zero
clipped lines and that `RAM:0002` lists all 28 references.

Then the standard gates: catalog regeneration and parity, `uv run pytest tests/unit/`,
`mvn test`, `mvn clean compile`, `git diff --check`, `CHANGELOG.md` `Unreleased` entry.

## Environment notes

- CI pins JDK 21; local default is JDK 26. The dangling-comment cleanup on this branch made
  JDK 26 compile cleanly too.
- `MemoryBlockCoreTest.securedFileReadUsesPinnedSizeAndReadsOnlyTheRequestedSlice` fails on
  this machine for an unrelated reason: `SecurityConfig.readFileRangeWithinRoot` requires a
  `SecureDirectoryStream` and this filesystem provider does not return one. A platform gap,
  not a test defect; out of scope.
