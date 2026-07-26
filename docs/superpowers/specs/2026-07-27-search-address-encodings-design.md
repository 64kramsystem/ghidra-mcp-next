# search_address_encodings — design

Date: 2026-07-27
Status: proposed (revised after review round 2)

Supersedes the "Extension: unreferenced address encodings" section of
`2026-07-26-references-into-range-design.md`, which proposed folding this into
`get_references_into_range`. Review argued the two belong apart and it is right: see
[Why not an extension](#why-not-an-extension).

## Motivation

`get_references_into_range` reports what the reference database holds, and says so:
`scope: "recorded_references_only"`. Bytes that *encode* an address in the queried range
without a recorded reference never appear — an operand the analyzer left unresolved, an untyped
pointer table, a pointer sitting in a run of undefined bytes.

On an overlay target that omission is not cosmetic. In the motivating project, four call sites
from game code into a recovered SID player (`$A884`, `$0703`, `$0706`, `$15CC`) were found by
reasoning about the program rather than by querying it, and a sweep that missed a fifth would
have looked identical to a complete one.

## Why not an extension

- The two answer different questions. One enumerates semantic references indexed by
  destination; the other reports raw byte windows that numerically decode into a range and
  carries **false positives by construction**.
- The proposed flag was misnamed: `include_unreferenced_encodings` would have returned both
  referenced and unreferenced rows.
- This query needs parameters meaningless on a reference lookup: encoding width, byte order,
  and a *source* scope distinct from the destination range.
- It needs resumable traversal. A broad range over a large program can produce tens of
  thousands of accidental matches, and a `limit` with a truncation flag caps the body without
  offering a route to the rest.

## Contract

`GET /search_address_encodings`, category `search`. Shares `MemorySearchCore` — the bounded
chunk scanner specified in the `search_byte_patterns` hardening document — with byte-pattern
search.

### Parameters

| name | required | notes |
| --- | --- | --- |
| `start` | yes | inclusive start of the **destination** range being looked for |
| `end` | yes | inclusive end of the destination range; same space as `start` |
| `width_bytes` | no | `1`–`8`, default `2` |
| `byte_order` | no | `little` or `big`; default `little` |
| `source_start` | no | restrict where the scan looks; requires `source_end`, same space as it |
| `source_end` | no | inclusive |
| `limit` | no | `1`–`10000`, default `1000` |
| `cursor` | no | authenticated continuation token from a previous page |
| `program` | no | existing selector convention |

`width_bytes` spans `1`–`8` because one-byte zero-page addresses and eight-byte pointers are
both ordinary address encodings; decoding uses unsigned `BigInteger` so no width is a special
case. Destination bounds not representable in the selected width are **rejected**, rather than
silently producing an empty result that looks like a clean sweep.

`byte_order` and `width_bytes` are explicit because the original proposal silently assumed
16-bit little-endian — right for 6502, wrong nearly everywhere else.

### Response

The destination range is what fixes which rows can appear. This example queries the overlay
occupant of `$9680`–`$98FF`:

```json
{
  "destination_range": "SND_PLAYER::9680 - SND_PLAYER::98ff",
  "source_scope": {"mode": "all_initialized_memory", "spaces": ["RAM", "SND_PLAYER"]},
  "width_bytes": 2,
  "byte_order": "little",
  "scope": "byte_encodings_of_destination_range",
  "encodings": [
    {"encoding_address": "RAM:a885", "site_address": "RAM:a884", "site_space": "RAM",
     "decoded_offset": "9695", "decoded_target": "SND_PLAYER::9695",
     "site": "inside_instruction",
     "site_rendering": "JSR SND_PLAYER:SND_TICK",
     "matching_references": [
       {"to": "SND_PLAYER::9695", "type": "UNCONDITIONAL_CALL",
        "source_kind": "user_defined", "operand_index": 0, "primary": true}
     ]},
    {"encoding_address": "RAM:0454", "site_address": "RAM:0453", "site_space": "RAM",
     "decoded_offset": "9700", "decoded_target": "SND_PLAYER::9700",
     "site": "inside_instruction",
     "site_rendering": "JSR DISK_LOADER_ENTRY",
     "matching_references": []},
    {"encoding_address": "RAM:5a3c", "site_address": "RAM:5a3c", "site_space": "RAM",
     "decoded_offset": "9680", "decoded_target": "SND_PLAYER::9680",
     "site": "undefined",
     "matching_references": []}
  ],
  "returned": 3,
  "limit": 1000,
  "cursor": null,
  "has_more": false,
  "program_modification_number": 4213
}
```

- **`decoded_offset` is the raw decoded number; `decoded_target` is it qualified into the
  queried destination space.** A bare `encodes` field could not say which occupant a numeric
  offset refers to, which is the whole problem on an overlaid program.
- **`matching_references` is space-specific and consistent with the query.** A reference counts
  only when its destination equals `decoded_target` in **both space and offset**. The
  overlay query above therefore shows the player call with its reference, and shows
  `$0453 JSR $9700` — a real byte window into the queried offsets — with an **empty** array,
  because its recorded reference targets `RAM:9700`, the disk loader. The equivalent `RAM`
  query inverts exactly that. Both facts are pinned, by two separate calls, and neither call
  returns both spaces' references.
- The array stays plural because several references can share one fully qualified destination
  while differing in `operand_index`, `type` or `source_kind` — audit distinctions the sibling
  endpoint already preserves.
- **`site` is `inside_instruction`, `inside_data_unit`, or `undefined`** — deliberately *not*
  `instruction_operand`. A window beginning inside an instruction is not necessarily an
  operand: it may start on the opcode or straddle a code-unit boundary, and Ghidra's
  `Instruction` API does not portably map operand indices to contiguous byte spans.
  `matching_references` carries the semantic evidence instead.
- Reference origins are defined for all three site kinds: for an instruction site, references
  are read **from the instruction start**; for a data site, from the **containing primitive
  component's start**; for an `undefined` site, from the **`encoding_address` itself**, there
  being no containing unit.
- `container` appears on `inside_data_unit` rows only, shaped
  `{"address": addr, "name": symbol, "offset": n}` where `address` is the containing unit's
  start and `offset` is `encoding_address - address`.
- `matching_references` is ordered deterministically: by `to` address, then `type`, then
  `operand_index`, then `source_kind`.
- `site_rendering` uses the operand-by-operand `CodeUnitFormat` path that
  `get_references_into_range` settled on, so symbols resolve and overlay qualifiers survive.
- Every offset is tested, **unaligned included** — 6502 operands are not aligned — and
  overlapping windows are separate rows, because either could be the real operand.
- The **entire** encoding window must lie inside the source range and inside one scanned
  initialized range within one block; a window straddling either boundary is not reported.
- `scope` states what the result claims: exhaustive *encodings*, a checkable fact about bytes.
  It does not claim exhaustive *meaning*.

### The cursor is authenticated, not merely opaque

Paging is a forward traversal, so a cursor — not `offset` — is what guarantees a route to the
remainder. It reuses the **HMAC pattern already implemented in `ListingRangeService`** rather
than a decodable-but-tamperable token, and binds:

- cursor format version;
- program identity and `program_modification_number`;
- destination space, start and end;
- `width_bytes` and `byte_order`;
- source-scope mode and, when set, source start and end;
- the **first unreturned candidate address** and its space (see below).

**Lookahead and inclusive resume.** Establishing `has_more` honestly requires finding one more
match than the page returns, and that extra match must not then be lost. The rule:

1. retain the first `limit` matches;
2. keep scanning until either one additional match is found or the traversal is exhausted;
3. if an additional match is found, emit `has_more: true` and bind **that match's own address**
   as the cursor's `resume_address`;
4. resuming starts **inclusively at `resume_address`**, deliberately retesting it, so the
   lookahead match is returned as the first row of the next page;
5. if no additional match exists, return `cursor: null` and `has_more: false`.

The field is named "first unreturned candidate address" rather than "next untested address"
because it is deliberately a *tested* address. Binding the next untested address instead would
drop the lookahead row, and stopping at exactly `limit` without lookahead could only claim that
unscanned addresses remain — which produces a final empty page whenever the tail holds no
further match.

Rows are traversed and returned in a total order: address-space name, then offset.

A cursor whose HMAC fails, or whose bound values differ from the current request, is rejected
as stale rather than reinterpreted. `limit` **may** change between pages, since it does not
affect which rows exist.

The modification number is checked when accepting a cursor **and again after producing each
page**, because an edit landing during the scan or during reference enrichment would otherwise
yield a torn page. No total count is promised: computing one requires the full scan the cursor
exists to avoid.

### Errors

- `start` > `end`, endpoints in different spaces, unresolvable endpoints — as
  `get_references_into_range`.
- `source_start` without `source_end`, reversed, or in different spaces — rejected.
- `width_bytes` outside `1`–`8`, unknown `byte_order` — rejected with permitted values.
- Destination bounds not representable in `width_bytes` — rejected.
- Stale, tampered or mismatched cursor — rejected, naming which bound value differs.

## Testing

- A byte-encoded pointer in an undefined run with no recorded reference: `site: "undefined"`,
  empty `matching_references`.
- An instruction site carrying a reference: populated `matching_references` including
  `source_kind` and `operand_index`, with `encoding_address` one byte past `site_address` for a
  three-byte instruction.
- **Windows that defeat the weaker classification:** one beginning on an opcode byte, and one
  straddling a code-unit boundary — both reported as `inside_instruction` with no operand claim.
- An encoding inside a `dw[]` array: container reported, references read from the containing
  primitive's start rather than the array's.
- **Two separate calls proving space exclusivity**: the overlay-range query and the RAM-range
  query over the same offsets each return only their own occupant's references, with the
  disk-loader window showing an empty array in the overlay query.
- All widths `1`–`8`, both byte orders, including a big-endian fixture that must **not** match
  the little-endian bytes, and a destination bound unrepresentable in `width_bytes` rejected.
- Unaligned detection at an odd offset; overlapping windows at consecutive offsets both
  reported; a window straddling a source-range edge and one straddling a block edge both
  absent.
- **Lookahead boundaries:** exactly `limit + 1` sparse matches, asserting the `(limit + 1)`th
  is returned as the first row of page two rather than lost; exactly `limit` matches with
  nothing after them, asserting `cursor: null`, `has_more: false` and **no trailing empty
  page**.
- **Concurrency:** a modification landing during the scan, and again during reference
  enrichment, each failing the request — so the post-page check is shown to be load-bearing
  rather than decorative.
- **Cursor:** continuation covering the full result across pages with no duplicates or gaps;
  continuation across initialized holes and long non-matching spans, not only dense adjacent
  hits; a tampered HMAC rejected; a cursor rejected after each of program, modification number,
  destination range, source range, width and byte order changes; `limit` changed mid-traversal
  accepted.
- Mutation checks on the destination-range and space comparisons, following the precedent that
  only mutation distinguished a real assertion from a passing one on the sibling endpoint.
- Characterization against the frozen C64 snapshot: an overlay-range sweep of
  `$9680`–`$98FF` surfaces the four known game-code call sites into the player.
- Catalog, wiring, GUI/headless parity, `CHANGELOG.md`, and integration tests asserting
  response fields rather than HTTP 200.
