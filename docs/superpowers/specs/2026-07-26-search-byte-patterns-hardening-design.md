# search_byte_patterns — hardening

Date: 2026-07-26
Status: proposed (revised 2026-07-27 after review)

## Motivation

The endpoint works. A project note claimed it "returned a single hit for `20 ?? 97` when
several exist, so it does not match exhaustively", and that claim is false: tested against
the program it was written about, it returns all 11 matches in the main block plus 3 in an
overlay, each correctly space-qualified. An independent scan of the same image finds exactly
the same 11. The note was never verified and has been repeated since; this document records
the retest so it stops propagating.

What is actually wrong is smaller and real:

1. **`mask` is accepted and ignored.** The parameter is declared, documented as "Pattern
   mask", and never read by the implementation — wildcards come only from `?` in `pattern`.
2. **No range scoping.** Every search covers every initialized block.
3. **Truncation is signalled in-band.** At the 1,000-match cap the implementation appends
   `{"note": "Limited to 1000 matches"}` as an element of the results array, and on zero
   matches returns `[{"note": "No matches found"}]`. A naive consumer treats the note as a
   match.
4. **The whole block is read into one `byte[]` and read failures are skipped silently.** A
   `block.getBytes` exception `continue`s to the next block, so a count presented as exact
   can omit a block without saying so.

## Contract

`GET /search_byte_patterns` keeps its path. Parameters added, response shape replaced.

**Category corrected to `search`.** The annotation currently says `analysis` while
`tests/endpoints.json` carries `search`; the catalog value is the better one, so the
annotation changes to match rather than the catalog being regenerated to the drift.

### Parameters

| name | required | notes |
| --- | --- | --- |
| `pattern` | yes | hex bytes, whitespace ignored; `??` is a wildcard byte; **at most 65,536 bytes** |
| `mask` | no | hex bytes, same byte count as `pattern`; bit mask, `00`–`FF` |
| `start` | no | inclusive; requires `end` |
| `end` | no | inclusive; requires `start` |
| `limit` | no | `1`–`10000`, default `1000` |
| `offset` | no | default `0` |
| `program` | no | existing selector convention |

`mask` is honoured with **bit-mask semantics mirroring `Memory.findBytes`** — a bit set in the
mask must match the corresponding pattern bit. Mirrored rather than reused: the implementation
below deliberately does not call that API, but adopting its semantics keeps the meaning
Ghidra's rather than invented. Partial bytes such as `F0` are valid and useful.

**Default mask, stated explicitly** so composition is unambiguous: a literal pattern byte
starts at `FF`, a `??` byte starts at `00`, and any caller-supplied `mask` is **ANDed** with
that default. Neither mechanism can re-enable a bit the other waived.

The pattern length cap exists for the scanner's memory bound: the chunk scanner retains
`patternLength - 1` bytes between chunks, so an unbounded pattern would defeat the fixed
buffer. Memory is bounded by `chunkSize + patternLength`, and the 64 KiB request cap bounds
the second term.

`start`/`end` follow `get_references_into_range`: both or neither, `start <= end`, same
address space. **The entire match must fit inside the range**, not merely its first byte.

### Response

```json
{
  "pattern": "20??97",
  "effective_mask": "ff00ff",
  "wildcard_count": 1,
  "scope": {"mode": "all_initialized_memory", "spaces": ["RAM", "SND_PLAYER"]},
  "matches": [
    {"address": "0453", "address_full": "RAM:0453", "address_space": "RAM"},
    {"address": "9698", "address_full": "SND_PLAYER::9698", "address_space": "SND_PLAYER"}
  ],
  "total_matched": 14,
  "returned": 14,
  "limit": 1000,
  "offset": 0,
  "has_more": false,
  "program_modification_number": 4213
}
```

- An envelope replaces the bare array. This is a breaking change, taken deliberately rather
  than shimmed: per `AGENTS.md`, breaking changes are acceptable when they produce a better
  contract, ride a minor version bump, and are recorded in `CHANGELOG.md`.
- Zero matches returns `"matches": []`. Empty is data, not a note.
- `effective_mask` echoes the normalized mask actually applied. `pattern` plus
  `wildcard_count` cannot reconstruct which bits an explicit mask waived.
- **`wildcard_count` is defined as the number of fully waived bytes — zero bytes in
  `effective_mask`** — not the number of `??` tokens. The two differ when a caller passes an
  explicit `00` mask byte against a literal pattern byte, and the field is about what the
  search did, not what the caller typed.
- `scope` has two shapes, and the range form searches **only** the named space:
  - `{"mode": "all_initialized_memory", "spaces": [...]}`
  - `{"mode": "range", "start": "RAM:0000", "end": "RAM:cfff", "spaces": ["RAM"]}`
- **Ordering is total and defined before paging**: by address-space name, then by offset.
  `offset` is meaningless without it.
- `has_more` replaces `truncated`, and `total_matched` is the pre-paging count, so a caller
  can page deterministically.

### Implementation: a bounded chunk scanner, not `Memory.findBytes`

An earlier revision specified `Memory.findBytes`. That cannot deliver this contract, and the
reason is in Ghidra's implementation: `MemoryMapDB.findBytes` wraps its candidate reads in
`try`/`catch` and returns `null` on failure, so **a read error is indistinguishable from "no
match"**. An endpoint that promises to surface read failures cannot be built on it. It also
constrains only the candidate *start* against `endAddr`, so it cannot enforce "the whole
match lies inside the range" by itself.

Instead, a `MemorySearchCore` shared by this endpoint and `search_address_encodings`:

- iterate the initialized set intersected with each block, **never crossing a block
  boundary**;
- read fixed-size chunks with `width - 1` bytes of overlap retained within the same range, so
  a match spanning a chunk seam is still found while memory use stays bounded;
- compare with Ghidra's own semantics, `(memoryByte & maskByte) == (patternByte & maskByte)`;
- treat an exception or a short read as a **structured error** naming the block and address,
  never as a miss;
- take the last legal candidate in a range as `rangeEnd - (patternLength - 1)`, which is what
  makes the whole-match-inside-range rule true rather than aspirational;
- advance one byte past each hit, so overlapping matches all appear.

**Paging streams; it does not accumulate.** Ranges are scanned in the defined total order,
every match is counted, and only the requested page is retained. Retaining all matches would
reintroduce an unbounded allocation by another route: an all-zero effective mask matches at
every offset, so a 16 MB program yields ~16 million rows.

**The scan is checked for tearing.** `program.getModificationNumber()` is captured before and
after, and a change fails the request rather than returning a `total_matched` that was never
true of any single program state. The number is echoed as `program_modification_number`, so a
caller can also tell that two `offset` pages came from different revisions — a multi-megabyte
scan is long enough for that to matter.

### Documented limitation

A match straddling the end of one initialized range and the start of the next is not found.
Ranges are scanned independently; a pattern spanning the seam would assume adjacency of
unrelated content. Stated in the tool description, not left for a caller to discover.

### Deliberately excluded

- **Alignment filters and "search only undefined bytes".** Post-filters the caller can
  apply; no parameter until something asks.
- **Listing context per match.** Answering "what does this site mean" belongs to
  `search_address_encodings` (companion spec). This endpoint stays a byte matcher.

## Testing

- **Mask:** a partial byte such as `A0` with mask `F0`; composition with `??`; a
  length-mismatched mask rejected; malformed patterns (odd digit count, single `?`)
  rejected.
- **Scoping:** a match wholly inside the range found; a match beginning inside but ending
  past `end` excluded; a range in one space not returning an identical offset in another;
  initialized holes inside a mapped block skipped correctly.
- **Matching:** overlapping matches all returned; identical offsets in `RAM` and an overlay
  both returned and correctly qualified; block seams behaving as documented.
- **Paging:** deterministic order across spaces, blocks and offsets; a mid-list offset; an
  offset past the end; `has_more` and `total_matched` consistency.
- **Robustness, via a scanner fake rather than a giant fixture:** the fake records the
  **absolute maximum** buffer the core ever requests and asserts it against
  `chunkSize + patternLength`, including a run with a 64 KiB pattern so the cap itself is
  exercised. Constructing an enormous block would only make the test slow while proving less.
- **Two distinct read failures**, since they take different code paths: a read that *throws*,
  and a read that returns *short*. Each must surface as a structured error naming the block and
  the address — not as a miss, and not as a silently short `total_matched`.
- **Tearing:** a modification landing mid-scan fails the request; `program_modification_number`
  is echoed and differs across two pages taken around an edit.
- **Mask sensitivity:** a case where ignoring the explicit mask changes the result set, so a
  regression to the old ignore-the-mask behaviour fails; `??` composed with an explicit mask;
  an all-zero mask (matching everywhere) paged without accumulating; the last-legal-candidate
  boundary at `rangeEnd - (patternLength - 1)`.
- **Chunking:** a match straddling a chunk seam inside one range is found (the overlap
  retention), while a match straddling a block boundary is not (the documented limitation).
- **Regression, dated evidence not a gate:** pattern `20 ?? 97` over the frozen C64 snapshot
  returns 14 matches, 11 in `RAM` and 3 in `SND_PLAYER`. Recorded with the image's sha256 and
  overlay layout so any future "it under-reports" claim has something concrete to check.
- **Catalog and wiring:** regeneration, parity, bridge normalization, category change
  recorded in `CHANGELOG.md`.
- **Integration:** assert response fields, not merely HTTP 200.
