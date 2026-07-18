# proofread-transparency

An **independent, out-of-band** verifier for every book published on
[proofreadbtc.com](https://proofreadbtc.com). It runs on a schedule here — on
infrastructure the site does not control — and checks each published book
against a **pinned, out-of-band ground truth**, rooting its trust in Bitcoin and
in this repo rather than in anything the site asserts at request time.

## Why a pin, not just "verify the anchor"

OpenTimestamps proves *"these exact bytes were stamped into Bitcoin at time T."*
It does **not** prove they are *the published* bytes — anyone can cheaply stamp
arbitrary bytes. So a server operator could tamper the text, build a new
manifest matching it, stamp that forgery, and serve a perfectly self-consistent
lie. The only defense is a ground truth the site cannot silently rewrite.

That ground truth is [`books.json`](./books.json) — the **pins**. For each book
it records the known-good `manifestHash` (SHA-256 of the exact Bitcoin-anchored
manifest), the `blockHeight`, and the `blockHash`, captured at a verified moment
and committed here. Any change to a pin is a visible, timestamped commit in this
repo's public history. The watchdog trusts the pin, not the live server.

## What each run checks

1. **Manifest binding** — `sha256(served manifest) === pin.manifestHash`. One
   check binds the entire anchored file list (every file's hash + the root hash)
   to the pin.
2. **Content integrity** (`node:crypto` only, no dependency) — recompute every
   file's SHA-256 and compare to the pin-bound manifest hash.
3. **Anchor integrity** (OpenTimestamps + two independent explorers,
   [blockstream.info](https://blockstream.info) + [mempool.space](https://mempool.space)) —
   the manifest's `.ots` proof commits to a real Bitcoin block whose merkle root
   matches, at exactly `pin.blockHeight` / `pin.blockHash`.
4. **Roster** — every pinned book is still listed and served (an operator can't
   hide a book by dropping it from the API).

A book the site serves but that isn't pinned yet is reported `UNPINNED` (exit 2)
— never silently "OK." A human reviews it and adds a pin.

Because it runs its own code on its own infrastructure and roots trust in a pin
it controls, it catches tampering an in-browser verifier (which runs page
JavaScript the site delivers) structurally cannot — including a swapped-out
verifier and an operator who re-anchors a forgery to a new block.

## The log

`log/YYYY-MM.jsonl` is an append-only, timestamped record — one line per run — of
what was verified: each book's version, root hash, the Bitcoin block its anchor
resolves to, and the verdict. Anyone can read the history and re-run the exact
check:

```bash
npm ci
WATCHDOG_BASE_URL=https://proofreadbtc.com npm run verify
```

Exit code: **0** = every pinned book verified; **1** = tampering (a text
mismatch, a manifest that doesn't match its pin, a wrong anchor block, or a
pinned book gone missing); **2** = operational (a site/explorer was unreachable,
a proof is pending, or a served book isn't pinned yet).

## Updating pins when a new book is published (or a book is re-published)

```bash
npm ci
WATCHDOG_BASE_URL=https://proofreadbtc.com node verify-watchdog.mjs --emit-pins > books.new.json
# EYEBALL the new pins against a block explorer, then replace books.json and commit.
```

`--emit-pins` only emits a pin for a book whose anchor it could verify to a real
Bitcoin block, so a pin is always Bitcoin-backed at capture. Re-verify by eye
before trusting a fresh capture — first observation is trust-on-first-use.

## What this does and doesn't prove

It proves the **content served for each published book matches the exact bytes
pinned to a specific Bitcoin block**. It is **tamper-evident, not tamper-proof**:
it detects and alerts after the fact — it cannot prevent a server from serving
altered content, and it verifies the canonical content artifacts, not the
rendered reader HTML (binding those is the content-addressing North Star). Trust
is rooted in Bitcoin, in the pins here, and in explorers this repo does not run;
verifying against your own Bitcoin node removes even that.

## Contents

- `verify-watchdog.mjs` — the verifier (a copy of the script maintained in the
  Proofread app repo; self-contained, no app code).
- `books.json` — the pins: per-book Bitcoin-anchored ground truth.
- `.github/workflows/verify.yml` — runs it every 6 hours and on demand.
- `log/` — the append-only verification history.
