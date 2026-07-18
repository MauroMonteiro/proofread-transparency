#!/usr/bin/env node
/**
 * External verification watchdog — the independent, out-of-band checker.
 *
 * It fetches the PUBLIC site exactly as an anonymous reader would and, per
 * published book, checks the served content and its Bitcoin anchor against a
 * PINNED, out-of-band ground truth — so it catches tampering that a browser
 * verifier (running server-delivered JS) structurally cannot, INCLUDING a
 * malicious operator who re-anchors a forged manifest.
 *
 * THE TRUST ROOT — PINS. OpenTimestamps proves "these exact bytes were stamped
 * into Bitcoin at block-time T"; it does NOT prove they are THE published bytes
 * — anyone can cheaply stamp arbitrary bytes. So a server operator who controls
 * the site could tamper the text, build a new manifest matching it, stamp that
 * forgery, and serve a fully self-consistent lie. The only defense is a ground
 * truth the operator cannot silently rewrite. That is `books.json` (the PINS):
 * per book, the known-good {manifestHash, blockHeight, blockHash}, captured at a
 * verified moment and committed to this PUBLIC repo, where any change is visible
 * in git history. The watchdog trusts the PIN, not whatever the server asserts.
 *
 * Per book it verifies:
 *   1. MANIFEST BINDING — sha256(served manifest bytes) === pin.manifestHash.
 *      This binds the entire anchored file list (every file's hash + rootHash)
 *      to the pin in one check.
 *   2. CONTENT INTEGRITY (self-contained, node:crypto only) — recompute every
 *      file's SHA-256 and compare to the (now pin-bound) manifest hash.
 *   3. ANCHOR INTEGRITY (OpenTimestamps → Bitcoin, two independent explorers) —
 *      the manifest's .ots proof commits to a real Bitcoin block whose merkle
 *      root matches, at pin.blockHeight with block hash pin.blockHash.
 *   4. ROSTER — every pinned book is still listed and served (an operator can't
 *      hide a book by dropping it from /api/v1/books).
 *
 * WITHOUT a pins file the watchdog runs in a weaker self-consistency mode (it
 * still catches a third-party/CDN tamperer and a server that lies about its
 * anchor, but NOT an operator who re-anchors) and says so loudly.
 *
 * HONEST BOUNDARY. This verifies the canonical, anchored content ARTIFACTS. It
 * does not prove the reader's rendered HTML is byte-identical to them — closing
 * that gap needs content-addressed delivery (the documented North Star). Trust
 * is rooted in Bitcoin, in the pins in this repo, and in explorers this repo
 * does not run; verifying against your own Bitcoin node removes the last of it.
 *
 * Usage:
 *   node verify-watchdog.mjs [--base https://proofreadbtc.com] [--pins books.json]
 *   node verify-watchdog.mjs --emit-pins        # capture a fresh pin set (verify first!)
 * Env: WATCHDOG_BASE_URL, WATCHDOG_GATE_COOKIE (pre-launch gate), WATCHDOG_PINS,
 *      WATCHDOG_NO_ANCHOR=1 (content only, e.g. standalone without npm install)
 * Exit: 0 = every pinned book verified against its pin; 1 = TAMPERING (content
 *   mismatch, manifest≠pin, anchor≠pin block, or a pinned book missing); 2 =
 *   OPERATIONAL (site/explorers unreachable, a proof pending, a book not yet
 *   pinned, or content incomplete) — no tampering confirmed.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// The OTS library prints progress ("Lite-client verification…") and transient
// calendar errors straight to the console; silence just that noise so our
// stdout carries only structured output (the WATCHDOG_REPORT line / --emit-pins
// JSON). Our own messages never start with these prefixes.
const OTS_NOISE = /^(Lite-client verification|Calendar https?:)/;
const _log = console.log.bind(console);
const _err = console.error.bind(console);
console.log = (...a) => {
  if (typeof a[0] === "string" && OTS_NOISE.test(a[0])) return;
  _log(...a);
};
console.error = (...a) => {
  if (typeof a[0] === "string" && OTS_NOISE.test(a[0])) return;
  _err(...a);
};

const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const hasFlag = (name) => process.argv.includes(name);
const BASE = (arg("--base") || process.env.WATCHDOG_BASE_URL || "https://proofreadbtc.com").replace(/\/$/, "");
const GATE = process.env.WATCHDOG_GATE_COOKIE || "";
const NO_ANCHOR = hasFlag("--no-anchor") || process.env.WATCHDOG_NO_ANCHOR === "1";
const EMIT_PINS = hasFlag("--emit-pins");
const PINS_PATH = arg("--pins") || process.env.WATCHDOG_PINS || "books.json";
const EXPLORER_TIMEOUT_MS = 15000; // generous, so ordinary explorer latency isn't misread as an error

// Two independent, Esplora-compatible block explorers used for redundancy: the
// pin is the ground truth, and no explorer may CONTRADICT it (a mismatch from
// any explorer is investigated, never ignored). At least one must confirm.
const EXPLORERS = [
  { name: "blockstream", url: "https://blockstream.info/api" },
  { name: "mempool", url: "https://mempool.space/api" },
];

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
// book.json holds mutable listing metadata (coverUrl, …) alongside immutable
// fields; a hash mismatch there is expected drift, not text tampering. (Reader-
// facing immutable fields ideally live in book-fulltext.json, not book.json.)
const isMetadata = (name) => name === "book.json";

async function loadOts() {
  if (NO_ANCHOR) return null;
  try {
    const mod = await import("javascript-opentimestamps");
    return mod.default ?? mod;
  } catch {
    return null;
  }
}

/** The out-of-band ground truth: id -> {manifestHash, blockHeight, blockHash, ...}. */
function loadPins() {
  try {
    const raw = JSON.parse(readFileSync(PINS_PATH, "utf-8"));
    const list = Array.isArray(raw) ? raw : raw.books ?? [];
    return new Map(list.filter((p) => p && p.id).map((p) => [p.id, p]));
  } catch {
    return new Map();
  }
}

async function getJson(path) {
  const res = await fetch(BASE + path, { headers: GATE ? { cookie: GATE } : {}, redirect: "manual" });
  if (res.status >= 300 && res.status < 400) throw new Error(`redirect (gated?) at ${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status} at ${path}`);
  return res.json();
}

async function getBytes(path) {
  const url = /^https?:\/\//.test(path) ? path : BASE + path;
  const res = await fetch(url, { headers: !/^https?:\/\//.test(path) && GATE ? { cookie: GATE } : {} });
  if (!res.ok) return null;
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * CONTENT: recompute each file's SHA-256 and compare to the AUTHORITATIVE hash.
 * Authoritative hashes come from the (pin-bound) anchored manifest, never from
 * the /verify JSON, which the server controls; the JSON supplies only the
 * name→contentUrl map (and a last-resort hash source flagged hashesAnchored:false).
 */
async function verifyContentBytes(verifyFiles, anchoredManifest) {
  const urlByName = new Map(verifyFiles.filter((f) => f.contentUrl).map((f) => [f.path, f.contentUrl]));
  const hashesAnchored = !!anchoredManifest;
  const expected = hashesAnchored
    ? Object.entries(anchoredManifest.files).map(([path, info]) => ({ path, sha256: info.sha256 }))
    : verifyFiles.map((f) => ({ path: f.path, sha256: f.sha256 }));

  let textOk = true;
  let incomplete = false;
  let metadataDrift = false;
  const mismatches = [];
  for (const f of expected) {
    const url = urlByName.get(f.path);
    if (!url) {
      if (!isMetadata(f.path)) incomplete = true;
      continue;
    }
    const bytes = await getBytes(url);
    if (!bytes) {
      if (!isMetadata(f.path)) incomplete = true;
      continue;
    }
    const match = sha256(bytes) === f.sha256;
    if (isMetadata(f.path)) {
      if (!match) metadataDrift = true;
    } else if (!match) {
      textOk = false;
      mismatches.push(f.path);
    }
  }
  return { textVerified: textOk && !incomplete, textOk, incomplete, metadataDrift, mismatches, hashesAnchored, fileCount: expected.length };
}

/** Independently fetch a block's hash + header from one explorer, by height. */
async function explorerBlockByHeight(explorer, height) {
  const ctl = AbortSignal.timeout(EXPLORER_TIMEOUT_MS);
  const hashRes = await fetch(`${explorer.url}/block-height/${height}`, { signal: ctl });
  if (!hashRes.ok) throw new Error(`${explorer.name} block-height ${height}: HTTP ${hashRes.status}`);
  const hash = (await hashRes.text()).trim();
  const blkRes = await fetch(`${explorer.url}/block/${hash}`, { signal: AbortSignal.timeout(EXPLORER_TIMEOUT_MS) });
  if (!blkRes.ok) throw new Error(`${explorer.name} block ${hash}: HTTP ${blkRes.status}`);
  const blk = await blkRes.json();
  return { hash, merkleRoot: blk.merkle_root, time: blk.timestamp };
}

// Classify an OTS verify() failure. Two failures mean the served artifacts do
// not chain to Bitcoin (integrity/tamper signals): "File does not match
// original!" (served manifest is not the file this .ots is for — local,
// deterministic, explorer-independent) and "...does not match merkleroot" (the
// proof does not reproduce the block's merkle root). Pending / unknown / any
// network error is OPERATIONAL — never cry tamper on a flaky explorer.
function classifyAnchorError(err) {
  const m = String(err && err.message ? err.message : err);
  if (/PendingAttestation/i.test(m)) return "pending";
  if (/UnknownAttestation/i.test(m)) return "operational";
  if (/File does not match original/i.test(m)) return "mismatch";
  if (/does not match merkleroot/i.test(m)) return "mismatch";
  return "operational";
}

/**
 * ANCHOR: verify the manifest's .ots proof to a real Bitcoin block via both
 * explorers, then require it match the PIN (block height + block hash). Falls
 * back to cross-checking the server's claim when unpinned.
 */
async function verifyAnchor(ots, book, claimed, manBytes, pin) {
  const otsUrl = book.manifest?.otsUrl;
  const result = {
    checked: true,
    claimedHeight: claimed?.height ?? null,
    attestedHeight: null,
    attestedTime: null,
    blockHash: null,
    explorers: {},
    verified: false,
    note: null,
  };
  if (!otsUrl || !manBytes) {
    result.note = "operational";
    return result;
  }
  const otsBytes = await getBytes(otsUrl);
  if (!otsBytes) {
    result.note = "operational";
    return result;
  }

  const original = ots.DetachedTimestampFile.fromBytes(new ots.Ops.OpSHA256(), Buffer.from(manBytes));

  const successes = [];
  let mismatchVotes = 0;
  let pendingVotes = 0;
  let opVotes = 0;
  for (const explorer of EXPLORERS) {
    try {
      const otsFile = ots.DetachedTimestampFile.deserialize(otsBytes); // fresh per explorer — verify() mutates
      const v = await ots.verify(otsFile, original, { ignoreBitcoinNode: true, esplora: { url: explorer.url, timeout: EXPLORER_TIMEOUT_MS } });
      if (v && v.bitcoin) {
        result.explorers[explorer.name] = { height: v.bitcoin.height, time: v.bitcoin.timestamp };
        successes.push({ name: explorer.name, height: v.bitcoin.height, time: v.bitcoin.timestamp });
      } else {
        result.explorers[explorer.name] = { error: "no bitcoin attestation" };
        pendingVotes++;
      }
    } catch (err) {
      const kind = classifyAnchorError(err);
      result.explorers[explorer.name] = { error: String(err && err.message ? err.message : err), kind };
      if (kind === "mismatch") mismatchVotes++;
      else if (kind === "pending") pendingVotes++;
      else opVotes++;
    }
  }

  if (successes.length > 0) {
    const h0 = successes[0].height;
    const t0 = successes[0].time;
    result.attestedHeight = h0;
    if (!successes.every((s) => s.height === h0 && s.time === t0)) {
      result.note = "operational"; // explorers disagree on the block → human, not auto-tamper
      return result;
    }
    if (mismatchVotes > 0) {
      result.note = "operational"; // one confirmed, another rejected → suspicious; flag, don't cry tamper
      return result;
    }
    result.attestedTime = t0;
    // Independent: fetch the block by height and record its hash.
    try {
      const blk = await explorerBlockByHeight(EXPLORERS[EXPLORERS.length - 1], h0);
      result.blockHash = blk.hash;
    } catch {
      // non-critical for verify(), but required to confirm pin.blockHash below
    }

    if (pin) {
      // PINNED: the ground truth decides. Height and block hash must match the
      // pin exactly; a match here means the .ots resolves to precisely the
      // block we recorded as this book's true anchor.
      if (h0 !== pin.blockHeight) {
        result.note = "pin-mismatch";
        return result;
      }
      if (pin.blockHash && result.blockHash && result.blockHash !== pin.blockHash) {
        // block at pin height has a different hash than pinned → reorg or a
        // lying explorer, not manifest tampering → operational (human).
        result.note = "operational";
        return result;
      }
      if (pin.blockHash && !result.blockHash) {
        result.note = "operational"; // couldn't confirm the pinned block hash this run
        return result;
      }
      result.verified = true;
      return result;
    }

    // UNPINNED: fall back to cross-checking the server's own claim. Coerce
    // numeric drift; a null/absent claim is incomplete, not a lie.
    const claimedHeight = claimed == null ? null : Number(claimed.height);
    if (claimedHeight == null || Number.isNaN(claimedHeight)) {
      result.note = "operational";
      return result;
    }
    if (claimedHeight !== h0) {
      result.note = "claim-mismatch"; // server claims an anchor Bitcoin does not back → tamper
      return result;
    }
    result.verified = true;
    return result;
  }

  // No explorer verified. Consensus that the proof doesn't commit to a block
  // (with no mere network hiccup mixed in) is a real integrity failure.
  if (mismatchVotes > 0 && opVotes === 0) {
    result.note = "mismatch";
    return result;
  }
  if (pendingVotes > 0 && mismatchVotes === 0) {
    result.note = "pending";
    return result;
  }
  result.note = "operational";
  return result;
}

async function verifyBook(ots, id, pin, pinsLoaded) {
  const env = await getJson(`/api/v1/books/${encodeURIComponent(id)}/verify`);
  const data = env.data ?? env;
  const files = data.files ?? [];
  const claimed = data.bitcoin ?? null;

  // Fetch the manifest ONCE. Bind it to the pin, then use its hashes as the
  // authoritative expected values for the content check and its bytes for the
  // anchor check.
  let anchoredManifest = null;
  let manifestHash = null;
  const manifestUrl = data.manifest?.manifestUrl;
  if (manifestUrl) {
    const manBytes = await getBytes(manifestUrl);
    if (manBytes) {
      manifestHash = sha256(manBytes);
      try {
        const m = JSON.parse(new TextDecoder().decode(manBytes));
        if (m && m.files) anchoredManifest = { files: m.files, rootHash: m.rootHash, bytes: manBytes };
      } catch {
        // unparseable → falls back to /verify JSON hashes (flagged) below
      }
    }
  }

  // MANIFEST BINDING: the served manifest must be byte-identical to the pinned
  // one. This single check binds every file hash + rootHash to the ground truth.
  const manifestPinOk = pin ? manifestHash != null && manifestHash === pin.manifestHash : null;

  const content = await verifyContentBytes(files, anchoredManifest);

  // ANCHOR: verify independent of the server-supplied status (a "pending" claim
  // must not be able to skip the check for a book we know is anchored).
  let anchor = { checked: false };
  if (ots && (manifestUrl || pin)) {
    anchor = await verifyAnchor(ots, data, claimed, anchoredManifest?.bytes, pin);
  }

  // Roll up. With a pin, "verified" means: manifest bound to pin, content
  // matches, and anchor resolves to the pinned block.
  const contentTampered = content.textOk === false;
  const anchorTampered = anchor.note === "mismatch" || anchor.note === "claim-mismatch" || anchor.note === "pin-mismatch";
  const manifestTampered = manifestPinOk === false && manifestHash != null; // served a manifest ≠ pin
  const tampered = contentTampered || anchorTampered || manifestTampered;

  let verdict;
  if (tampered) {
    verdict = "TAMPERED";
  } else if (pin) {
    const fullyVerified = manifestPinOk === true && content.textVerified && anchor.verified === true;
    verdict = fullyVerified ? "OK" : anchor.note === "pending" ? "PENDING" : "INCOMPLETE";
  } else {
    // Unpinned book (a pins file exists but this book isn't in it) → cannot
    // check against ground truth. Never "OK": needs a human to add a pin.
    const anchorOk = !ots || anchor.verified === true;
    if (pinsLoaded) verdict = "UNPINNED";
    else if (content.textVerified && anchorOk) verdict = "OK";
    else if (anchor.note === "pending") verdict = "PENDING";
    else verdict = "INCOMPLETE";
  }

  return {
    id,
    version: data.version,
    rootHash: data.rootHash,
    status: data.status,
    pinned: !!pin,
    manifestHash,
    manifestPinOk,
    content,
    anchor,
    verdict,
    tampered,
    operational: !tampered && verdict !== "OK",
    block: anchor.attestedHeight ?? claimed?.height ?? null,
  };
}

/** Capture a Bitcoin-verified pin for a book (used by --emit-pins). */
async function capturePin(ots, id) {
  const env = await getJson(`/api/v1/books/${encodeURIComponent(id)}/verify`);
  const data = env.data ?? env;
  const manifestUrl = data.manifest?.manifestUrl;
  if (!manifestUrl) return null;
  const manBytes = await getBytes(manifestUrl);
  if (!manBytes) return null;
  const manifestHash = sha256(manBytes);
  let rootHash = null;
  try {
    rootHash = JSON.parse(new TextDecoder().decode(manBytes)).rootHash ?? null;
  } catch {
    /* keep null */
  }
  const anchor = await verifyAnchor(ots, data, data.bitcoin ?? null, manBytes, null);
  if (!anchor.verified || anchor.attestedHeight == null || !anchor.blockHash) return null;
  return {
    id,
    version: data.version ?? null,
    rootHash,
    manifestHash,
    blockHeight: anchor.attestedHeight,
    blockHash: anchor.blockHash,
    blockTime: anchor.attestedTime ?? null,
    capturedAt: null, // stamped by the caller (no Date in this scope for reproducibility)
  };
}

function line(r) {
  const bits = [];
  bits.push(`content ${r.content.textOk === false ? "TAMPERED" : r.content.textVerified ? "OK" : "INCOMPLETE"}`);
  if (r.pinned && r.manifestPinOk === false) bits.push("manifest ≠ PIN");
  if (r.anchor.checked) {
    if (r.anchor.verified) bits.push(`anchor OK (block ${r.anchor.attestedHeight}${r.anchor.blockHash ? " " + r.anchor.blockHash.slice(0, 12) + "…" : ""})`);
    else if (r.anchor.note === "pin-mismatch") bits.push(`anchor ≠ PIN (Bitcoin attests ${r.anchor.attestedHeight})`);
    else if (r.anchor.note === "mismatch") bits.push("anchor MISMATCH (manifest does not commit to a block)");
    else if (r.anchor.note === "claim-mismatch") bits.push(`anchor LIE (claims ${r.anchor.claimedHeight}, Bitcoin attests ${r.anchor.attestedHeight})`);
    else if (r.anchor.note === "pending") bits.push("anchor pending (not yet in a block)");
    else bits.push("anchor unverified (operational)");
  } else if (!r.pinned && r.verdict === "UNPINNED") {
    bits.push("UNPINNED (needs review)");
  }
  const tag = r.verdict === "UNPINNED" ? " [UNPINNED — add a pin after review]" : r.content.metadataDrift ? " [metadata drift — expected]" : "";
  return `[watchdog] ${r.id} v${r.version ?? "?"}: ${bits.join(", ")}${tag}`;
}

async function main() {
  const now = new Date().toISOString();
  const ots = await loadOts();
  if (!ots && !NO_ANCHOR) {
    console.warn("[watchdog] javascript-opentimestamps not installed — CONTENT check only. `npm ci` to enable the Bitcoin anchor check.");
  }

  let serverIds;
  try {
    const env = await getJson(`/api/v1/books`);
    const list = env.data ?? env;
    serverIds = (Array.isArray(list) ? list : list.books ?? []).map((b) => b.id ?? b);
  } catch (err) {
    console.error(`[watchdog] could not list books: ${err.message}`);
    process.exit(2);
  }

  // --emit-pins: capture a fresh, Bitcoin-verified pin set. VERIFY the output
  // by eye against explorers before committing it as ground truth.
  if (EMIT_PINS) {
    if (!ots) {
      console.error("[watchdog] --emit-pins requires the OTS library (npm ci first).");
      process.exit(2);
    }
    const pins = [];
    for (const id of serverIds) {
      try {
        const p = await capturePin(ots, id);
        if (p) {
          pins.push(p);
          console.error(`[emit-pins] ${id}: block ${p.blockHeight} ${p.blockHash.slice(0, 12)}… manifest ${p.manifestHash.slice(0, 12)}…`);
        } else {
          console.error(`[emit-pins] ${id}: SKIPPED (not verifiable — pending or unreachable)`);
        }
      } catch (err) {
        console.error(`[emit-pins] ${id}: ${err.message}`);
      }
    }
    console.log(JSON.stringify({ generatedAt: now, base: BASE, books: pins }, null, 2));
    return;
  }

  const pins = loadPins();
  const pinsLoaded = pins.size > 0;
  if (!pinsLoaded) {
    console.warn("[watchdog] no pins loaded — running in self-consistency mode. This catches a third-party tamperer and an anchor-lie, but NOT an operator who re-anchors a forgery. Commit a books.json pin set (see --emit-pins).");
  }

  const report = { checkedAt: now, base: BASE, anchorChecked: !!ots, pinned: pinsLoaded, books: [] };
  let tampered = false;
  let opError = false;

  // ROSTER: a pinned (previously published + anchored) book must still be
  // listed and served. Hiding it by dropping it from /api/v1/books is tampering.
  if (pinsLoaded) {
    for (const id of pins.keys()) {
      if (!serverIds.includes(id)) {
        console.error(`[watchdog] ${id}: MISSING — a pinned book is no longer listed by the site.`);
        report.books.push({ id, verdict: "MISSING", tampered: true });
        tampered = true;
      }
    }
  }

  const roster = pinsLoaded ? Array.from(new Set([...serverIds, ...pins.keys()])).filter((id) => serverIds.includes(id)) : serverIds;
  for (const id of roster) {
    try {
      const r = await verifyBook(ots, id, pins.get(id) ?? null, pinsLoaded);
      report.books.push(r);
      console.log(line(r));
      if (r.tampered) tampered = true;
      else if (r.verdict !== "OK") opError = true;
    } catch (err) {
      console.error(`[watchdog] ${id}: ${err.message}`);
      report.books.push({ id, error: err.message });
      opError = true;
    }
  }

  console.log("WATCHDOG_REPORT " + JSON.stringify(report));

  if (tampered) {
    console.error("[watchdog] TAMPERING DETECTED — a published book's served text, manifest, or Bitcoin anchor does not match its pin.");
    process.exit(1);
  }
  if (opError) {
    console.error("[watchdog] completed with operational errors (unreachable / pending / unpinned / incomplete) — no tampering confirmed.");
    process.exit(2);
  }
  console.log("[watchdog] all pinned books verified: content matches the manifest, and the manifest's anchor is the pinned Bitcoin block.");
}

main().catch((err) => {
  console.error(`[watchdog] fatal: ${err.message}`);
  process.exit(2);
});
