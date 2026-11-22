# Offload Proof — independent verifier

mmMover seals every offload with `_REPORT/offload_proof.json` (a canonical JSON manifest: SHA-256 and size of every
copied file, plus an RFC 6962 Merkle root) and anchors the manifest's SHA-256 in Bitcoin through OpenTimestamps
(`_REPORT/offload_proof.json.ots`). A proof only the vendor's program can check would be easy to dispute, so this folder
holds a small open verifier written from the format specification, in Python 3.8+ with the standard library only.

## Verify one clip (about ten lines)

1. Put the clip back in (or leave it in) its card folder, the one that holds `_REPORT/offload_proof.json` and its `.ots`.
2. Run `python verify_proof.py path/to/CLIP/A001C003.MXF` (add `--offline` to ask no block explorer).
3. Read the `RESULT:` line. Exit code `0` = OK, `1` = FAILED, `2` = NOT YET (anchor still pending, offline, or the
   block explorers could not be reached or disagreed).
4. OK means: this exact file (SHA-256 and size) is listed in a manifest whose Merkle root and canonical form are right,
   the `.ots` is a timestamp of exactly that manifest, and its Bitcoin attestation matches the block header returned by
   two independent explorers (`blockstream.info`, `mempool.space`; each header must hash to its block hash and carry
   valid proof of work). The result says the file **existed unchanged no later than** the block's time. It never says
   the content is authentic.
5. Cross-check with the official client: `pip install opentimestamps-client`, then
   `ots verify _REPORT/offload_proof.json.ots` (it finds `offload_proof.json` beside it and needs a Bitcoin node or
   explorer access). That checks the timestamp of the manifest; this script also checks the clip against the manifest.
6. Give a card folder instead of a file to re-hash every file of every manifest in it:
   `python verify_proof.py path/to/A001`.

## Files

- `verify_proof.py` — the verifier (`--make-vectors out.json` regenerates `vectors.json`).
- `test_verify_proof.py` — its tests: `python -m unittest shared/proof/test_verify_proof.py -v` from the repo root.
- `vectors.json` — shared test vectors, reproduced by both this script and mmMover's C# code (`merkle`: 0, 1, 2, 3 and
  2001 leaves; `ct`: the Certificate Transparency leaves 0–8; `jcs`: RFC 8785 cases, with non-ASCII paths).
