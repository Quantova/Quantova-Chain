# qtv-store slice

This is the first disk backed persistence for the Quantova node. The node runs a
state transition and finalization loop but holds the finalized chain and the
account state in memory, so a restart loses them. This crate adds two file backed
stores so the chain survives a restart.

## What is in this slice

- A block store that appends each finalized block to a single file and indexes it
  by height and by hash, so a block is fetched by either. The stored record keeps
  the height, the header hash, and the canonical block encoding.
- A state store that persists the account state, the leaves of the qtv-state
  sparse Merkle trie keyed by their thirty two byte hash, and records the root a
  state was committed under. The head is the last committed root, and the trie
  rebuilt from the leaves reproduces that root.
- Canonical encoding throughout. Every record is written and read through the
  qtv-codec length delimited codec, never an ad hoc format.
- Index rebuilt on open. Each store scans its log once and rebuilds the in memory
  index and the head from it, so a reopen sees exactly what was committed.
- Torn tail tolerance. An append that was interrupted leaves an incomplete frame
  at the end of the file. The scan stops at the last whole record and truncates
  the file back to it, so the store stays append only and nothing torn is read.
  An absent or truncated file opens as an empty store rather than a panic.

## Properties held

- A write then read returns the same bytes.
- A block written at a height is found by height and by hash.
- A state committed under a root is fully readable after reopening from disk, and
  a reopened store reports the same head as before the restart.
- The store is deterministic and append only.

## What is deferred to later store work

- A hardened embedded store. This slice is a plain append log plus an index built
  from the standard library alone, with no external database crate. Checksummed
  pages, page level corruption detection, and repair are later work.
- Atomic multi record commits. A single record append is flushed and either lands
  whole or is dropped as a torn tail. A batch that spans several records is not
  yet committed as one unit.
- Compaction. A key rewritten many times keeps every prior record in the log; the
  index keeps only the latest. Reclaiming the superseded records is later work.
- A shared write ahead log across the two stores, snapshots, and pruning of the
  finalized chain below a checkpoint.
