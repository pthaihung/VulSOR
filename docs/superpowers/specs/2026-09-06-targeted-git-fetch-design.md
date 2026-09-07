# Targeted Git Fetch for PrimeVul Context

## Goal

Resolve the vulnerable revision for paired PrimeVul samples without cloning a
repository's complete history.  The result remains an immutable full SHA and
the runtime remains query-only.

## Design

For each indexed patch commit, the offline resolver maintains a bare cache
repository keyed by canonical URL.  Instead of `git clone --mirror`, it
initializes the cache, records `origin`, and fetches only the requested patch
SHA with depth two.  The second fetched commit is the first parent, which is
resolved to a full SHA and stored in `index.jsonl` as the vulnerable revision.

When a requested SHA is absent, the resolver performs the same targeted fetch
for that SHA.  It validates that Git resolves the requested full SHA before
materializing a detached, read-only checkout.  Existing cache and checkout
locking, URL verification, error redaction, timeouts, and atomic publication
remain unchanged.

## Failure behavior

An unreachable repository, unavailable SHA, or missing parent produces a
controlled repository-unavailable import rejection.  It never blocks other
samples and never publishes partial input/index files.

## Verification

Tests cover targeted fetch arguments, parent resolution, cache reuse, and the
existing immutable-checkout invariants.  A real PrimeVul smoke sample must
resolve its parent and match source before any all-sample run.
