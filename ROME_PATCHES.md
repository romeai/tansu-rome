# Rome patch ledger

This branch is Tansu plus a deliberately reviewable series of generic robustness
and embedding seams used by Rome's Kafka receiver. The immutable **code
milestone** consumed by Rome is
`19be185529d1e8b3542ee6553ac02ab5f8045dcf` (`19be185`). This manifest is a
documentation-only descendant of that milestone; its presence must not be read
as a change to the code Rome consumes.

No patch in this series changes Rome's advertised `ApiVersions` set or its Fetch
behavior. The explicit `ApiVersions` service seam lets Rome preserve its existing
advertisement while retaining callable denial/compatibility routes. Ordinary
Tansu defaults remain unchanged unless a patch fixes invalid framing, malformed
protocol input, or an authentication/security bug; those cases intentionally
fail earlier or fail closed.

Status terms below are intentionally narrow:

- **Direct**: Rome configures or calls the seam.
- **Foundation**: required transitively by a direct Rome integration.
- **Correctness**: relied on as a Tansu-wide security/protocol invariant, without
  a Rome-specific configuration path.

The issue and PR references are placeholders until the maintainer chooses the
preferred decomposition. Each row can become an independent PR unless its
`Depends on` entry says otherwise.

## 1. Framing, authentication, and advertisement composition

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `b1665f3`<br>`b1665f3494ae12b81e5f9eac52c94dd58ed76a26` | Validates signed Kafka frame lengths before allocation, preventing malformed prefixes from becoming peer-sized capacities. | Optional maximum preserves valid defaults; invalid frames fail earlier. **Direct.** | — | Issue TBD / PR TBD |
| `2bc47c9`<br>`2bc47c91be8c7f94f6197ce2a045f2b60fcf01e6` | Requires a positive SASL verifier verdict; handshake completion alone must never authenticate a peer. | Security correction: failed or absent verdicts now fail closed. **Correctness.** | — | Issue TBD / PR TBD |
| `c280ddb`<br>`c280ddb959d54a18f0bff5e384de70124cafec6c` | Advertises only mechanisms backed by credential verification, preventing feature-unified PLAIN from bypassing password checks. | Security correction; verified SCRAM success is unchanged. **Correctness.** | `2bc47c9` | Issue TBD / PR TBD |
| `ff227f0`<br>`ff227f0d7ff85577ea25c0eb70de0a91be5c9738` | Separates callable routes from discovery so a denial route need not become an advertised capability. | Default builder still derives versions from routes. **Direct**, used specifically to preserve Rome's existing advertisement. | — | Issue TBD / PR TBD |

**Verification:** signed/minimum/maximum frame tests, successful and failed SCRAM
tests, mechanism-advertisement tests, and explicit-versus-derived `ApiVersions`
service tests.

## 2. Listener lifecycle and connection admission

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `4a6e484`<br>`4a6e484307e4530af50d024f567cc7911bb4dda4` | Builds immutable routes once while keeping SASL/framing state per socket, bounding connection-churn setup and preventing auth-state sharing. | Existing helper composes the same stack. **Foundation.** | `ff227f0` | Issue TBD / PR TBD |
| `18b05a9`<br>`18b05a973ecf85cb23e9b77f5d057ce692df7649` | Extracts a reusable Rama listener with a typed per-connection factory, so embedders can add policy without replacing task ownership and shutdown. | Default layer retains clone-per-socket behavior. **Direct.** | `4a6e484` | Issue TBD / PR TBD |
| `ccd0d27`<br>`ccd0d27eebf40557e870ea69669ba835015e6bd8` | Runs admission before `accept`, leaving overload in the kernel backlog instead of allocating accepted socket/task state first. | `UnlimitedPolicy` remains the default. **Direct.** | `18b05a9` | Issue TBD / PR TBD |
| `945529c`<br>`945529c641bc01b5d5605fdb8bfd9d3f408eb24b` | Retains connection guards until tasks are reaped, making the limit cover listener-owned bookkeeping as well as running futures. | Unlimited behavior and APIs are unchanged. **Foundation.** | `ccd0d27` | Issue TBD / PR TBD |

**Verification:** per-connection SASL isolation, pre-accept semaphore blocking,
cancellation, join reaping, listener-error draining, and hard task/guard population
bounds.

## 3. Embeddable and bounded SASL

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `60769dc`<br>`60769dc95a8913fce611d739cfe0dcfa8a385ef1` | Makes storage-backed auth an adapter and permits a caller-supplied verified rsasl callback, avoiding the full storage graph in protocol embedders. | Broker explicitly enables the old storage adapter. **Direct.** | `c280ddb` | Issue TBD / PR TBD |
| `46c2e77`<br>`46c2e7715249acfe2411f692f9e753c7a97c8042` | Bounds individual SASL tokens and cumulative transcripts, and removes credential-bearing payload logs. | Defaults match Kafka's 512 KiB server token allowance and four-token transcript. **Direct.** | `60769dc` | Issue TBD / PR TBD |

**Verification:** storage-free static SCRAM, storage adapter coverage, mechanism
selection, per-token/cumulative input/output limits, and metadata-only tracing.

## 4. Request admission, transport policy, and lease ownership

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `d31f9f3`<br>`d31f9f37efe23cf24a2d37c867f91aeb43948d12` | Reads the fixed Kafka head before body allocation, exposing API/version/correlation data needed to price the request. | Default path immediately continues to the same frame. **Direct.** | `b1665f3` | Issue TBD / PR TBD |
| `2efb0ec`<br>`2efb0ec39b8cf3ceb52b530e963dd08e747dd022` | Carries a private admission guard monotonically through decode, handling, response encoding, and socket write. | Additive policy envelope; legacy/default path unchanged. **Direct.** | `d31f9f3` | Issue TBD / PR TBD |
| `404153a`<br>`404153a7253771404c1284014c01885df47913b0` | Models Produce `acks=0` as no wire response while retaining admission through handler completion, preserving stream alignment. | Protocol correctness for `acks=0`; other requests unchanged. **Correctness.** | `2efb0ec` | Issue TBD / PR TBD |
| `ac96c35`<br>`ac96c35cbc980c79d4da0e679145fd5319c159fa` | Adds checked socket buffers, keepalive, and next-frame idle policy so inactive peers cannot retain unplanned memory/capacity indefinitely. | All fields default to unset. **Direct.** | `18b05a9` | Issue TBD / PR TBD |
| `08e3f3a`<br>`08e3f3a845df4fe8f30ceeb69f3cbd39e151105b` | Adds explicit `TCP_NODELAY`; Kafka's small control/auth replies should not incur Nagle/delayed-ACK latency. | Unset by default; this is latency policy, not memory accounting. **Direct.** | `ac96c35` | Issue TBD / PR TBD |
| `49379a3`<br>`49379a36dffcb66e63643fe0dbe34dc73e5aa60e` | Lends restricted evidence from the private guard, allowing zero-copy frame borrows while proving their reservation remains alive. | Purely additive refinement. **Direct.** | `2efb0ec` | Issue TBD / PR TBD |
| `0f89f01`<br>`0f89f019f59c1dca121d502968ee3f6540310f19` | Reconciles a request reservation after its large payload is dropped but before its smaller response is written, without exposing guard replacement. | Only explicit handlers adjust a lease. **Direct.** | `2efb0ec` | Issue TBD / PR TBD |
| `080fd7e`<br>`080fd7e55b0d2a6107b4e0ef315e870ce61e5e71` | Bounds generated decode frame/value/cardinality/depth/work before allocation or traversal. | Existing unbounded entry point remains; bounded API is explicit. **Direct.** | — | Issue TBD / PR TBD |
| `d16b513`<br>`d16b5139dbd587e35178dee61cd528ce950c5041` | Requires one exact declared frame, rejects trailing bytes/compact underflow, and validates batch lengths before casts. | Malformed input fails earlier; valid requests unchanged. **Correctness.** | `080fd7e` | Issue TBD / PR TBD |
| `aab3dfd`<br>`aab3dfdbfedc51de1345501f98ceb0bed285942d` | Adds separate head/body/write deadlines so slow peers cannot retain admitted capacity indefinitely and policy waits do not consume I/O budgets. | Every deadline is opt-in. **Direct.** | `d31f9f3`, `2efb0ec` | Issue TBD / PR TBD |
| `8a741b2`<br>`8a741b287e5b4b6c4ac2355859bbfb0ba83f56ab` | Observes disconnects while admission waits without consuming queued Kafka bytes. | No-op monitor is the generic default. **Direct.** | `2efb0ec` | Issue TBD / PR TBD |

**Verification:** exact head/body hand-off, guard identity/lifetime compile-fail
tests, reconciliation order, `acks=0` next-request alignment, socket option
round-trips, phase timeout tests, and disconnect monitoring with unread body bytes.

## 5. Borrowed, bounded record-bearing requests

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `9ee05bb`<br>`9ee05bbbe4c9509b8be2642be55e2cd107b1e03a` | Adds allocation-free magic-v2 `RecordSet`/`Batch` views with bounded count/work and one validated CRC pass. | Additive borrowed API; owned behavior unchanged. **Foundation.** | — | Issue TBD / PR TBD |
| `86da8f5`<br>`86da8f5c93440fa744e3d8bd45a46b650c2d43b3` | Generates bounded borrowed views for every record-bearing request schema, avoiding a drifting handwritten Produce parser. | Owned types and `ApiVersions` are unchanged. **Direct.** | `080fd7e`, `9ee05bb` | Issue TBD / PR TBD |
| `0a6b6b4`<br>`0a6b6b4e00ee364fb03fa5f99a733a841a9ee8af` | Removes the response `BufWriter`'s hidden heap allocation after admission has been reconciled to exact retained response memory. | Same complete frame, flush, and deadline behavior. **Direct.** | `2efb0ec` | Issue TBD / PR TBD |
| `cc143e7`<br>`cc143e7ebce704c338268bb1e276b6085c85a14f` | Lends uncompressed records without collecting records/headers, with exact body/count/trailing and work limits. | Compressed C1 input fails explicitly; owned decoding unchanged. **Direct.** | `9ee05bb` | Issue TBD / PR TBD |
| `fc1008f`<br>`fc1008faa75c0bb7043a22c17aa904776227b17e` | Correctly decodes mandatory strings inside nullable arrays, restoring bounded control-request compatibility. | Protocol correctness; no API/default change. **Correctness.** | `080fd7e` | Issue TBD / PR TBD |
| `8049e6b`<br>`8049e6b61a72ce0ca88488f14445c90dac634a53` | Routes flexible tag counts/bytes through decode limits and rejects non-increasing IDs, preventing bypass allocations while accepting compatible unknown payload sizes. | Public/default API unchanged; malformed tags fail. **Correctness.** | `080fd7e` | Issue TBD / PR TBD |
| `ca65ac8`<br>`ca65ac8d1d77ca77cca3c7d082545807c47e80c5` | Exposes typed record-set framing/format/CRC/policy failures so brokers can isolate one bad partition without string matching. | Additive error detail; success unchanged. **Direct.** | `9ee05bb` | Issue TBD / PR TBD |
| `076846f`<br>`076846ff570005ccfa7d55330b984f5bdca16aeb` | Streams only selected values into caller scratch, bounds all semantic work/bytes, and carries failed progress so bomb budgets cannot reset after errors. | Additive already-decompressed reader; no codec/default change. **Direct.** | `cc143e7` | Issue TBD / PR TBD |
| `ac17eb1`<br>`ac17eb120189c2614398f4b321a6063b6925994d` | Defers record-set validation to field access so corrupt partitions can fail independently after the complete envelope is safe. | Eager validation remains the default. **Direct.** | `86da8f5` | Issue TBD / PR TBD |
| `c2c5b2b`<br>`c2c5b2bf0f87ea512df6eeda9b8dc38ab7a427db` | Keeps record-set count/work overflow inside the typed partition-local error taxonomy. | Correctness only; success/default behavior unchanged. **Correctness.** | `ca65ac8` | Issue TBD / PR TBD |
| `0a648bf`<br>`0a648bf0776e4d3c7f2640913715686c0ac8d214` | Reuses caller transfer scratch for every skipped field and EOF probe, removing repeated 8 KiB initialization as a CPU amplification vector. | Caller supplies nonempty scratch; additive API evolution. **Direct.** | `076846f` | Issue TBD / PR TBD |

**Verification:** generator fixtures and schema drift failures, pointer-sharing and
CRC adversaries, exact-frame/trailing/limit cases, C1 parity, lending lifetime
compile-fail tests, failed-progress accounting, flexible v0/v4 control requests,
and zero hidden response buffering.

## 6. Bounded compressed record streams

| Commit | Robustness value and why it is needed | Defaults / Rome status | Depends on | Upstream |
| --- | --- | --- | --- | --- |
| `1911c7b`<br>`1911c7b049f09eb88ef056a306a726507d634dd6` | Defines explicit typed Snappy-block, LZ4-block, and exact Zstd-window ceilings before native decoder construction. | No aggregate policy or permissive `Default`; existing inflation unchanged. **Direct.** | — | Issue TBD / PR TBD |
| `d5f07dc`<br>`d5f07dc44bd6d3062d3000c06a632fe6f5906e3e` | Streams allocation-free RFC 1952 envelopes, including concatenated members, and verifies per-member CRC/ISIZE plus exact final EOF. | Additive gzip reader; owned/default compression unchanged. **Direct.** | `076846f` | Issue TBD / PR TBD |
| `cc08ee7`<br>`cc08ee7bcad1a2c5d037fd1b1ed4047da84149e0` | Preflights every Xerial block before output and reuses caller scratch, preventing a late oversized block after earlier values were emitted. | Additive reader; existing Snappy path unchanged. **Direct.** | `1911c7b`, `076846f` | Issue TBD / PR TBD |
| `9e73b09`<br>`9e73b097863a0bb41aa7b7685551a04c3158ce4b` | Preflights the complete LZ4 frame, exact end marker/checksums, block ceiling, and linked-history mode before backend allocation. | Additive reader; existing LZ4 path unchanged. **Direct.** | `1911c7b`, `076846f` | Issue TBD / PR TBD |
| `c32bf6e`<br>`c32bf6e39a6a6df4288a48f7e2d7d91d5fc940d8` | Admits exact Zstd window bytes and one exact non-dictionary/non-skippable frame, avoiding backend-log rounding and hidden input buffering. | Additive reader; existing Zstd path unchanged. **Direct.** | `1911c7b`, `076846f` | Issue TBD / PR TBD |
| `19be185`<br>`19be185529d1e8b3542ee6553ac02ab5f8045dcf` | Stack-dispatches the four bounded compressed readers into `ValueRecords` without boxing or weakening codec-specific admission. | Additive compressed-only enum; uncompressed and owned inflation remain separate. **Direct; immutable Rome code milestone.** | preceding five rows | Issue TBD / PR TBD |

**Verification:** all four codecs produce declared values and then surface deferred
terminal corruption through both `next_value` and `finish`; gzip additionally
covers concatenated members and header/trailer integrity; Snappy, LZ4, and Zstd
cover exact structural and configured state limits.

## Milestone verification

At `19be185`, the polished 38-commit tree is byte-identical to the corrected codec
development milestone `c9282df1483e4f64735d37c064a6aaa454f30412`.
Verification completed for the affected crates includes:

- `tansu-service`: all-feature tests (including listener, admission, framing,
  transport, and routing coverage) and all-target/all-feature Clippy with warnings
  denied;
- `tansu-auth`: all-feature tests and all-target/all-feature Clippy with warnings
  denied;
- `tansu-sans-io`: all-feature tests and all-target/all-feature Clippy with
  warnings denied;
- `git show --check` across the complete series, a 38-commit count, and nonempty
  rationale bodies for every commit.

Workspace-wide Clippy is not a milestone claim: the standalone worktree layout
triggers an unrelated `tansu-schema` checkout-relative test include. The affected
crate checks above are the reproducible verification boundary for this series.

## Fork maintenance rules

1. Never rewrite or move `19be185`; Rome pins that immutable code milestone.
2. Keep this manifest and later documentation in docs-only descendants. A docs
   SHA may be tagged or reviewed, but must not replace the code SHA in Rome.
3. Keep commits dependency-ordered and independently cherry-pickable. Upstream
   feedback should be applied as new topic branches or commits, not by silently
   mutating published milestone history.
4. Preserve upstream-compatible defaults. New policy remains opt-in; only
   correctness/security fixes deliberately reject behavior that was invalid or
   unsafe.
5. Do not add Rome types, memory-governor policy, route policy, or advertised API
   choices to Tansu. Tansu provides typed lifecycle, admission, evidence, bounded
   decode, and codec seams; Rome owns the deployment policy.
6. Record the eventual discussion and PR URLs in the placeholders above, and
   note any commit replacement explicitly so downstream pins remain auditable.
