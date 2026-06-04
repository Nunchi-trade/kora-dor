# Issue #167: AllLogs Message Deserialization Has No Count Cap -- OOM Vector

## Problem

In `ProtocolMessage::from_bytes()`, the `AllLogs` variant (tag 5) reads a
`u32` count from the wire and immediately calls `Vec::with_capacity(count)`.
A malicious peer can send a message with `count = u32::MAX` (4,294,967,295),
causing the node to attempt allocating ~200+ GB of memory, resulting in an
immediate OOM crash.

Even with the existing `max_entries` check in `handle_message()` (which caps
the number of dealer logs stored), the deserialization happens *before* that
check, so the allocation is already made.

## Fix

Added a count cap in `from_bytes()` before the `Vec::with_capacity()` call.
The maximum allowed count is `max_degree * 2`, where `max_degree` is derived
from the participant count `n`. This is a generous upper bound (the actual
maximum number of dealer logs equals `n`), but it prevents any allocation
larger than what a legitimate ceremony could produce. Messages exceeding
this cap are rejected with `commonware_codec::Error::InvalidLength`.
