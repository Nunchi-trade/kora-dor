# Issue #169: DKG send_outgoing Silently Drops Failed Phase 1 Broadcasts

## Problem

In `ceremony.rs`, `send_outgoing()` calls `participant.take_outgoing()` which
drains the outgoing message buffer via `std::mem::take`. If a subsequent
`network.send_to()` or `network.broadcast()` call fails (e.g., due to a
transient network error), the message is permanently lost. The warning log
says "will retry on next cycle" but no retry actually occurs because the
message has already been removed from the buffer.

This is especially critical during Phase 1 where dealer public commitments
and private shares are broadcast. If these messages are lost, the receiving
participant will never get the dealer's contribution, causing Phase 2 to
time out.

## Fix

Modified `send_outgoing()` to collect failed messages into a `Vec` and
re-queue them via a new `DkgParticipant::requeue_messages()` method. Failed
messages are prepended to the outgoing buffer so they are retried before any
newly generated messages on the next send cycle.
