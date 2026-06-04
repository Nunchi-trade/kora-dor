# Issue #170: DKG Crash Recovery Skips Re-Broadcasting Dealer Messages

## Problem

When a DKG participant crashes after Phase 3 (dealer finalized) and restores
from persisted state, the ceremony runner sets `skip_phase1 = true` and
`skip_phase3 = true`. This means the dealer log that was created and
persisted to disk is never re-broadcast to peers.

If the crash occurred between creating the dealer log and peers receiving it,
those peers will never get the log. Phase 4 (collecting dealer logs) will
then time out because not all dealer logs can be collected.

## Fix

Added a `DkgParticipant::requeue_dealer_log_for_broadcast()` method that
re-enqueues the persisted dealer log as an outgoing broadcast message.
This is called during crash recovery when Phase 1 and Phase 3 are skipped
(i.e., when the dealer was already finalized before the crash).
