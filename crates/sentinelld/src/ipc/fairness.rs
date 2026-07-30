//! Per-principal connection fairness for the IPC accept loop.
//!
//! WHY this exists: the global semaphore (`MAX_CONCURRENT_CONNECTIONS` in
//! `ipc::mod`) bounds total resource use but is blind to WHO holds the
//! permits. Permits are held for the whole session and the 60 s idle timer
//! restarts on every frame, so a single local principal — e.g. malware
//! running as the interactive console user, which `client_auth::decide`
//! deliberately Allows for GUI compat — can park all 64 permits with
//! keep-alive frames. The accept loop's `try_acquire` shed then rejects
//! EVERY new caller indiscriminately: it sheds the victim (the elevated
//! GUI the user needs to manage the daemon), not the flooder. One
//! principal must never be able to consume the entire global budget.
//!
//! Identity source and spoofing resistance: the key is the client SID
//! resolved at accept time by `client_auth::authorize_and_resolve_pipe_client`
//! (GetNamedPipeClientProcessId → OpenProcess → token query). The SID comes
//! from the client process's kernel-owned token — the client cannot choose
//! or forge it, and resolution runs BEFORE we get here (denied clients
//! never reach this module).
//!
//! Deliberately NO PID fallback: an unresolved identity falls into a shared
//! `Unidentified` bucket with its own cap, never into a per-PID bucket. A
//! PID-keyed quota is void on arrival — an attacker spawning N processes
//! gets N independent buckets and is back to consuming the whole global
//! semaphore. The unidentified bucket instead preserves the existing
//! fail-open availability contract (a transient OS API quirk must not
//! brick a legit GUI — see client_auth.rs module docs) while bounding its
//! blast radius. Note an attacker cannot steer themselves into this bucket
//! either: `ResolveOutcome::Unresolved` means the kernel would not hand us
//! the client PID or a token query failed on a live process — not
//! something a client can induce — and even if they could, 16 > 8 is a
//! bounded difference, not a bypass.
//!
//! Cap sizing: every first-party client (Tauri GUI `daemon_client`, CLI,
//! dev-console) opens ONE fresh short-lived connection per request, so a
//! generous cap of 8 concurrent connections per SID covers bursts of
//! parallel GUI calls with headroom. Nothing inside the daemon connects
//! back to its own pipe, so SYSTEM needs no exemption. The unidentified
//! bucket gets 16 because it is shared by definition (kill-switch
//! `SENTINELLA_DISABLE_CLIENT_SID_CHECK` also lands here).
//!
//! Locking / deadlock analysis: accounting lives in a `std::sync::Mutex`
//! held only for O(1) hash-map increment/decrement — never across an
//! `.await`, and never while acquiring the global semaphore, so there is
//! no lock-ordering relationship between the two limits. Shed paths rely
//! on RAII: whichever guard (global permit or principal permit) was
//! already taken is released by `Drop` when the loop `continue`s. Map
//! entries are removed at zero, so the map holds at most one entry per
//! concurrently-connected principal (bounded by the global cap, 64).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::client_auth::ClientIdentity;

/// Max concurrent IPC connections per resolved principal (SID).
pub const MAX_CONNECTIONS_PER_PRINCIPAL: usize = 8;
/// Max concurrent IPC connections sharing the unidentified bucket
/// (identity resolution failed open, or the SID-check kill-switch is on).
pub const MAX_CONNECTIONS_UNIDENTIFIED: usize = 16;

/// Bucket a connection is accounted against. `Unidentified` is a real
/// capped bucket, not a bypass — see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PrincipalKey {
    /// String SID from the client's process token (e.g. `S-1-5-21-…`).
    Sid(String),
    /// Identity could not be resolved (fail-open path) or was disabled.
    Unidentified,
}

impl PrincipalKey {
    fn from_identity(id: Option<&ClientIdentity>) -> Self {
        match id {
            Some(i) => PrincipalKey::Sid(i.sid.clone()),
            None => PrincipalKey::Unidentified,
        }
    }

    fn cap(&self) -> usize {
        match self {
            PrincipalKey::Sid(_) => MAX_CONNECTIONS_PER_PRINCIPAL,
            PrincipalKey::Unidentified => MAX_CONNECTIONS_UNIDENTIFIED,
        }
    }
}

/// Per-principal concurrent-connection accounting. Cheap to clone via
/// `Arc`; all mutation goes through the internal mutex.
#[derive(Debug, Default)]
pub struct PrincipalQuota {
    counts: Mutex<HashMap<PrincipalKey, usize>>,
}

impl PrincipalQuota {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Try to take one per-principal slot for `id` (the accept-time
    /// identity; `None` = unresolved → shared unidentified bucket).
    /// Returns `None` when the principal is already at its cap — the
    /// caller must shed the connection. The mutex is held only for the
    /// map update; poisoning is recovered rather than propagated because
    /// a panicked holder can only have left a count, and availability of
    /// the accept loop outranks exact accounting in that scenario.
    pub fn try_acquire(self: &Arc<Self>, id: Option<&ClientIdentity>) -> Option<PrincipalPermit> {
        let key = PrincipalKey::from_identity(id);
        let cap = key.cap();
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let n = counts.entry(key.clone()).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(PrincipalPermit {
            quota: Arc::clone(self),
            key,
        })
    }

    /// Decrement the bucket, removing the entry at zero so the map stays
    /// bounded by the number of concurrently-connected principals.
    fn release(&self, key: &PrincipalKey) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = counts.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(key);
            }
        }
    }

    #[cfg(test)]
    fn held(&self, id: Option<&ClientIdentity>) -> usize {
        let counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        counts
            .get(&PrincipalKey::from_identity(id))
            .copied()
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn distinct_principals(&self) -> usize {
        let counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        counts.len()
    }
}

/// RAII slot guard: dropping it releases the per-principal slot. Moved
/// into the connection task alongside the global semaphore permit so both
/// limits are held for exactly the session lifetime.
#[derive(Debug)]
pub struct PrincipalPermit {
    quota: Arc<PrincipalQuota>,
    key: PrincipalKey,
}

impl Drop for PrincipalPermit {
    fn drop(&mut self) {
        self.quota.release(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(sid: &str) -> ClientIdentity {
        ClientIdentity {
            sid: sid.into(),
            session_id: 1,
            is_elevated: false,
            is_system: sid == "S-1-5-18",
            well_known_untrusted: false,
        }
    }

    #[test]
    fn principal_capped_at_max() {
        let q = PrincipalQuota::new();
        let alice = id("S-1-5-21-1-2-3-1001");
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS_PER_PRINCIPAL {
            held.push(q.try_acquire(Some(&alice)).expect("under cap"));
        }
        assert!(
            q.try_acquire(Some(&alice)).is_none(),
            "connection #{} for one SID must be shed",
            MAX_CONNECTIONS_PER_PRINCIPAL + 1
        );
        assert_eq!(q.held(Some(&alice)), MAX_CONNECTIONS_PER_PRINCIPAL);
    }

    #[test]
    fn over_cap_shed_does_not_corrupt_accounting() {
        let q = PrincipalQuota::new();
        let alice = id("S-1-5-21-1-2-3-1001");
        let held: Vec<_> = (0..MAX_CONNECTIONS_PER_PRINCIPAL)
            .map(|_| q.try_acquire(Some(&alice)).unwrap())
            .collect();
        assert!(q.try_acquire(Some(&alice)).is_none());
        assert!(q.try_acquire(Some(&alice)).is_none());
        // Repeated sheds must not decrement or otherwise disturb the count.
        assert_eq!(q.held(Some(&alice)), MAX_CONNECTIONS_PER_PRINCIPAL);
        drop(held);
        assert_eq!(q.held(Some(&alice)), 0);
        // And the principal can connect again after releasing.
        assert!(q.try_acquire(Some(&alice)).is_some());
    }

    #[test]
    fn principals_are_independent() {
        // The core fairness property: one principal at its own cap must
        // not affect any other principal's ability to connect.
        let q = PrincipalQuota::new();
        let alice = id("S-1-5-21-1-2-3-1001");
        let bob = id("S-1-5-21-9-9-9-1055");
        let _flood: Vec<_> = (0..MAX_CONNECTIONS_PER_PRINCIPAL)
            .map(|_| q.try_acquire(Some(&alice)).unwrap())
            .collect();
        assert!(q.try_acquire(Some(&alice)).is_none());
        assert!(
            q.try_acquire(Some(&bob)).is_some(),
            "a second principal must still get service while the first is capped"
        );
    }

    #[test]
    fn drop_releases_and_entry_is_removed() {
        let q = PrincipalQuota::new();
        let alice = id("S-1-5-21-1-2-3-1001");
        {
            let _p = q.try_acquire(Some(&alice)).unwrap();
            assert_eq!(q.held(Some(&alice)), 1);
            assert_eq!(q.distinct_principals(), 1);
        }
        assert_eq!(q.held(Some(&alice)), 0);
        // Entry removed at zero → map stays bounded by live principals,
        // not by the number of distinct SIDs ever seen.
        assert_eq!(q.distinct_principals(), 0);
    }

    #[test]
    fn unidentified_bucket_is_shared_and_capped() {
        let q = PrincipalQuota::new();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS_UNIDENTIFIED {
            held.push(q.try_acquire(None).expect("under unidentified cap"));
        }
        assert!(
            q.try_acquire(None).is_none(),
            "the fail-open bucket must have its own cap, not be a bypass"
        );
        assert_eq!(q.held(None), MAX_CONNECTIONS_UNIDENTIFIED);
        drop(held);
        assert_eq!(q.held(None), 0);
    }

    #[test]
    fn unidentified_bucket_does_not_starve_identified_principals() {
        let q = PrincipalQuota::new();
        let alice = id("S-1-5-21-1-2-3-1001");
        let _flood: Vec<_> = (0..MAX_CONNECTIONS_UNIDENTIFIED)
            .map(|_| q.try_acquire(None).unwrap())
            .collect();
        assert!(q.try_acquire(None).is_none());
        assert!(q.try_acquire(Some(&alice)).is_some());
    }

    #[test]
    fn cap_constants_keep_global_budget_plausible() {
        // Sanity invariant: the per-principal caps are meaningful relative
        // to the global semaphore (64). At least two capped principals plus
        // a full unidentified bucket must fit under the global cap, so the
        // global shed stays the exception rather than the fairness
        // mechanism of last resort.
        assert!(2 * MAX_CONNECTIONS_PER_PRINCIPAL + MAX_CONNECTIONS_UNIDENTIFIED <= 64);
    }
}
