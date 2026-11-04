//! The shared session as one state machine.
//!
//! INWX keeps one session per account: a successful `account.login` replaces
//! the cookie that was valid before it, and the older session is dead
//! server-side afterwards. Two logins that overlap therefore do not both end
//! well — the one whose answer arrives last installs a cookie the other login
//! has already invalidated, and every attempt is a credential POST against an
//! account that locks after repeated failures.
//!
//! Thirty-two tasks on one client must not each open a session. This module
//! makes the transition single-flight: one claim at a time, the callers that
//! lose the race wait for that login's cookie instead of posting credentials of
//! their own, and a cookie is installed only while the state is still the one
//! the login was started for.
//!
//! Everything here is synchronous under one [`Mutex`], and that lock is never
//! held across an `.await`: the wait for a login in flight is a `poll_fn` over a
//! list of wakers, so the crate still runs on whatever executor the caller
//! brings and needs no runtime of its own.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};

/// Cookie, generation and the tasks waiting for a login in flight.
#[derive(Debug, Default)]
struct State {
    /// The `Set-Cookie` value every request replays, when there is one.
    cookie: Option<String>,
    /// Bumped on every transition — install, drop, claim — so a caller can tell
    /// "the session I saw is still the one installed" from "somebody already
    /// replaced it" without comparing cookies (two logins can hand out the same
    /// cookie, and equal strings then hide a transition).
    generation: u64,
    /// Set while one `account.login` is on the wire.
    logging_in: bool,
    /// Tasks parked until that login is finished.
    waiters: Vec<Waker>,
}

/// The shared session of one client.
#[derive(Debug, Default)]
pub(crate) struct SessionGate {
    state: Arc<Mutex<State>>,
}

impl SessionGate {
    /// A gate without a session.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cookie to replay, if a session is installed.
    pub(crate) fn cookie(&self) -> Option<String> {
        self.lock().cookie.clone()
    }

    /// Whether a cookie is installed.
    pub(crate) fn is_authenticated(&self) -> bool {
        self.lock().cookie.is_some()
    }

    /// The generation of the state right now.
    ///
    /// Read before a request is sent, so that a session which died during the
    /// round trip can be told apart from one a concurrent caller has replaced
    /// in the meantime.
    pub(crate) fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Installs a cookie that did not come from a login on this client — the
    /// one [`InwxClient::with_session`](crate::InwxClient::with_session) was
    /// handed.
    pub(crate) fn install(&self, cookie: String) {
        let mut state = self.lock();
        state.cookie = Some(cookie);
        state.generation = state.generation.wrapping_add(1);
        // No login can be in flight here: `install` runs on the builder, before
        // the client is shared. Nothing to wake.
    }

    /// Drops the cookie without telling the server.
    ///
    /// A login that is on the wire finishes afterwards but does not install its
    /// cookie: dropping a session must not be undone by a transition that
    /// started before the drop.
    pub(crate) fn clear(&self) {
        let mut state = self.lock();
        state.cookie = None;
        state.generation = state.generation.wrapping_add(1);
    }

    /// Claims the one login that may be on the wire, or reports that a session
    /// is already installed.
    ///
    /// `seen` is the generation the caller found dead, or `None` when any
    /// session will do. A caller that arrives while another login is in flight
    /// waits for it and then re-decides, so a session that died under
    /// thirty-two tasks costs one `account.login`, not thirty-two.
    pub(crate) async fn begin(&self, seen: Option<u64>) -> Turn {
        loop {
            if let Some(turn) = self.try_begin(seen) {
                return turn;
            }
            self.wait_until_idle().await;
        }
    }

    /// One attempt at [`Self::begin`] without waiting; `None` means a login is
    /// on the wire and the caller has to wait for it.
    fn try_begin(&self, seen: Option<u64>) -> Option<Turn> {
        let mut state = self.lock();
        // A session that is not the one this caller saw fail is somebody else's
        // finished work: replacing it would invalidate the cookie that caller
        // is about to use, without making this one any better.
        if state.cookie.is_some() && seen.is_none_or(|seen| seen != state.generation) {
            return Some(Turn::Fresh);
        }
        if state.logging_in {
            return None;
        }
        // The rejected cookie goes before the wire call, so no request leaves
        // with a session the API has already dropped.
        state.cookie = None;
        state.generation = state.generation.wrapping_add(1);
        state.logging_in = true;
        let claim = Claim {
            state: Arc::clone(&self.state),
            generation: state.generation,
            resolved: false,
        };
        drop(state);
        Some(Turn::Login(claim))
    }

    /// Parks the current task until no login is on the wire any more.
    ///
    /// The waker is registered under the same lock that the login releases, so
    /// a login that finishes between the two cannot be missed. A task that is
    /// dropped while parked leaves one dead waker behind; the next transition
    /// drains the whole list, so the list never grows past the number of tasks
    /// that were ever parked between two transitions.
    async fn wait_until_idle(&self) {
        std::future::poll_fn(|cx| {
            let mut state = self.lock();
            if !state.logging_in {
                return Poll::Ready(());
            }
            if !state
                .waiters
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                state.waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await;
    }
}

/// What [`SessionGate::begin`] decided for one caller.
pub(crate) enum Turn {
    /// A session is installed: use it instead of logging in.
    Fresh,
    /// This caller owns the transition and has to run the login.
    Login(Claim),
}

/// The right to run the one `account.login` that is on the wire.
///
/// Resolving it installs the cookie the login produced — or records that it
/// produced none — and wakes the callers that waited for it. Dropping it
/// unresolved (a task aborted mid-login) releases the claim just the same, so an
/// aborted login cannot park every other caller forever.
pub(crate) struct Claim {
    state: Arc<Mutex<State>>,
    generation: u64,
    resolved: bool,
}

impl Claim {
    /// Installs the cookie this login produced, or `None` for a failed login,
    /// and wakes everyone who waited.
    pub(crate) fn resolve(mut self, cookie: Option<String>) {
        self.settle(cookie);
    }

    fn settle(&mut self, cookie: Option<String>) {
        if self.resolved {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Only a state that did not move on may take this cookie: a
        // `clear_session` between the claim and the answer keeps the session
        // empty, because an explicit drop outranks a login nobody asked for any
        // more.
        if state.generation == self.generation {
            if let Some(cookie) = cookie {
                state.cookie = Some(cookie);
                state.generation = state.generation.wrapping_add(1);
            }
        }
        state.logging_in = false;
        let waiters = std::mem::take(&mut state.waiters);
        self.resolved = true;
        drop(state);
        for waker in waiters {
            waker.wake();
        }
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.settle(None);
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionGate, Turn};

    /// A claim blocks the next one until it is resolved, and the waiter then
    /// sees the session instead of claiming a second login.
    #[tokio::test]
    async fn a_second_caller_reuses_the_session_of_the_first() {
        let gate = SessionGate::new();
        let Turn::Login(claim) = gate.begin(None).await else {
            panic!("the first caller must claim the login");
        };
        claim.resolve(Some("s=1".to_owned()));

        let Turn::Fresh = gate.begin(None).await else {
            panic!("an installed session must not be claimed again");
        };
        assert_eq!(gate.cookie().as_deref(), Some("s=1"));
    }

    /// A session that is not the one the caller saw fail is not replaced:
    /// replacing it would invalidate a cookie another task is already using.
    #[tokio::test]
    async fn a_login_does_not_replace_a_newer_session() {
        let gate = SessionGate::new();
        let stale = gate.generation();
        gate.install("s=old".to_owned());
        // Somebody else recovered the session between our failure and our call.
        gate.clear();
        gate.install("s=new".to_owned());

        let Turn::Fresh = gate.begin(Some(stale)).await else {
            panic!("the newer session must be reused");
        };
        assert_eq!(gate.cookie().as_deref(), Some("s=new"));
    }

    /// Dropping a claim without a cookie releases the next caller: a login that
    /// failed must not park everybody behind it.
    #[tokio::test]
    async fn a_failed_login_releases_the_next_caller() {
        let gate = SessionGate::new();
        let Turn::Login(claim) = gate.begin(None).await else {
            panic!("the first caller must claim the login");
        };
        claim.resolve(None);
        assert!(!gate.is_authenticated());

        let Turn::Login(_) = gate.begin(None).await else {
            panic!("a failed login must let the next caller try");
        };
    }

    /// A cookie that arrives after a `clear` is dropped, not installed.
    #[tokio::test]
    async fn a_clear_wins_over_a_login_in_flight() {
        let gate = SessionGate::new();
        let Turn::Login(claim) = gate.begin(None).await else {
            panic!("the caller must claim the login");
        };
        gate.clear();
        claim.resolve(Some("s=late".to_owned()));

        assert!(!gate.is_authenticated());
    }
}
