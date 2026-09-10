use alloy_primitives::U256;
use blq_primitives::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const PEER_BAN_THRESHOLD: i32 = -100;
pub const PEER_MAX_SCORE: i32 = 100;
// Peers that repeatedly send invalid protocol data are temporarily isolated,
// not permanently excluded. Transport pressure and sync races are handled by
// backpressure in the node and must not reach this path.
pub const PEER_BAN_COOLDOWN_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Hash256);

impl PeerId {
    pub fn from_advertised_address(address: &str) -> Self {
        Self(Hash256(*blake3::hash(address.as_bytes()).as_bytes()))
    }

    pub fn from_identity_public_key(public_key: &str) -> Self {
        let mut input = b"BLQ-PEER-IDENTITY-v1\0".to_vec();
        input.extend_from_slice(public_key.to_ascii_lowercase().as_bytes());
        Self(Hash256(*blake3::hash(&input).as_bytes()))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScore {
    pub score: i32,
    pub consecutive_failures: u32,
    pub banned: bool,
    #[serde(default)]
    pub ban_until_epoch: Option<u64>,
    #[serde(default)]
    pub last_failure_epoch: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct PeerScoreBook {
    peers: BTreeMap<PeerId, PeerScore>,
}

#[derive(Deserialize, Serialize)]
struct StoredPeerScore {
    peer: PeerId,
    score: PeerScore,
}

impl PeerScoreBook {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).map_err(|err| err.to_string())?;
        let entries: Vec<StoredPeerScore> =
            serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
        Ok(Self {
            peers: entries
                .into_iter()
                .map(|entry| (entry.peer, entry.score))
                .collect(),
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let temp = path.with_extension("json.tmp");
        let entries = self
            .peers
            .iter()
            .map(|(peer, score)| StoredPeerScore {
                peer: *peer,
                score: score.clone(),
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec_pretty(&entries).map_err(|err| err.to_string())?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(|err| err.to_string())?;
        file.write_all(&bytes).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())?;
        drop(file);
        fs::rename(&temp, path).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub fn observe_valid(&mut self, peer: PeerId) -> &PeerScore {
        let entry = self.peers.entry(peer).or_default();
        // A banned identity must not be able to self-clear its ban by sending
        // one well-formed message. Recovery is an explicit operator action.
        if entry.banned {
            return entry;
        }
        entry.score = (entry.score + 1).min(PEER_MAX_SCORE);
        entry.consecutive_failures = 0;
        entry
    }

    pub fn clear_ban(&mut self, peer: PeerId) -> &PeerScore {
        let entry = self.peers.entry(peer).or_default();
        entry.score = 0;
        entry.consecutive_failures = 0;
        entry.banned = false;
        entry.ban_until_epoch = None;
        entry
    }

    pub fn penalize(&mut self, peer: PeerId, penalty: i32) -> &PeerScore {
        let entry = self.peers.entry(peer).or_default();
        entry.score = entry.score.saturating_sub(penalty.abs());
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_epoch = Some(current_epoch());
        if entry.score <= PEER_BAN_THRESHOLD {
            entry.banned = true;
            entry.ban_until_epoch = Some(current_epoch().saturating_add(PEER_BAN_COOLDOWN_SECS));
        }
        entry
    }

    pub fn is_banned(&self, peer: PeerId) -> bool {
        self.peers
            .get(&peer)
            .map(|score| {
                score.banned
                    && score
                        .ban_until_epoch
                        .map(|until| current_epoch() < until)
                        .unwrap_or(true)
            })
            .unwrap_or(false)
    }

    pub fn get(&self, peer: PeerId) -> PeerScore {
        self.peers.get(&peer).cloned().unwrap_or_default()
    }

    pub fn clear_all_bans(&mut self) -> usize {
        let mut cleared = 0;
        for score in self.peers.values_mut() {
            if score.banned || score.score != 0 || score.consecutive_failures != 0 {
                cleared += 1;
            }
            score.score = 0;
            score.consecutive_failures = 0;
            score.banned = false;
            score.ban_until_epoch = None;
        }
        cleared
    }
}

fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchTip {
    pub height: u64,
    pub hash: Hash256,
    pub difficulty_target: Hash256,
    pub cumulative_work: u128,
}

impl BranchTip {
    pub fn new(height: u64, hash: Hash256, difficulty_target: Hash256) -> Self {
        Self {
            height,
            hash,
            difficulty_target,
            cumulative_work: work_for_target(difficulty_target),
        }
    }

    pub fn extend(self, hash: Hash256, difficulty_target: Hash256) -> Self {
        Self {
            height: self.height.saturating_add(1),
            hash,
            difficulty_target,
            cumulative_work: self
                .cumulative_work
                .saturating_add(work_for_target(difficulty_target)),
        }
    }
}

pub fn work_for_target(target: Hash256) -> u128 {
    if target == Hash256([0xff; 32]) {
        return 1;
    }
    // Work is floor(2^256 / (target + 1)). Keep the numerator representable
    // as MAX + 1 and add one only when that hidden increment crosses the
    // divisor boundary, then saturate to the u128 representation used here.
    let denominator = U256::from_be_bytes(target.0) + U256::from(1u8);
    let max = U256::MAX;
    let mut quotient = max / denominator;
    if max % denominator == denominator - U256::from(1u8) && quotient != U256::MAX {
        quotient += U256::from(1u8);
    }
    let max_work = U256::from(u128::MAX);
    if quotient > max_work {
        u128::MAX
    } else {
        quotient.to::<u128>().max(1)
    }
}

pub fn better_branch(candidate: BranchTip, current: BranchTip) -> bool {
    (
        candidate.cumulative_work,
        candidate.height,
        std::cmp::Reverse(candidate.hash),
    ) > (
        current.cumulative_work,
        current.height,
        std::cmp::Reverse(current.hash),
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("peer is banned")]
    BannedPeer,
    #[error("branch does not extend its parent")]
    InvalidExtension,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_is_banned_after_repeated_failures() {
        let peer = PeerId::from_advertised_address("192.0.2.39:30333");
        let mut book = PeerScoreBook::default();
        for _ in 0..10 {
            book.penalize(peer, 11);
        }
        assert!(book.is_banned(peer));
        book.observe_valid(peer);
        assert!(book.is_banned(peer));
        book.clear_ban(peer);
        assert!(!book.is_banned(peer));
    }

    #[test]
    fn branch_choice_prefers_cumulative_work_then_height_then_hash() {
        let weak = BranchTip::new(10, Hash256([1; 32]), Hash256([0xff; 32]));
        let strong = BranchTip::new(9, Hash256([2; 32]), Hash256([0x0f; 32]));
        assert!(better_branch(strong, weak));
    }

    #[test]
    fn branch_comparison_remains_deterministic_across_work_and_ties() {
        let mut current = BranchTip::new(0, Hash256([0; 32]), Hash256([0xff; 32]));
        for height in 1..=1024 {
            let candidate =
                current.extend(Hash256([(height & 0xff) as u8; 32]), Hash256([0xff; 32]));
            assert!(better_branch(candidate, current));
            current = candidate;
        }

        let left = BranchTip::new(7, Hash256([1; 32]), Hash256([0x7f; 32]));
        let right = BranchTip::new(7, Hash256([2; 32]), Hash256([0x7f; 32]));
        assert_ne!(better_branch(left, right), better_branch(right, left));
    }

    #[test]
    fn cumulative_work_uses_all_target_bits() {
        let boundary: U256 = U256::from(1u8) << 254;
        let lower = Hash256((boundary - U256::from(1u8)).to_be_bytes::<32>());
        let higher = Hash256(boundary.to_be_bytes::<32>());
        let lower_work = work_for_target(lower);
        let higher_work = work_for_target(higher);
        assert!(lower_work > higher_work);

        assert_eq!(work_for_target(Hash256([0xff; 32])), 1);
        assert_eq!(work_for_target(Hash256::ZERO), u128::MAX);
    }

    #[test]
    fn peer_score_bounds_and_ban_transition_are_stable() {
        let peer = PeerId::from_advertised_address("127.0.0.1:30333");
        let mut book = PeerScoreBook::default();
        for _ in 0..200 {
            book.observe_valid(peer);
        }
        assert_eq!(book.get(peer).score, PEER_MAX_SCORE);
        for _ in 0..200 {
            book.penalize(peer, 3);
        }
        assert!(book.is_banned(peer));
        book.observe_valid(peer);
        assert!(book.is_banned(peer));
        book.clear_ban(peer);
        assert!(!book.is_banned(peer));
        assert_eq!(book.get(peer).consecutive_failures, 0);
    }

    #[test]
    fn peer_scores_round_trip_to_disk() {
        let path = std::env::temp_dir().join(format!(
            "blq-peer-scores-{}-{}.json",
            std::process::id(),
            17
        ));
        let peer = PeerId::from_advertised_address("127.0.0.1:30333");
        let mut scores = PeerScoreBook::default();
        scores.penalize(peer, 12);
        scores.save(&path).expect("save scores");
        let loaded = PeerScoreBook::load(&path).expect("load scores");
        assert_eq!(loaded.get(peer), scores.get(peer));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn peer_ban_has_bounded_cooldown() {
        let peer = PeerId::from_advertised_address("127.0.0.1:30335");
        let mut scores = PeerScoreBook::default();
        for _ in 0..10 {
            scores.penalize(peer, 11);
        }
        let score = scores.get(peer);
        assert!(score.banned);
        assert!(score.ban_until_epoch.is_some());
        assert!(score.last_failure_epoch.is_some());
    }

    #[test]
    fn identity_peer_ids_are_stable_and_address_independent() {
        let identity = PeerId::from_identity_public_key(
            "02f3f1db3e8915533722c943ff52f18dbefd269ecbae9d5d166ff95d41047c3334",
        );
        assert_eq!(
            identity,
            PeerId::from_identity_public_key(
                "02f3f1db3e8915533722c943ff52f18dbefd269ecbae9d5d166ff95d41047c3334"
            )
        );
        assert_eq!(
            identity,
            PeerId::from_identity_public_key(
                "02F3F1DB3E8915533722C943FF52F18DBEFD269ECBAE9D5D166FF95D41047C3334"
            )
        );
        assert_ne!(
            identity,
            PeerId::from_identity_public_key(
                "033f2aae0bf475ece7b700de93d02487845e6aff33e6fab3ebb61668b5f9161792"
            )
        );
        assert_ne!(
            identity,
            PeerId::from_advertised_address("192.0.2.39:30333")
        );
    }

    #[test]
    fn peer_score_save_replaces_existing_file_durably() {
        let path = std::env::temp_dir().join(format!(
            "blq-peer-scores-replace-{}-{}.json",
            std::process::id(),
            23
        ));
        let peer = PeerId::from_advertised_address("127.0.0.1:30334");
        let mut first = PeerScoreBook::default();
        first.penalize(peer, 12);
        first.save(&path).expect("save first score state");

        let mut second = PeerScoreBook::default();
        second.observe_valid(peer);
        second.save(&path).expect("replace score state");
        let loaded = PeerScoreBook::load(&path).expect("load replaced score state");
        assert_eq!(loaded.get(peer), second.get(peer));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn randomized_branch_ordering_is_strict_and_transitive() {
        // A deterministic generator keeps this stress test reproducible without
        // making consensus or network behavior depend on an external RNG.
        let mut seed = 0x6d5a_56e9_1f3b_2c47u64;
        let mut tips = Vec::with_capacity(4096);
        for height in 0..4096u64 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&seed.to_be_bytes());
            hash[8..16].copy_from_slice(&seed.rotate_left(17).to_be_bytes());
            let target = if seed & 1 == 0 {
                [0x7f; 32]
            } else {
                [0xff; 32]
            };
            tips.push(BranchTip::new(height, Hash256(hash), Hash256(target)));
        }

        for (left_index, left) in tips.iter().enumerate() {
            assert!(!better_branch(*left, *left));
            for right in tips.iter().skip(left_index + 1).take(31) {
                assert_ne!(
                    better_branch(*left, *right),
                    better_branch(*right, *left),
                    "distinct branch tips must have one deterministic winner"
                );
            }
        }

        let mut chain = BranchTip::new(0, Hash256([0; 32]), Hash256([0xff; 32]));
        let mut previous_work = chain.cumulative_work;
        for tip in tips.iter().take(1024) {
            let extended = chain.extend(tip.hash, tip.difficulty_target);
            assert!(extended.cumulative_work >= previous_work);
            assert_eq!(extended.height, chain.height + 1);
            assert!(better_branch(extended, chain));
            previous_work = extended.cumulative_work;
            chain = extended;
        }
    }
}
