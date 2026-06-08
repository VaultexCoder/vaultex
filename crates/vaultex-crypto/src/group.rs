//! Group messaging types for VAULTEX.
//!
//! Phase 1 uses fan-out encryption: the sender encrypts the message
//! individually for each group member using their existing pairwise
//! Double Ratchet sessions. This is less efficient than sender keys
//! but reuses the existing crypto infrastructure.

use serde::{Deserialize, Serialize};
use sodiumoxide::randombytes::randombytes;

use crate::errors::{CryptoError, Result};

/// A unique identifier for a group conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    /// Generate a random 32-byte group ID.
    pub fn generate() -> Result<Self> {
        sodiumoxide::init().map_err(|_| CryptoError::InitFailed)?;
        let bytes = randombytes(32);
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }

    /// Encode the group ID as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode a group ID from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::RatchetError("invalid hex for group ID".into()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::RatchetError(
                "group ID must be 32 bytes".into(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }
}

/// Metadata about a group conversation.
///
/// This is stored locally on each member's device. The server stores
/// only opaque group IDs and member account IDs — never group names
/// or other metadata (zero-knowledge constraint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Unique group identifier.
    pub group_id: GroupId,
    /// Human-readable group name (stored locally only, never sent to server).
    pub name: String,
    /// Identity key hex strings of each group member.
    pub members: Vec<String>,
    /// Unix timestamp (seconds) when the group was created.
    pub created_at: u64,
    /// Identity key hex of the group creator.
    pub created_by: String,
}

impl GroupInfo {
    /// Create a new group with the given name and initial members.
    ///
    /// The creator's identity key is automatically included in the member list.
    pub fn new(
        name: String,
        creator_identity_hex: String,
        member_identity_hexes: Vec<String>,
    ) -> Result<Self> {
        let group_id = GroupId::generate()?;

        let mut members = member_identity_hexes;
        if !members.contains(&creator_identity_hex) {
            members.push(creator_identity_hex.clone());
        }

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            group_id,
            name,
            members,
            created_at,
            created_by: creator_identity_hex,
        })
    }

    /// Add a member to the group. Returns true if the member was added,
    /// false if they were already a member.
    pub fn add_member(&mut self, identity_key_hex: String) -> bool {
        if self.members.contains(&identity_key_hex) {
            false
        } else {
            self.members.push(identity_key_hex);
            true
        }
    }

    /// Remove a member from the group. Returns true if the member was removed,
    /// false if they were not a member.
    pub fn remove_member(&mut self, identity_key_hex: &str) -> bool {
        let before = self.members.len();
        self.members.retain(|m| m != identity_key_hex);
        self.members.len() < before
    }

    /// Check if an identity key is a member of this group.
    pub fn is_member(&self, identity_key_hex: &str) -> bool {
        self.members.iter().any(|m| m == identity_key_hex)
    }

    /// Get the list of members excluding the given identity key
    /// (useful for fan-out: encrypt for everyone except self).
    pub fn other_members(&self, self_identity_hex: &str) -> Vec<&str> {
        self.members
            .iter()
            .filter(|m| m.as_str() != self_identity_hex)
            .map(|m| m.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_id_generate_unique() {
        sodiumoxide::init().unwrap();
        let id1 = GroupId::generate().unwrap();
        let id2 = GroupId::generate().unwrap();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn test_group_id_hex_roundtrip() {
        sodiumoxide::init().unwrap();
        let id = GroupId::generate().unwrap();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let restored = GroupId::from_hex(&hex).unwrap();
        assert_eq!(id.0, restored.0);
    }

    #[test]
    fn test_group_id_from_hex_invalid_length() {
        let result = GroupId::from_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn test_group_id_from_hex_invalid_hex() {
        let result = GroupId::from_hex("zzzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_group_info_new_includes_creator() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let member = "bb".repeat(32);
        let group =
            GroupInfo::new("Test Group".into(), creator.clone(), vec![member.clone()]).unwrap();

        assert_eq!(group.name, "Test Group");
        assert!(group.members.contains(&creator));
        assert!(group.members.contains(&member));
        assert_eq!(group.created_by, creator);
        assert!(group.created_at > 0);
    }

    #[test]
    fn test_group_info_creator_already_in_members() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let group =
            GroupInfo::new("Solo Group".into(), creator.clone(), vec![creator.clone()]).unwrap();

        // Creator should not be duplicated
        assert_eq!(group.members.iter().filter(|m| **m == creator).count(), 1);
    }

    #[test]
    fn test_add_member() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let mut group = GroupInfo::new("Group".into(), creator.clone(), vec![]).unwrap();

        let new_member = "bb".repeat(32);
        assert!(group.add_member(new_member.clone()));
        assert!(group.is_member(&new_member));

        // Adding again returns false
        assert!(!group.add_member(new_member));
    }

    #[test]
    fn test_remove_member() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let member = "bb".repeat(32);
        let mut group =
            GroupInfo::new("Group".into(), creator.clone(), vec![member.clone()]).unwrap();

        assert!(group.remove_member(&member));
        assert!(!group.is_member(&member));

        // Removing again returns false
        assert!(!group.remove_member(&member));
    }

    #[test]
    fn test_other_members() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let m1 = "bb".repeat(32);
        let m2 = "cc".repeat(32);
        let group = GroupInfo::new(
            "Group".into(),
            creator.clone(),
            vec![m1.clone(), m2.clone()],
        )
        .unwrap();

        let others = group.other_members(&creator);
        assert_eq!(others.len(), 2);
        assert!(others.contains(&m1.as_str()));
        assert!(others.contains(&m2.as_str()));
        assert!(!others.contains(&creator.as_str()));
    }

    #[test]
    fn test_non_member_cannot_be_verified() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let group = GroupInfo::new("Group".into(), creator, vec![]).unwrap();

        let outsider = "ff".repeat(32);
        assert!(!group.is_member(&outsider));
    }

    #[test]
    fn test_group_info_serialization() {
        sodiumoxide::init().unwrap();
        let creator = "aa".repeat(32);
        let group = GroupInfo::new("Serialization Test".into(), creator, vec![]).unwrap();

        let json = serde_json::to_string(&group).unwrap();
        let restored: GroupInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "Serialization Test");
        assert_eq!(restored.group_id.0, group.group_id.0);
    }
}
