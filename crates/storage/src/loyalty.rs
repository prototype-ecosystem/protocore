//! Loyalty Tracker for the Inverse Rewards System
//!
//! This module tracks validator tenure and calculates loyalty scores for the
//! Proto Core inverse rewards system. The loyalty component rewards long-term
//! commitment to the network and helps prevent Sybil attacks by making it
//! economically irrational to reset and restart validators.
//!
//! ## Loyalty Formula
//!
//! ```text
//! LoyaltyScore = min(1.0, sqrt(MonthsActive / MaturityMonths))
//! ```
//!
//! The square root function allows new validators to reach 50% loyalty bonus
//! at approximately 6 months (with default 24-month maturity), making bootstrap
//! viable while still rewarding long-term commitment.
//!
//! ## Key Features
//!
//! - **Tenure Tracking**: Records when validators register and calculates active months
//! - **Cooldown Enforcement**: Prevents reset-and-restart attacks with re-registration cooldown
//! - **Sybil Tracking**: Links addresses operated by the same entity
//! - **Ban Management**: Handles confirmed Sybil bans with time-based expiration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 20-byte address type (re-exported from protocore-types when available)
pub type Address = [u8; 20];

/// Seconds in a day
const SECONDS_PER_DAY: u64 = 86_400;

/// Seconds in a month (approximation: 30 days)
const SECONDS_PER_MONTH: f64 = 30.0 * 86_400.0;

/// Tracks validator tenure and calculates loyalty scores for the inverse rewards system.
///
/// The LoyaltyTracker maintains registration records for all validators, enforces
/// re-registration cooldowns, tracks address linkages for Sybil detection, and
/// manages bans for confirmed Sybil attackers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltyTracker {
    /// Maturity period in months for full loyalty bonus (typically 24)
    maturity_months: u32,
    /// Re-registration cooldown in days (typically 90)
    cooldown_days: u32,
    /// Validator registration timestamps (Unix timestamp)
    registrations: HashMap<Address, ValidatorRegistration>,
    /// Banned addresses with unban timestamp
    banned: HashMap<Address, u64>,
}

/// Registration record for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// When the validator registered (Unix timestamp)
    pub registered_at: u64,
    /// Previous addresses this validator used (for Sybil tracking)
    pub previous_addresses: Vec<Address>,
    /// When validator can re-register if they leave (cooldown timestamp)
    pub earliest_reregister: Option<u64>,
}

/// Complete loyalty status for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltyStatus {
    /// Number of months the validator has been active
    pub months_active: f64,
    /// Maturity period in months for full loyalty bonus
    pub maturity_months: u32,
    /// Calculated loyalty score (0.0 to 1.0)
    pub loyalty_score: f64,
    /// Whether the validator has reached full maturity
    pub is_mature: bool,
    /// Months remaining until full bonus (0 if already mature)
    pub full_bonus_in_months: f64,
}

/// Snapshot of the loyalty tracker state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltySnapshot {
    /// Maturity period in months
    pub maturity_months: u32,
    /// Re-registration cooldown in days
    pub cooldown_days: u32,
    /// All validator registrations
    pub registrations: Vec<(Address, ValidatorRegistration)>,
    /// All banned addresses with unban timestamps
    pub banned: Vec<(Address, u64)>,
}

/// Errors that can occur during loyalty operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoyaltyError {
    /// Validator is in cooldown period after unregistration
    InCooldown {
        /// Days remaining in cooldown
        remaining_days: u32,
    },
    /// Address is banned due to confirmed Sybil attack
    Banned {
        /// Timestamp when ban expires
        until: u64,
    },
    /// Address is already registered as a validator
    AlreadyRegistered,
}

impl std::fmt::Display for LoyaltyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoyaltyError::InCooldown { remaining_days } => {
                write!(
                    f,
                    "Address is in cooldown period, {} days remaining",
                    remaining_days
                )
            }
            LoyaltyError::Banned { until } => {
                write!(f, "Address is banned until timestamp {}", until)
            }
            LoyaltyError::AlreadyRegistered => {
                write!(f, "Address is already registered as a validator")
            }
        }
    }
}

impl std::error::Error for LoyaltyError {}

impl LoyaltyTracker {
    /// Creates a new LoyaltyTracker with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `maturity_months` - Number of months until a validator reaches full loyalty bonus (typically 24)
    /// * `cooldown_days` - Number of days a validator must wait after unregistering before re-registering (typically 90)
    ///
    /// # Example
    ///
    /// ```
    /// use protocore_storage::loyalty::LoyaltyTracker;
    ///
    /// let tracker = LoyaltyTracker::new(24, 90);
    /// ```
    pub fn new(maturity_months: u32, cooldown_days: u32) -> Self {
        Self {
            maturity_months,
            cooldown_days,
            registrations: HashMap::new(),
            banned: HashMap::new(),
        }
    }

    /// Registers a new validator at the given timestamp.
    ///
    /// This will fail if:
    /// - The address is already registered
    /// - The address is banned
    /// - The address is in a cooldown period from previous unregistration
    ///
    /// # Arguments
    ///
    /// * `address` - The validator's address
    /// * `timestamp` - Current Unix timestamp
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Registration successful
    /// * `Err(LoyaltyError)` - Registration failed
    pub fn register_validator(
        &mut self,
        address: Address,
        timestamp: u64,
    ) -> Result<(), LoyaltyError> {
        // Check if already registered
        if self.registrations.contains_key(&address) {
            return Err(LoyaltyError::AlreadyRegistered);
        }

        // Check if banned
        if self.is_banned(&address, timestamp) {
            let until = self.banned.get(&address).copied().unwrap_or(0);
            return Err(LoyaltyError::Banned { until });
        }

        // Check cooldown - we need to look for any previous registration record
        // that might have been stored before unregistration
        // Note: In a real implementation, we might keep historical records
        // For now, cooldown is tracked via the earliest_reregister field
        // which would be set on a previous registration that was unregistered

        let registration = ValidatorRegistration {
            registered_at: timestamp,
            previous_addresses: Vec::new(),
            earliest_reregister: None,
        };

        self.registrations.insert(address, registration);
        Ok(())
    }

    /// Unregisters a validator and starts the cooldown period.
    ///
    /// After unregistering, the validator must wait `cooldown_days` before
    /// they can register again. This prevents reset-and-restart attacks.
    ///
    /// # Arguments
    ///
    /// * `address` - The validator's address
    /// * `timestamp` - Current Unix timestamp
    pub fn unregister_validator(&mut self, address: Address, timestamp: u64) {
        if let Some(mut registration) = self.registrations.remove(&address) {
            // Calculate cooldown end timestamp
            let cooldown_end = timestamp + (self.cooldown_days as u64 * SECONDS_PER_DAY);
            registration.earliest_reregister = Some(cooldown_end);

            // Store the registration back with cooldown info
            // This allows tracking of cooldown even after unregistration
            self.registrations.insert(address, registration);
        }
    }

    /// Checks if an address can register as a validator.
    ///
    /// Returns false if the address is:
    /// - Already registered (and not in cooldown)
    /// - Banned
    /// - In a cooldown period
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    /// * `timestamp` - Current Unix timestamp
    pub fn can_register(&self, address: &Address, timestamp: u64) -> bool {
        // Check if banned
        if self.is_banned(address, timestamp) {
            return false;
        }

        // Check if already registered or in cooldown
        if let Some(registration) = self.registrations.get(address) {
            // If there's an earliest_reregister set, check if cooldown has passed
            if let Some(cooldown_end) = registration.earliest_reregister {
                // In cooldown period
                if timestamp < cooldown_end {
                    return false;
                }
                // Cooldown has passed, can re-register
                return true;
            }
            // No cooldown set means actively registered
            return false;
        }

        // Not registered and not banned
        true
    }

    /// Calculates the loyalty score for a validator at the given timestamp.
    ///
    /// Uses the formula: `min(1.0, sqrt(MonthsActive / MaturityMonths))`
    ///
    /// Returns 0.0 if the validator is not registered or is in cooldown.
    ///
    /// # Arguments
    ///
    /// * `address` - The validator's address
    /// * `current_timestamp` - Current Unix timestamp
    pub fn calculate_score(&self, address: &Address, current_timestamp: u64) -> f64 {
        let Some(registration) = self.registrations.get(address) else {
            return 0.0;
        };

        // If in cooldown (has earliest_reregister set), score is 0
        if registration.earliest_reregister.is_some() {
            return 0.0;
        }

        // Calculate months active
        let seconds_active = current_timestamp.saturating_sub(registration.registered_at);
        let months_active = seconds_active as f64 / SECONDS_PER_MONTH;

        // Apply the loyalty formula: min(1.0, sqrt(months_active / maturity_months))
        let ratio = months_active / self.maturity_months as f64;

        ratio.sqrt().min(1.0)
    }

    /// Gets the complete loyalty status for a validator.
    ///
    /// Returns None if the validator is not registered or is in cooldown.
    ///
    /// # Arguments
    ///
    /// * `address` - The validator's address
    /// * `current_timestamp` - Current Unix timestamp
    pub fn get_status(&self, address: &Address, current_timestamp: u64) -> Option<LoyaltyStatus> {
        let registration = self.registrations.get(address)?;

        // If in cooldown, return None
        if registration.earliest_reregister.is_some() {
            return None;
        }

        // Calculate months active
        let seconds_active = current_timestamp.saturating_sub(registration.registered_at);
        let months_active = seconds_active as f64 / SECONDS_PER_MONTH;

        // Calculate loyalty score
        let ratio = months_active / self.maturity_months as f64;
        let loyalty_score = ratio.sqrt().min(1.0);

        // Check if mature
        let is_mature = months_active >= self.maturity_months as f64;

        // Calculate months until full bonus
        let full_bonus_in_months = if is_mature {
            0.0
        } else {
            self.maturity_months as f64 - months_active
        };

        Some(LoyaltyStatus {
            months_active,
            maturity_months: self.maturity_months,
            loyalty_score,
            is_mature,
            full_bonus_in_months,
        })
    }

    /// Bans a validator address until the specified timestamp.
    ///
    /// Used for confirmed Sybil attackers. The address cannot register
    /// as a validator until after the ban expires.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to ban
    /// * `until_timestamp` - Unix timestamp when the ban expires
    pub fn ban_validator(&mut self, address: Address, until_timestamp: u64) {
        self.banned.insert(address, until_timestamp);
        // Remove from active registrations if present
        self.registrations.remove(&address);
    }

    /// Checks if an address is currently banned.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    /// * `current_timestamp` - Current Unix timestamp
    pub fn is_banned(&self, address: &Address, current_timestamp: u64) -> bool {
        if let Some(&ban_end) = self.banned.get(address) {
            current_timestamp < ban_end
        } else {
            false
        }
    }

    /// Links two addresses as being operated by the same entity.
    ///
    /// This is used for Sybil tracking - when it's determined that multiple
    /// addresses are controlled by the same operator, they should be linked.
    ///
    /// # Arguments
    ///
    /// * `primary` - The primary address
    /// * `secondary` - The secondary address to link
    pub fn link_addresses(&mut self, primary: &Address, secondary: Address) {
        if let Some(registration) = self.registrations.get_mut(primary) {
            if !registration.previous_addresses.contains(&secondary) {
                registration.previous_addresses.push(secondary);
            }
        }
    }

    /// Gets all addresses linked to the given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to get linked addresses for
    pub fn get_linked_addresses(&self, address: &Address) -> Vec<Address> {
        self.registrations
            .get(address)
            .map(|r| r.previous_addresses.clone())
            .unwrap_or_default()
    }

    /// Creates a snapshot of the current state for persistence.
    pub fn snapshot(&self) -> LoyaltySnapshot {
        LoyaltySnapshot {
            maturity_months: self.maturity_months,
            cooldown_days: self.cooldown_days,
            registrations: self
                .registrations
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect(),
            banned: self.banned.iter().map(|(&k, &v)| (k, v)).collect(),
        }
    }

    /// Restores the tracker state from a snapshot.
    pub fn restore(snapshot: LoyaltySnapshot) -> Self {
        Self {
            maturity_months: snapshot.maturity_months,
            cooldown_days: snapshot.cooldown_days,
            registrations: snapshot.registrations.into_iter().collect(),
            banned: snapshot.banned.into_iter().collect(),
        }
    }

    /// Returns the maturity period in months.
    pub fn maturity_months(&self) -> u32 {
        self.maturity_months
    }

    /// Returns the cooldown period in days.
    pub fn cooldown_days(&self) -> u32 {
        self.cooldown_days
    }

    /// Returns the number of registered validators (not including those in cooldown).
    pub fn active_validator_count(&self) -> usize {
        self.registrations
            .values()
            .filter(|r| r.earliest_reregister.is_none())
            .count()
    }

    /// Returns all currently banned addresses with their unban timestamps.
    pub fn get_banned_addresses(&self) -> Vec<(Address, u64)> {
        self.banned.iter().map(|(&k, &v)| (k, v)).collect()
    }

    /// Clears expired bans (those where current_timestamp >= ban_end).
    pub fn clear_expired_bans(&mut self, current_timestamp: u64) {
        self.banned
            .retain(|_, &mut ban_end| current_timestamp < ban_end);
    }

    /// Clears expired cooldowns and removes those registrations.
    pub fn clear_expired_cooldowns(&mut self, current_timestamp: u64) {
        self.registrations.retain(|_, registration| {
            // Keep if not in cooldown (active validator)
            if registration.earliest_reregister.is_none() {
                return true;
            }
            // Keep if cooldown hasn't expired yet
            if let Some(cooldown_end) = registration.earliest_reregister {
                return current_timestamp < cooldown_end;
            }
            false
        });
    }
}

impl Default for LoyaltyTracker {
    fn default() -> Self {
        // Default values from the spec
        Self::new(24, 90)
    }
}
