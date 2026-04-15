//! Access control policies for client certificates.

use crate::auth::client_auth::ClientIdentity;

/// Action to take when a policy rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow access.
    Allow,
    /// Deny access.
    Deny,
}

/// A single policy rule for access control.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Pattern to match against client identity.
    pub pattern: String,
    /// Action to take if pattern matches.
    pub action: PolicyAction,
    /// Optional organization requirement.
    pub require_org: Option<String>,
    /// Optional issuer CN requirement.
    pub require_issuer: Option<String>,
    /// Description of this rule.
    pub description: Option<String>,
}

impl PolicyRule {
    /// Create an allow rule for a pattern.
    pub fn allow(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            action: PolicyAction::Allow,
            require_org: None,
            require_issuer: None,
            description: None,
        }
    }

    /// Create a deny rule for a pattern.
    pub fn deny(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            action: PolicyAction::Deny,
            require_org: None,
            require_issuer: None,
            description: None,
        }
    }

    /// Require a specific organization.
    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.require_org = Some(org.into());
        self
    }

    /// Require a specific issuer CN.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.require_issuer = Some(issuer.into());
        self
    }

    /// Add a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Check if this rule matches the given identity.
    pub fn matches(&self, identity: &ClientIdentity) -> bool {
        // First check the pattern
        if !identity.matches_pattern(&self.pattern) {
            return false;
        }

        // Check organization requirement
        if let Some(ref required_org) = self.require_org {
            match &identity.organization {
                Some(org) if org == required_org => {}
                _ => return false,
            }
        }

        // Check issuer requirement
        if let Some(ref required_issuer) = self.require_issuer {
            match &identity.issuer_cn {
                Some(issuer) if issuer == required_issuer => {}
                _ => return false,
            }
        }

        true
    }
}

/// Access policy for client certificate authorization.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    /// Ordered list of rules (first match wins).
    rules: Vec<PolicyRule>,
    /// Default action if no rule matches.
    default_action: PolicyAction,
}

impl AccessPolicy {
    /// Create a new policy with a default action.
    pub fn new(default_action: PolicyAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Create a policy that allows by default.
    pub fn allow_by_default() -> Self {
        Self::new(PolicyAction::Allow)
    }

    /// Create a policy that denies by default.
    pub fn deny_by_default() -> Self {
        Self::new(PolicyAction::Deny)
    }

    /// Add a rule to the policy.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Add a rule using builder pattern.
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Evaluate the policy for a client identity.
    pub fn evaluate(&self, identity: &ClientIdentity) -> PolicyAction {
        // Check rules in order (first match wins)
        for rule in &self.rules {
            if rule.matches(identity) {
                return rule.action;
            }
        }

        // No rule matched, use default
        self.default_action
    }

    /// Check if access should be allowed.
    pub fn is_allowed(&self, identity: &ClientIdentity) -> bool {
        self.evaluate(identity) == PolicyAction::Allow
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get all rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::deny_by_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(cn: &str, org: Option<&str>, issuer: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            common_name: Some(cn.to_string()),
            organization: org.map(|s| s.to_string()),
            organizational_unit: None,
            dns_names: vec![],
            email_addresses: vec![],
            serial_number: "1234".to_string(),
            fingerprint: "abcd".to_string(),
            issuer_cn: issuer.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_policy_rule_allow() {
        let rule = PolicyRule::allow("test.example.com");
        assert_eq!(rule.action, PolicyAction::Allow);
        assert_eq!(rule.pattern, "test.example.com");
    }

    #[test]
    fn test_policy_rule_deny() {
        let rule = PolicyRule::deny("bad.example.com");
        assert_eq!(rule.action, PolicyAction::Deny);
    }

    #[test]
    fn test_policy_rule_with_org() {
        let rule = PolicyRule::allow("*").with_org("Acme Corp");
        
        let id_with_org = make_identity("test", Some("Acme Corp"), None);
        let id_wrong_org = make_identity("test", Some("Other"), None);
        let id_no_org = make_identity("test", None, None);

        assert!(rule.matches(&id_with_org));
        assert!(!rule.matches(&id_wrong_org));
        assert!(!rule.matches(&id_no_org));
    }

    #[test]
    fn test_policy_rule_with_issuer() {
        let rule = PolicyRule::allow("*").with_issuer("Internal CA");
        
        let id_good = make_identity("test", None, Some("Internal CA"));
        let id_bad = make_identity("test", None, Some("External CA"));

        assert!(rule.matches(&id_good));
        assert!(!rule.matches(&id_bad));
    }

    #[test]
    fn test_access_policy_default_deny() {
        let policy = AccessPolicy::deny_by_default();
        let identity = make_identity("unknown", None, None);
        
        assert!(!policy.is_allowed(&identity));
    }

    #[test]
    fn test_access_policy_default_allow() {
        let policy = AccessPolicy::allow_by_default();
        let identity = make_identity("unknown", None, None);
        
        assert!(policy.is_allowed(&identity));
    }

    #[test]
    fn test_access_policy_first_match_wins() {
        let policy = AccessPolicy::deny_by_default()
            .with_rule(PolicyRule::deny("bad.example.com"))
            .with_rule(PolicyRule::allow("*.example.com"));

        let good_id = make_identity("good.example.com", None, None);
        let bad_id = make_identity("bad.example.com", None, None);
        let other_id = make_identity("test.other.com", None, None);

        assert!(policy.is_allowed(&good_id));
        assert!(!policy.is_allowed(&bad_id)); // Deny rule matches first
        assert!(!policy.is_allowed(&other_id)); // Default deny
    }

    #[test]
    fn test_access_policy_complex() {
        let policy = AccessPolicy::deny_by_default()
            // Allow internal services with specific issuer
            .with_rule(
                PolicyRule::allow("*.internal.example.com")
                    .with_issuer("Internal CA")
                    .with_description("Internal services")
            )
            // Allow specific external partner
            .with_rule(
                PolicyRule::allow("api.partner.com")
                    .with_org("Partner Inc")
            )
            // Deny known bad actors
            .with_rule(PolicyRule::deny("*.suspicious.com"));

        let internal = make_identity("service.internal.example.com", None, Some("Internal CA"));
        let partner = make_identity("api.partner.com", Some("Partner Inc"), None);
        let external = make_identity("other.service.com", None, None);
        let suspicious = make_identity("attack.suspicious.com", None, None);

        assert!(policy.is_allowed(&internal));
        assert!(policy.is_allowed(&partner));
        assert!(!policy.is_allowed(&external)); // Default deny
        assert!(!policy.is_allowed(&suspicious)); // Explicit deny
    }

    #[test]
    fn test_policy_rule_count() {
        let policy = AccessPolicy::deny_by_default()
            .with_rule(PolicyRule::allow("a"))
            .with_rule(PolicyRule::allow("b"));

        assert_eq!(policy.rule_count(), 2);
    }
}
