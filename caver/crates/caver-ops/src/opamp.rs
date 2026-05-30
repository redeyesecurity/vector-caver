//! OPAMP agent-registration stub for RES fleet UI integration.
//!
//! The Open Agent Management Protocol (OPAMP) lets a management plane push
//! config updates to agents and receive health/capability reports.  Upstream
//! Vector ships partial OPAMP support; this module provides the agent-identity
//! and label structures that caver-collector will eventually wire to the RES
//! fleet UI at `app.etairos.ai`.
//!
//! # Current state
//!
//! This is a typed stub.  Full OPAMP wire protocol requires the `opamp-client`
//! crate and a running management server.  The structs here capture the
//! _intent_ (what metadata we'll register) so that the config schema is
//! already defined when the OPAMP integration is completed.
//!
//! # Planned fields for RES fleet UI
//!
//! - `agent_id`: stable UUID for this collector instance
//! - `tenant_id`: which RES customer this agent belongs to
//! - `site`: physical or logical site label (e.g. `"aws-us-east-1"`)
//! - `agent_pool`: collector role (`"edge"`, `"aggregator"`, `"replay"`)
//! - `version`: caver-collector version string

use serde_json::{json, Value};

/// Stable identity for a caver-collector instance registered with the fleet UI.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Stable agent UUID.  Should be persisted across restarts.
    pub agent_id: String,
    /// RES customer / tenant identifier.
    pub tenant_id: String,
    /// Physical or logical site label.
    pub site: String,
    /// Collector role within the pipeline.
    pub agent_pool: AgentPool,
    /// Caver-collector semantic version string.
    pub version: String,
}

/// Role of a caver-collector instance in the pipeline topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPool {
    /// Edge collector: ingests directly from sources.
    Edge,
    /// Aggregator: fans-in from multiple edge collectors.
    Aggregator,
    /// Replay agent: replays stored events for backtesting.
    Replay,
}

impl AgentPool {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentPool::Edge => "edge",
            AgentPool::Aggregator => "aggregator",
            AgentPool::Replay => "replay",
        }
    }
}

impl AgentIdentity {
    /// Serialize to a JSON object suitable for OPAMP `AgentDescription.identifying_attributes`.
    pub fn to_attributes(&self) -> Value {
        json!({
            "agent_id":   self.agent_id,
            "tenant_id":  self.tenant_id,
            "site":       self.site,
            "agent_pool": self.agent_pool.as_str(),
            "version":    self.version,
            "software":   "caver-collector",
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> AgentIdentity {
        AgentIdentity {
            agent_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            tenant_id: "acme-corp".into(),
            site: "aws-us-east-1".into(),
            agent_pool: AgentPool::Edge,
            version: "0.6.0".into(),
        }
    }

    #[test]
    fn attributes_contain_required_fields() {
        let attrs = sample_identity().to_attributes();
        assert_eq!(attrs["agent_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(attrs["tenant_id"], "acme-corp");
        assert_eq!(attrs["site"], "aws-us-east-1");
        assert_eq!(attrs["agent_pool"], "edge");
        assert_eq!(attrs["software"], "caver-collector");
    }

    #[test]
    fn agent_pool_str_variants() {
        assert_eq!(AgentPool::Edge.as_str(), "edge");
        assert_eq!(AgentPool::Aggregator.as_str(), "aggregator");
        assert_eq!(AgentPool::Replay.as_str(), "replay");
    }

    #[test]
    fn aggregator_identity() {
        let mut id = sample_identity();
        id.agent_pool = AgentPool::Aggregator;
        assert_eq!(id.to_attributes()["agent_pool"], "aggregator");
    }
}
