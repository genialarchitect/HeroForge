//! BloodHound/SharpHound type definitions
//!
//! These types represent Active Directory objects and relationships
//! as collected by SharpHound and used by BloodHound for attack path analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a BloodHound import
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl Default for ImportStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Configuration for BloodHound import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundConfig {
    pub domain: Option<String>,
    pub import_computers: bool,
    pub import_users: bool,
    pub import_groups: bool,
    pub import_domains: bool,
    pub import_gpos: bool,
    pub import_ous: bool,
    pub import_containers: bool,
    pub analyze_paths: bool,
}

impl Default for BloodHoundConfig {
    fn default() -> Self {
        Self {
            domain: None,
            import_computers: true,
            import_users: true,
            import_groups: true,
            import_domains: true,
            import_gpos: true,
            import_ous: true,
            import_containers: true,
            analyze_paths: true,
        }
    }
}

/// Result of a BloodHound import
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BloodHoundImportResult {
    pub id: String,
    pub status: ImportStatus,
    pub domain: String,
    pub statistics: ImportStatistics,
    pub attack_paths: Vec<AttackPath>,
    pub high_value_targets: Vec<HighValueTarget>,
    pub kerberoastable_users: Vec<KerberoastableUser>,
    pub asrep_roastable_users: Vec<AsrepRoastableUser>,
    pub unconstrained_delegation: Vec<UnconstrainedDelegation>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

/// Statistics from import
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportStatistics {
    pub total_computers: usize,
    pub total_users: usize,
    pub total_groups: usize,
    pub total_domains: usize,
    pub total_gpos: usize,
    pub total_ous: usize,
    pub total_containers: usize,
    pub total_sessions: usize,
    pub total_relationships: usize,
    pub domain_admins: usize,
    pub enterprise_admins: usize,
    pub attack_paths_found: usize,
}

/// Active Directory object types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ADObjectType {
    User,
    Computer,
    Group,
    Domain,
    GPO,
    OU,
    Container,
    Unknown,
}

impl Default for ADObjectType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Base AD object with common properties
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADObject {
    pub object_id: String,
    pub object_type: ADObjectType,
    pub name: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD User object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADUser {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub sam_account_name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub admin_count: bool,
    pub is_domain_admin: bool,
    pub is_enterprise_admin: bool,
    pub password_never_expires: bool,
    pub password_not_required: bool,
    pub dont_require_preauth: bool,
    pub has_spn: bool,
    pub service_principal_names: Vec<String>,
    pub last_logon: Option<String>,
    pub last_password_change: Option<String>,
    pub member_of: Vec<String>,
    pub has_session_on: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD Computer object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADComputer {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub sam_account_name: Option<String>,
    pub operating_system: Option<String>,
    pub os_version: Option<String>,
    pub enabled: bool,
    pub is_dc: bool,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: bool,
    pub allowed_to_delegate: Vec<String>,
    pub local_admins: Vec<String>,
    pub sessions: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD Group object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADGroup {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub sam_account_name: Option<String>,
    pub description: Option<String>,
    pub admin_count: bool,
    pub is_high_value: bool,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD Domain object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADDomain {
    pub object_id: String,
    pub name: String,
    pub domain_sid: Option<String>,
    pub forest_name: Option<String>,
    pub functional_level: Option<String>,
    pub trusts: Vec<DomainTrust>,
    pub child_domains: Vec<String>,
    pub linked_gpos: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// Domain trust relationship
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainTrust {
    pub target_domain: String,
    pub trust_direction: String,
    pub trust_type: String,
    pub is_transitive: bool,
    pub sid_filtering_enabled: bool,
}

/// AD GPO object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADGpo {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub guid: String,
    pub gpc_path: Option<String>,
    pub affects_computers: Vec<String>,
    pub affects_users: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD OU object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADOu {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub guid: Option<String>,
    pub block_inheritance: bool,
    pub linked_gpos: Vec<String>,
    pub child_objects: Vec<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// AD relationship types (edges in the graph)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum RelationshipType {
    // Group membership
    MemberOf,
    HasMember,

    // Session/access
    HasSession,
    AdminTo,
    CanRDP,
    CanPSRemote,
    ExecuteDCOM,

    // Permissions
    GenericAll,
    GenericWrite,
    WriteOwner,
    WriteDacl,
    AddMember,
    ForceChangePassword,
    AllExtendedRights,

    // GPO
    GPLink,
    Contains,

    // Delegation
    AllowedToDelegate,
    AllowedToAct,

    // Trust
    TrustedBy,

    // Kerberos
    GetChanges,
    GetChangesAll,
    ReadLAPSPassword,
    ReadGMSAPassword,

    // Certificate
    AddKeyCredentialLink,

    // SQL
    SQLAdmin,

    // Ownership
    Owns,

    // DCSync
    DCSync,

    // Other
    HasSIDHistory,
    Contains_,
    Unknown,
}

impl Default for RelationshipType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A relationship between two AD objects
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ADRelationship {
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: RelationshipType,
    pub is_acl: bool,
    pub is_inherited: bool,
    pub properties: HashMap<String, serde_json::Value>,
}

/// An attack path from source to target
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackPath {
    pub id: String,
    pub start_node: PathNode,
    pub end_node: PathNode,
    pub path: Vec<PathStep>,
    pub length: usize,
    pub risk_score: u8,
    pub techniques: Vec<String>,
    pub description: String,
}

/// A node in an attack path
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathNode {
    pub object_id: String,
    pub name: String,
    pub object_type: ADObjectType,
    pub domain: String,
    pub is_high_value: bool,
}

/// A step in an attack path
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathStep {
    pub from_node: PathNode,
    pub to_node: PathNode,
    pub relationship: RelationshipType,
    pub abuse_info: String,
    pub opsec_considerations: Option<String>,
}

/// High-value target (Domain Admin, Enterprise Admin, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HighValueTarget {
    pub object_id: String,
    pub name: String,
    pub object_type: ADObjectType,
    pub domain: String,
    pub reason: String,
    pub paths_to_target: usize,
}

/// A Kerberoastable user
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KerberoastableUser {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub service_principal_names: Vec<String>,
    pub is_admin: bool,
    pub password_last_set: Option<String>,
    pub description: Option<String>,
}

/// An AS-REP roastable user
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsrepRoastableUser {
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub is_enabled: bool,
    pub is_admin: bool,
    pub description: Option<String>,
}

/// Object with unconstrained delegation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnconstrainedDelegation {
    pub object_id: String,
    pub name: String,
    pub object_type: ADObjectType,
    pub domain: String,
    pub is_dc: bool,
    pub description: Option<String>,
}

/// Query types for BloodHound analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BloodHoundQuery {
    /// Find shortest path to Domain Admins from a user
    ShortestPathToDomainAdmin { from_user: String },
    /// Find all Kerberoastable users
    KerberoastableUsers,
    /// Find all AS-REP roastable users
    AsrepRoastableUsers,
    /// Find objects with unconstrained delegation
    UnconstrainedDelegation,
    /// Find objects with constrained delegation
    ConstrainedDelegation,
    /// Find users that can DCSync
    DCSync,
    /// Find local admin rights for a user
    LocalAdminRights { user: String },
    /// Find sessions on domain controllers
    SessionsOnDC,
    /// Find GPO abuse paths
    GPOAbuse,
    /// Find paths from owned users to high-value targets
    PathsFromOwned { owned_principals: Vec<String> },
    /// Find all paths to a specific target
    PathsToTarget { target: String },
    /// Find users with path to Domain Admin
    UsersWithPathToDA,
    /// Find computers where Domain Admins have sessions
    DASessionComputers,
    /// Custom query
    Custom { description: String },
}

/// Result of a BloodHound query
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueryResult {
    pub query_type: String,
    pub description: String,
    pub count: usize,
    pub paths: Vec<AttackPath>,
    pub objects: Vec<ADObject>,
    pub execution_time_ms: u64,
}

/// SharpHound collection data (imported from JSON/ZIP)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharpHoundData {
    pub meta: SharpHoundMeta,
    pub computers: Vec<SharpHoundComputer>,
    pub users: Vec<SharpHoundUser>,
    pub groups: Vec<SharpHoundGroup>,
    pub domains: Vec<SharpHoundDomain>,
    pub gpos: Vec<SharpHoundGpo>,
    pub ous: Vec<SharpHoundOu>,
    pub containers: Vec<SharpHoundContainer>,
}

/// SharpHound metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharpHoundMeta {
    pub methods: i64,
    pub r#type: String,
    pub count: i64,
    pub version: i64,
}

/// SharpHound Computer JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundComputer {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundComputerProperties,
    #[serde(default)]
    pub local_admins: SharpHoundResults,
    #[serde(default)]
    pub remote_desktop_users: SharpHoundResults,
    #[serde(default)]
    pub dcom_users: SharpHoundResults,
    #[serde(default)]
    pub ps_remote_users: SharpHoundResults,
    #[serde(default)]
    pub sessions: SharpHoundResults,
    #[serde(default)]
    pub allowed_to_delegate: Vec<SharpHoundAce>,
    #[serde(default)]
    pub allowed_to_act: Vec<SharpHoundAce>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundComputerProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub samaccountname: Option<String>,
    pub operatingsystem: Option<String>,
    pub enabled: Option<bool>,
    pub isdc: Option<bool>,
    pub unconstraineddelegation: Option<bool>,
    pub haslaps: Option<bool>,
    pub lastlogontimestamp: Option<i64>,
    pub pwdlastset: Option<i64>,
    #[serde(default)]
    pub serviceprincipalnames: Vec<String>,
}

/// SharpHound User JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundUser {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundUserProperties,
    #[serde(default)]
    pub primary_group_sid: Option<String>,
    #[serde(default)]
    pub allowed_to_delegate: Vec<SharpHoundAce>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
    #[serde(default)]
    pub sp_ntargets: Vec<SharpHoundSpnTarget>,
    #[serde(default)]
    pub has_sid_history: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundUserProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub samaccountname: Option<String>,
    pub displayname: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub admincount: Option<bool>,
    pub dontreqpreauth: Option<bool>,
    pub passwordnotreqd: Option<bool>,
    pub unconstraineddelegation: Option<bool>,
    pub sensitive: Option<bool>,
    pub hasspn: Option<bool>,
    pub lastlogon: Option<i64>,
    pub lastlogontimestamp: Option<i64>,
    pub pwdlastset: Option<i64>,
    pub pwdneverexpires: Option<bool>,
    #[serde(default)]
    pub serviceprincipalnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundSpnTarget {
    pub computer_sid: String,
    pub port: i32,
    pub service: String,
}

/// SharpHound Group JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundGroup {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundGroupProperties,
    #[serde(default)]
    pub members: Vec<SharpHoundMember>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundGroupProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub samaccountname: Option<String>,
    pub description: Option<String>,
    pub admincount: Option<bool>,
    pub highvalue: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundMember {
    pub object_identifier: String,
    pub object_type: String,
}

/// SharpHound Domain JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundDomain {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundDomainProperties,
    #[serde(default)]
    pub child_objects: Vec<SharpHoundMember>,
    #[serde(default)]
    pub trusts: Vec<SharpHoundTrust>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
    #[serde(default)]
    pub links: Vec<SharpHoundGpLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundDomainProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub functionallevel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundTrust {
    pub target_domain_sid: String,
    pub target_domain_name: String,
    pub is_transitive: bool,
    pub trust_direction: i32,
    pub trust_type: i32,
    pub sid_filtering_enabled: bool,
}

/// SharpHound GPO JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundGpo {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundGpoProperties,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundGpoProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub gpcpath: Option<String>,
}

/// SharpHound OU JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundOu {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundOuProperties,
    #[serde(default)]
    pub child_objects: Vec<SharpHoundMember>,
    #[serde(default)]
    pub links: Vec<SharpHoundGpLink>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundOuProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub blockinheritance: Option<bool>,
}

/// SharpHound Container JSON structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundContainer {
    pub object_identifier: String,
    #[serde(default)]
    pub properties: SharpHoundContainerProperties,
    #[serde(default)]
    pub child_objects: Vec<SharpHoundMember>,
    #[serde(default)]
    pub aces: Vec<SharpHoundAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct SharpHoundContainerProperties {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
}

/// SharpHound ACE (Access Control Entry)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundAce {
    pub principal_sid: String,
    pub principal_type: String,
    pub right_name: String,
    #[serde(default)]
    pub is_inherited: bool,
}

/// SharpHound GP Link
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundGpLink {
    pub guid: String,
    pub is_enforced: bool,
}

/// SharpHound Results container
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SharpHoundResults {
    #[serde(default)]
    pub results: Vec<SharpHoundAce>,
    pub collected: bool,
    #[serde(default)]
    pub failure_reason: Option<String>,
}
