//! French SecNumCloud (ANSSI Cloud Security Qualification) Controls
//!
//! This module implements controls based on ANSSI's SecNumCloud qualification
//! framework (v3.2), which is the French government's security certification
//! for cloud service providers.
//!
//! Key domains covered:
//! - Gouvernance (Governance)
//! - Protection des donnees (Data Protection)
//! - Securite des ressources humaines (Personnel Security)
//! - Gestion des actifs (Asset Management)
//! - Controle d'acces (Access Control)
//! - Cryptographie (Cryptography)
//! - Securite physique (Physical Security)
//! - Securite des operations (Operations Security)
//! - Securite des communications (Communications Security)
//! - Acquisition et developpement (Development Security)
//! - Relations fournisseurs (Supplier Relations)
//! - Gestion des incidents (Incident Management)
//! - Continuite d'activite (Business Continuity)
//! - Conformite (Compliance)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of SecNumCloud controls
pub const CONTROL_COUNT: usize = 49;

/// Get all SecNumCloud controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Gouvernance (Governance)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-GOV-01".to_string(),
        control_id: "GOV.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Politique de securite (Security Policy)".to_string(),
        description: "Une politique de securite de l'information est definie, approuvee par la direction et communiquee".to_string(),
        category: "Gouvernance".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop and approve comprehensive information security policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-GOV-02".to_string(),
        control_id: "GOV.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Organisation de la securite (Security Organization)".to_string(),
        description: "L'organisation de la securite de l'information est definie avec des roles et responsabilites clairs".to_string(),
        category: "Gouvernance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.2".to_string()],
        remediation_guidance: Some("Define security organization with clear RACI".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-GOV-03".to_string(),
        control_id: "GOV.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Analyse des risques (Risk Analysis)".to_string(),
        description: "Une analyse des risques est realisee et maintenue a jour".to_string(),
        category: "Gouvernance".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-6.1".to_string(), "EBIOS-RM".to_string()],
        remediation_guidance: Some("Conduct risk analysis using EBIOS RM or equivalent methodology".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-GOV-04".to_string(),
        control_id: "GOV.4".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Revue de securite (Security Review)".to_string(),
        description: "Des revues periodiques de securite sont conduites".to_string(),
        category: "Gouvernance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-9.3".to_string()],
        remediation_guidance: Some("Conduct annual management reviews of security".to_string()),
    });

    // ========================================================================
    // Protection des donnees (Data Protection)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-DAT-01".to_string(),
        control_id: "DAT.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Localisation des donnees (Data Location)".to_string(),
        description: "Les donnees sont hebergees dans des centres situes dans l'Union Europeenne".to_string(),
        category: "Protection des donnees".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.44".to_string()],
        remediation_guidance: Some("Ensure all data centers are located within the EU".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DAT-02".to_string(),
        control_id: "DAT.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Protection juridique (Legal Protection)".to_string(),
        description: "Les donnees sont protegees contre l'acces par des lois extra-europeennes".to_string(),
        category: "Protection des donnees".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.48".to_string()],
        remediation_guidance: Some("Implement legal protections against extraterritorial access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DAT-03".to_string(),
        control_id: "DAT.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Classification des donnees (Data Classification)".to_string(),
        description: "Les informations sont classifiees selon leur sensibilite".to_string(),
        category: "Protection des donnees".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.12".to_string()],
        remediation_guidance: Some("Implement data classification scheme".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DAT-04".to_string(),
        control_id: "DAT.4".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Separation des donnees (Data Separation)".to_string(),
        description: "Les donnees des differents clients sont logiquement separees".to_string(),
        category: "Protection des donnees".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["CSA-CCM-DSI-04".to_string()],
        remediation_guidance: Some("Implement multi-tenancy isolation controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DAT-05".to_string(),
        control_id: "DAT.5".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Effacement des donnees (Data Deletion)".to_string(),
        description: "Les donnees sont effacees de maniere securisee en fin de contrat".to_string(),
        category: "Protection des donnees".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.17".to_string()],
        remediation_guidance: Some("Implement secure data deletion procedures".to_string()),
    });

    // ========================================================================
    // Securite des ressources humaines (Personnel Security)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-RH-01".to_string(),
        control_id: "RH.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Verification des antecedents (Background Checks)".to_string(),
        description: "Des verifications d'antecedents sont effectuees pour le personnel".to_string(),
        category: "Ressources humaines".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.1".to_string()],
        remediation_guidance: Some("Conduct background checks for all personnel".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-RH-02".to_string(),
        control_id: "RH.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Sensibilisation (Security Awareness)".to_string(),
        description: "Le personnel recoit une formation de sensibilisation a la securite".to_string(),
        category: "Ressources humaines".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-2".to_string()],
        remediation_guidance: Some("Implement security awareness training program".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-RH-03".to_string(),
        control_id: "RH.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Formation specialisee (Specialized Training)".to_string(),
        description: "Le personnel technique recoit une formation specialisee en securite".to_string(),
        category: "Ressources humaines".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-3".to_string()],
        remediation_guidance: Some("Provide role-based security training".to_string()),
    });

    // ========================================================================
    // Controle d'acces (Access Control)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-ACC-01".to_string(),
        control_id: "ACC.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Politique de controle d'acces (Access Control Policy)".to_string(),
        description: "Une politique de controle d'acces basee sur le principe du moindre privilege est appliquee".to_string(),
        category: "Controle d'acces".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string()],
        remediation_guidance: Some("Implement least privilege access control".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-ACC-02".to_string(),
        control_id: "ACC.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Authentification forte (Strong Authentication)".to_string(),
        description: "L'authentification forte est requise pour les acces privilegies et distants".to_string(),
        category: "Controle d'acces".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ANSSI-PA-022".to_string(), "NIST-IA-2(1)".to_string()],
        remediation_guidance: Some("Implement MFA for all privileged and remote access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-ACC-03".to_string(),
        control_id: "ACC.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Gestion des identites (Identity Management)".to_string(),
        description: "Un systeme de gestion des identites et des acces est mis en oeuvre".to_string(),
        category: "Controle d'acces".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string()],
        remediation_guidance: Some("Implement centralized identity management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-ACC-04".to_string(),
        control_id: "ACC.4".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Revue des droits d'acces (Access Rights Review)".to_string(),
        description: "Les droits d'acces sont revus regulierement".to_string(),
        category: "Controle d'acces".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2(3)".to_string()],
        remediation_guidance: Some("Conduct quarterly access rights reviews".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-ACC-05".to_string(),
        control_id: "ACC.5".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Gestion des comptes privilegies (Privileged Account Management)".to_string(),
        description: "Les comptes privilegies sont geres avec des controles renforces".to_string(),
        category: "Controle d'acces".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ANSSI-PA-022".to_string()],
        remediation_guidance: Some("Implement PAM solution with session recording".to_string()),
    });

    // ========================================================================
    // Cryptographie (Cryptography)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-CRY-01".to_string(),
        control_id: "CRY.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Algorithmes approuves (Approved Algorithms)".to_string(),
        description: "Seuls des algorithmes cryptographiques conformes au RGS sont utilises".to_string(),
        category: "Cryptographie".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["RGS-B1".to_string(), "ANSSI-Crypto".to_string()],
        remediation_guidance: Some("Use only RGS-compliant cryptographic algorithms".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-CRY-02".to_string(),
        control_id: "CRY.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Chiffrement au repos (Encryption at Rest)".to_string(),
        description: "Les donnees client sont chiffrees au repos avec AES-256 ou equivalent".to_string(),
        category: "Cryptographie".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string()],
        remediation_guidance: Some("Encrypt all customer data at rest with AES-256".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-CRY-03".to_string(),
        control_id: "CRY.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Chiffrement en transit (Encryption in Transit)".to_string(),
        description: "Les communications sont chiffrees avec TLS 1.2 minimum".to_string(),
        category: "Cryptographie".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Enforce TLS 1.2 or higher for all communications".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-CRY-04".to_string(),
        control_id: "CRY.4".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Gestion des cles (Key Management)".to_string(),
        description: "Les cles cryptographiques sont gerees de maniere securisee".to_string(),
        category: "Cryptographie".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string()],
        remediation_guidance: Some("Implement HSM-based key management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-CRY-05".to_string(),
        control_id: "CRY.5".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Cles client (Customer Keys)".to_string(),
        description: "Les clients peuvent utiliser leurs propres cles de chiffrement".to_string(),
        category: "Cryptographie".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["BYOK".to_string()],
        remediation_guidance: Some("Support customer-managed encryption keys (BYOK)".to_string()),
    });

    // ========================================================================
    // Securite physique (Physical Security)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-PHY-01".to_string(),
        control_id: "PHY.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Perimetres de securite (Security Perimeters)".to_string(),
        description: "Des perimetres de securite physique sont definis et proteges".to_string(),
        category: "Securite physique".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string()],
        remediation_guidance: Some("Define and protect physical security perimeters".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-PHY-02".to_string(),
        control_id: "PHY.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Controle d'acces physique (Physical Access Control)".to_string(),
        description: "L'acces physique aux zones sensibles est controle et enregistre".to_string(),
        category: "Securite physique".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string()],
        remediation_guidance: Some("Implement physical access controls with logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-PHY-03".to_string(),
        control_id: "PHY.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Protection environnementale (Environmental Protection)".to_string(),
        description: "Les equipements sont proteges contre les menaces environnementales".to_string(),
        category: "Securite physique".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PE-13".to_string()],
        remediation_guidance: Some("Implement environmental controls (fire, flood, power)".to_string()),
    });

    // ========================================================================
    // Securite des operations (Operations Security)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-OPS-01".to_string(),
        control_id: "OPS.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Procedures d'exploitation (Operating Procedures)".to_string(),
        description: "Des procedures d'exploitation securisees sont documentees et appliquees".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.37".to_string()],
        remediation_guidance: Some("Document and maintain operating procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-02".to_string(),
        control_id: "OPS.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Gestion des changements (Change Management)".to_string(),
        description: "Les changements sont geres selon un processus formel".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-3".to_string()],
        remediation_guidance: Some("Implement formal change management process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-03".to_string(),
        control_id: "OPS.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Protection contre les codes malveillants (Malware Protection)".to_string(),
        description: "Des protections contre les codes malveillants sont deployees".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string()],
        remediation_guidance: Some("Deploy comprehensive anti-malware protection".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-04".to_string(),
        control_id: "OPS.4".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Sauvegardes (Backups)".to_string(),
        description: "Des sauvegardes sont realisees et testees regulierement".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Implement and test regular backups".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-05".to_string(),
        control_id: "OPS.5".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Journalisation (Logging)".to_string(),
        description: "Les evenements de securite sont journalises et conserves".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-2".to_string()],
        remediation_guidance: Some("Implement comprehensive security logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-06".to_string(),
        control_id: "OPS.6".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Protection des journaux (Log Protection)".to_string(),
        description: "Les journaux sont proteges contre la modification et la suppression".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Protect logs from tampering".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-07".to_string(),
        control_id: "OPS.7".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Gestion des vulnerabilites (Vulnerability Management)".to_string(),
        description: "Les vulnerabilites sont identifiees et corrigees dans les delais".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string()],
        remediation_guidance: Some("Implement vulnerability scanning and patch management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-OPS-08".to_string(),
        control_id: "OPS.8".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Tests d'intrusion (Penetration Testing)".to_string(),
        description: "Des tests d'intrusion sont realises annuellement par un tiers".to_string(),
        category: "Securite des operations".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["PASSI".to_string()],
        remediation_guidance: Some("Conduct annual penetration tests by PASSI-qualified provider".to_string()),
    });

    // ========================================================================
    // Securite des communications (Communications Security)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-COM-01".to_string(),
        control_id: "COM.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Segmentation reseau (Network Segmentation)".to_string(),
        description: "Les reseaux sont segmentes selon les niveaux de securite".to_string(),
        category: "Securite des communications".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string()],
        remediation_guidance: Some("Implement network segmentation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-COM-02".to_string(),
        control_id: "COM.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Filtrage reseau (Network Filtering)".to_string(),
        description: "Des pare-feu et systemes de detection d'intrusion sont deployes".to_string(),
        category: "Securite des communications".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7(5)".to_string()],
        remediation_guidance: Some("Deploy firewalls and IDS/IPS".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-COM-03".to_string(),
        control_id: "COM.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Protection DDoS (DDoS Protection)".to_string(),
        description: "Des protections contre les attaques par deni de service sont en place".to_string(),
        category: "Securite des communications".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-5".to_string()],
        remediation_guidance: Some("Implement DDoS mitigation".to_string()),
    });

    // ========================================================================
    // Acquisition et developpement (Development Security)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-DEV-01".to_string(),
        control_id: "DEV.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Developpement securise (Secure Development)".to_string(),
        description: "Le developpement suit un cycle de vie securise".to_string(),
        category: "Developpement".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-15".to_string()],
        remediation_guidance: Some("Implement secure SDLC".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DEV-02".to_string(),
        control_id: "DEV.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Revue de code (Code Review)".to_string(),
        description: "Les revues de code securite sont effectuees".to_string(),
        category: "Developpement".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-11".to_string()],
        remediation_guidance: Some("Conduct security code reviews".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-DEV-03".to_string(),
        control_id: "DEV.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Separation des environnements (Environment Separation)".to_string(),
        description: "Les environnements de developpement, test et production sont separes".to_string(),
        category: "Developpement".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-4".to_string()],
        remediation_guidance: Some("Maintain separate environments".to_string()),
    });

    // ========================================================================
    // Relations fournisseurs (Supplier Relations)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-FOU-01".to_string(),
        control_id: "FOU.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Evaluation des fournisseurs (Supplier Assessment)".to_string(),
        description: "Les fournisseurs sont evalues sur leur niveau de securite".to_string(),
        category: "Fournisseurs".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-6".to_string()],
        remediation_guidance: Some("Conduct supplier security assessments".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-FOU-02".to_string(),
        control_id: "FOU.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Accords de securite (Security Agreements)".to_string(),
        description: "Des accords de securite sont etablis avec les fournisseurs".to_string(),
        category: "Fournisseurs".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-9".to_string()],
        remediation_guidance: Some("Establish security agreements with suppliers".to_string()),
    });

    // ========================================================================
    // Gestion des incidents (Incident Management)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-INC-01".to_string(),
        control_id: "INC.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Processus de gestion des incidents (Incident Management Process)".to_string(),
        description: "Un processus de gestion des incidents de securite est etabli".to_string(),
        category: "Gestion des incidents".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string()],
        remediation_guidance: Some("Establish incident response process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-INC-02".to_string(),
        control_id: "INC.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Notification des incidents (Incident Notification)".to_string(),
        description: "Les incidents sont signales aux clients et aux autorites dans les delais".to_string(),
        category: "Gestion des incidents".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.33".to_string(), "ANSSI-Notif".to_string()],
        remediation_guidance: Some("Notify clients and ANSSI within required timeframes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-INC-03".to_string(),
        control_id: "INC.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Analyse forensique (Forensic Analysis)".to_string(),
        description: "Des capacites d'analyse forensique sont disponibles".to_string(),
        category: "Gestion des incidents".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-4".to_string()],
        remediation_guidance: Some("Establish forensic analysis capabilities".to_string()),
    });

    // ========================================================================
    // Continuite d'activite (Business Continuity)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-BCM-01".to_string(),
        control_id: "BCM.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Plan de continuite (Continuity Plan)".to_string(),
        description: "Un plan de continuite d'activite est etabli et maintenu".to_string(),
        category: "Continuite d'activite".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string()],
        remediation_guidance: Some("Develop and maintain BCP".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-BCM-02".to_string(),
        control_id: "BCM.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Redondance (Redundancy)".to_string(),
        description: "Une redondance suffisante est mise en place pour la disponibilite".to_string(),
        category: "Continuite d'activite".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-7".to_string()],
        remediation_guidance: Some("Implement redundant systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-BCM-03".to_string(),
        control_id: "BCM.3".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Tests de continuite (Continuity Testing)".to_string(),
        description: "Le plan de continuite est teste regulierement".to_string(),
        category: "Continuite d'activite".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-4".to_string()],
        remediation_guidance: Some("Test BCP annually".to_string()),
    });

    // ========================================================================
    // Conformite (Compliance)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "SNC-CONF-01".to_string(),
        control_id: "CONF.1".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Conformite legale (Legal Compliance)".to_string(),
        description: "La conformite aux exigences legales et reglementaires est assuree".to_string(),
        category: "Conformite".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.31".to_string()],
        remediation_guidance: Some("Ensure legal and regulatory compliance".to_string()),
    });

    controls.push(ComplianceControl {
        id: "SNC-CONF-02".to_string(),
        control_id: "CONF.2".to_string(),
        framework: ComplianceFramework::SecNumCloud,
        title: "Audits externes (External Audits)".to_string(),
        description: "Des audits externes reguliers sont realises".to_string(),
        category: "Conformite".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-9.2".to_string()],
        remediation_guidance: Some("Conduct annual external audits".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant SecNumCloud controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication / MFA
    if title_lower.contains("authentication") || title_lower.contains("mfa") || title_lower.contains("password") {
        mappings.push(("ACC.2".to_string(), Severity::Critical));
        mappings.push(("ACC.3".to_string(), Severity::High));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") || title_lower.contains("root") {
        mappings.push(("ACC.5".to_string(), Severity::Critical));
        mappings.push(("ACC.1".to_string(), Severity::High));
    }

    // Encryption
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") || title_lower.contains("cipher") {
        mappings.push(("CRY.1".to_string(), Severity::Critical));
        mappings.push(("CRY.2".to_string(), Severity::Critical));
        mappings.push(("CRY.3".to_string(), Severity::Critical));
    }

    // Key management
    if title_lower.contains("key") || title_lower.contains("certificate") {
        mappings.push(("CRY.4".to_string(), Severity::Critical));
    }

    // Network security
    if title_lower.contains("network") || title_lower.contains("firewall") || title_lower.contains("segment") {
        mappings.push(("COM.1".to_string(), Severity::High));
        mappings.push(("COM.2".to_string(), Severity::High));
    }

    // DDoS
    if title_lower.contains("dos") || title_lower.contains("ddos") || title_lower.contains("denial") {
        mappings.push(("COM.3".to_string(), Severity::High));
    }

    // Vulnerability / Patching
    if title_lower.contains("vulnerability") || title_lower.contains("patch") || title_lower.contains("cve") {
        mappings.push(("OPS.7".to_string(), Severity::Critical));
    }

    // Malware
    if title_lower.contains("malware") || title_lower.contains("virus") || title_lower.contains("ransomware") {
        mappings.push(("OPS.3".to_string(), Severity::Critical));
    }

    // Logging
    if title_lower.contains("log") || title_lower.contains("audit") || title_lower.contains("monitor") {
        mappings.push(("OPS.5".to_string(), Severity::High));
        mappings.push(("OPS.6".to_string(), Severity::High));
    }

    // Backup
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("OPS.4".to_string(), Severity::High));
    }

    // Data protection / GDPR
    if title_lower.contains("personal data") || title_lower.contains("gdpr") || title_lower.contains("privacy") {
        mappings.push(("DAT.1".to_string(), Severity::Critical));
        mappings.push(("DAT.4".to_string(), Severity::High));
    }

    // Code / Development
    if title_lower.contains("code") || title_lower.contains("injection") || title_lower.contains("xss") {
        mappings.push(("DEV.2".to_string(), Severity::High));
    }

    // Configuration / Change
    if title_lower.contains("config") || title_lower.contains("change") {
        mappings.push(("OPS.2".to_string(), Severity::High));
    }

    // Default mapping
    if mappings.is_empty() {
        mappings.push(("GOV.3".to_string(), Severity::Medium));
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT);
    }

    #[test]
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::SecNumCloud);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Weak encryption configuration", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.starts_with("CRY")));

        let auth_mappings = map_vulnerability("Missing MFA for privileged access", None, None, None);
        assert!(auth_mappings.iter().any(|(id, _)| id == "ACC.2"));
    }
}
