//! Spanish ENS (Esquema Nacional de Seguridad) Compliance Controls
//!
//! This module implements controls based on Spain's National Security Framework
//! (Real Decreto 311/2022), which establishes security requirements for
//! public sector information systems.
//!
//! Key areas covered:
//! - Organizational Framework (Marco Organizativo)
//! - Operational Framework (Marco Operacional)
//! - Protection Measures (Medidas de Proteccion)
//!
//! Security Levels:
//! - BASICO (Basic)
//! - MEDIO (Medium)
//! - ALTO (High)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of ENS controls
pub const CONTROL_COUNT: usize = 50;

/// Get all ENS controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Marco Organizativo (Organizational Framework)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-ORG-001".to_string(),
        control_id: "org.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Politica de seguridad (Security Policy)".to_string(),
        description: "Se dispondra de una politica de seguridad que articule la gestion continuada de la seguridad".to_string(),
        category: "Marco Organizativo".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop and approve a comprehensive security policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ORG-002".to_string(),
        control_id: "org.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Normativa de seguridad (Security Standards)".to_string(),
        description: "Se dispondra de normativa de seguridad que concrete la politica".to_string(),
        category: "Marco Organizativo".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop security standards implementing the security policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ORG-003".to_string(),
        control_id: "org.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Procedimientos de seguridad (Security Procedures)".to_string(),
        description: "Se dispondran de procedimientos operativos que detallen las tareas".to_string(),
        category: "Marco Organizativo".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.37".to_string()],
        remediation_guidance: Some("Document detailed security procedures for all operations".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ORG-004".to_string(),
        control_id: "org.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proceso de autorizacion (Authorization Process)".to_string(),
        description: "Se establecera un proceso formal de autorizaciones".to_string(),
        category: "Marco Organizativo".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CA-6".to_string()],
        remediation_guidance: Some("Establish formal authorization process for systems and changes".to_string()),
    });

    // ========================================================================
    // Marco Operacional (Operational Framework)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-OPR-001".to_string(),
        control_id: "op.pl.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Analisis de riesgos (Risk Analysis)".to_string(),
        description: "Se realizara un analisis de riesgos que determine las amenazas y vulnerabilidades".to_string(),
        category: "Planificacion".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.12".to_string(), "NIST-RA-3".to_string()],
        remediation_guidance: Some("Conduct comprehensive risk analysis identifying threats and vulnerabilities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-OPR-002".to_string(),
        control_id: "op.pl.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Arquitectura de seguridad (Security Architecture)".to_string(),
        description: "El sistema se protegera mediante una arquitectura de seguridad documentada".to_string(),
        category: "Planificacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PL-8".to_string()],
        remediation_guidance: Some("Document and implement security architecture".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-OPR-003".to_string(),
        control_id: "op.pl.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Adquisicion de nuevos componentes (Component Acquisition)".to_string(),
        description: "Se estableceran requisitos de seguridad para la adquisicion de componentes".to_string(),
        category: "Planificacion".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-4".to_string()],
        remediation_guidance: Some("Define security requirements for component acquisition".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-OPR-004".to_string(),
        control_id: "op.pl.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Dimensionamiento / Gestion de capacidades (Capacity Management)".to_string(),
        description: "Se realizara un estudio de capacidades para asegurar disponibilidad".to_string(),
        category: "Planificacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.6".to_string()],
        remediation_guidance: Some("Implement capacity planning and monitoring".to_string()),
    });

    // ========================================================================
    // Control de Acceso (Access Control)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-ACC-001".to_string(),
        control_id: "op.acc.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Identificacion (Identification)".to_string(),
        description: "Todo usuario estara identificado de forma unica".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-4".to_string()],
        remediation_guidance: Some("Implement unique user identification for all accounts".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-002".to_string(),
        control_id: "op.acc.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Requisitos de acceso (Access Requirements)".to_string(),
        description: "Los requisitos de acceso se estableceran segun las necesidades".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string()],
        remediation_guidance: Some("Define access requirements based on job functions".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-003".to_string(),
        control_id: "op.acc.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Segregacion de funciones (Segregation of Duties)".to_string(),
        description: "Se segregaran las funciones para evitar conflictos de interes".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-5".to_string()],
        remediation_guidance: Some("Implement segregation of duties controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-004".to_string(),
        control_id: "op.acc.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proceso de gestion de derechos de acceso (Access Rights Management)".to_string(),
        description: "Los derechos de acceso de cada usuario se limitaran a lo estrictamente necesario".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string()],
        remediation_guidance: Some("Implement least privilege access control".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-005".to_string(),
        control_id: "op.acc.5".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Mecanismo de autenticacion (Authentication Mechanism)".to_string(),
        description: "Se utilizaran mecanismos de autenticacion acordes al nivel de seguridad".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2".to_string()],
        remediation_guidance: Some("Implement strong authentication mechanisms including MFA".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-006".to_string(),
        control_id: "op.acc.6".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Acceso local (Local Access)".to_string(),
        description: "Se controlara el acceso local a los sistemas".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string()],
        remediation_guidance: Some("Control physical and logical local access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-ACC-007".to_string(),
        control_id: "op.acc.7".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Acceso remoto (Remote Access)".to_string(),
        description: "Se controlara el acceso remoto garantizando autenticacion y cifrado".to_string(),
        category: "Control de Acceso".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-17".to_string()],
        remediation_guidance: Some("Secure remote access with MFA and encryption".to_string()),
    });

    // ========================================================================
    // Explotacion (Operations)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-EXP-001".to_string(),
        control_id: "op.exp.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Inventario de activos (Asset Inventory)".to_string(),
        description: "Se mantendra un inventario actualizado de todos los activos".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-8".to_string()],
        remediation_guidance: Some("Maintain comprehensive and current asset inventory".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-002".to_string(),
        control_id: "op.exp.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Configuracion de seguridad (Security Configuration)".to_string(),
        description: "Se establecera una configuracion de seguridad para cada componente".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-6".to_string()],
        remediation_guidance: Some("Define and apply security baselines for all components".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-003".to_string(),
        control_id: "op.exp.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Gestion de la configuracion (Configuration Management)".to_string(),
        description: "Se gestionara la configuracion de forma controlada".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-3".to_string()],
        remediation_guidance: Some("Implement configuration management process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-004".to_string(),
        control_id: "op.exp.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Mantenimiento (Maintenance)".to_string(),
        description: "Se realizara el mantenimiento de los sistemas de forma segura".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-MA-2".to_string()],
        remediation_guidance: Some("Implement secure maintenance procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-005".to_string(),
        control_id: "op.exp.5".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Gestion de cambios (Change Management)".to_string(),
        description: "Se gestionaran los cambios de forma controlada".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CM-3".to_string()],
        remediation_guidance: Some("Implement formal change management process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-006".to_string(),
        control_id: "op.exp.6".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion frente a codigo danino (Malware Protection)".to_string(),
        description: "Se protegeran los sistemas frente a codigo danino".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string()],
        remediation_guidance: Some("Deploy and maintain anti-malware protection".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-007".to_string(),
        control_id: "op.exp.7".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Gestion de incidentes (Incident Management)".to_string(),
        description: "Se gestionaran los incidentes de seguridad de forma estructurada".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-4".to_string()],
        remediation_guidance: Some("Implement incident management process and team".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-008".to_string(),
        control_id: "op.exp.8".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Registro de la actividad (Activity Logging)".to_string(),
        description: "Se registrara la actividad de los usuarios y administradores".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-2".to_string()],
        remediation_guidance: Some("Implement comprehensive activity logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-009".to_string(),
        control_id: "op.exp.9".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Registro de la gestion de incidentes (Incident Logging)".to_string(),
        description: "Se registraran los incidentes de seguridad".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-5".to_string()],
        remediation_guidance: Some("Maintain incident register with detailed records".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXP-010".to_string(),
        control_id: "op.exp.10".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion de los registros (Log Protection)".to_string(),
        description: "Se protegeran los registros de actividad frente a manipulacion".to_string(),
        category: "Explotacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Protect logs from unauthorized modification".to_string()),
    });

    // ========================================================================
    // Servicios Externos (External Services)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-EXT-001".to_string(),
        control_id: "op.ext.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Contratacion y acuerdos de nivel de servicio (SLAs)".to_string(),
        description: "Se incluiran requisitos de seguridad en contratos con terceros".to_string(),
        category: "Servicios Externos".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-9".to_string()],
        remediation_guidance: Some("Include security requirements in third-party contracts".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-EXT-002".to_string(),
        control_id: "op.ext.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Gestion diaria de servicios externos (External Service Management)".to_string(),
        description: "Se supervisara el cumplimiento de los acuerdos con terceros".to_string(),
        category: "Servicios Externos".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-9".to_string()],
        remediation_guidance: Some("Monitor and audit third-party compliance".to_string()),
    });

    // ========================================================================
    // Continuidad del Servicio (Service Continuity)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-CON-001".to_string(),
        control_id: "op.cont.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Analisis de impacto (Impact Analysis)".to_string(),
        description: "Se realizara un analisis de impacto en el negocio".to_string(),
        category: "Continuidad".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string()],
        remediation_guidance: Some("Conduct business impact analysis".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-CON-002".to_string(),
        control_id: "op.cont.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Plan de continuidad (Continuity Plan)".to_string(),
        description: "Se dispondra de un plan de continuidad".to_string(),
        category: "Continuidad".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string()],
        remediation_guidance: Some("Develop and maintain business continuity plan".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-CON-003".to_string(),
        control_id: "op.cont.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Pruebas periodicas (Periodic Testing)".to_string(),
        description: "Se realizaran pruebas periodicas del plan de continuidad".to_string(),
        category: "Continuidad".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-4".to_string()],
        remediation_guidance: Some("Test continuity plan periodically".to_string()),
    });

    // ========================================================================
    // Monitorizacion (Monitoring)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-MON-001".to_string(),
        control_id: "op.mon.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Deteccion de intrusos (Intrusion Detection)".to_string(),
        description: "Se implementaran sistemas de deteccion de intrusos".to_string(),
        category: "Monitorizacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4".to_string()],
        remediation_guidance: Some("Deploy and maintain IDS/IPS systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-MON-002".to_string(),
        control_id: "op.mon.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Sistema de metricas (Metrics System)".to_string(),
        description: "Se establecera un sistema de metricas de seguridad".to_string(),
        category: "Monitorizacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PM-6".to_string()],
        remediation_guidance: Some("Implement security metrics and dashboards".to_string()),
    });

    // ========================================================================
    // Medidas de Proteccion - Proteccion de las Comunicaciones
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-COM-001".to_string(),
        control_id: "mp.com.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Perimetro seguro (Secure Perimeter)".to_string(),
        description: "Se dispondra de un perimetro de red seguro".to_string(),
        category: "Comunicaciones".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string()],
        remediation_guidance: Some("Implement secure network perimeter with firewalls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-COM-002".to_string(),
        control_id: "mp.com.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion de la confidencialidad (Confidentiality Protection)".to_string(),
        description: "Se protegera la confidencialidad de la informacion en transito".to_string(),
        category: "Comunicaciones".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Encrypt all data in transit using approved protocols".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-COM-003".to_string(),
        control_id: "mp.com.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion de la integridad y autenticidad (Integrity Protection)".to_string(),
        description: "Se protegera la integridad y autenticidad de las comunicaciones".to_string(),
        category: "Comunicaciones".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Implement message authentication and integrity checks".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-COM-004".to_string(),
        control_id: "mp.com.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Separacion de redes (Network Separation)".to_string(),
        description: "Se mantendra la separacion entre redes de diferente nivel de seguridad".to_string(),
        category: "Comunicaciones".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7(5)".to_string()],
        remediation_guidance: Some("Implement network segmentation by security level".to_string()),
    });

    // ========================================================================
    // Medidas de Proteccion - Proteccion de la Informacion
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-INF-001".to_string(),
        control_id: "mp.info.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Datos de caracter personal (Personal Data)".to_string(),
        description: "Se protegeran los datos de caracter personal segun RGPD".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.32".to_string()],
        remediation_guidance: Some("Implement GDPR-compliant personal data protection".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-002".to_string(),
        control_id: "mp.info.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Clasificacion de la informacion (Information Classification)".to_string(),
        description: "La informacion se clasificara segun su nivel de seguridad".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.12".to_string()],
        remediation_guidance: Some("Implement information classification scheme".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-003".to_string(),
        control_id: "mp.info.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Cifrado (Encryption)".to_string(),
        description: "Se cifrara la informacion segun su nivel de clasificacion".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string()],
        remediation_guidance: Some("Encrypt information based on classification level".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-004".to_string(),
        control_id: "mp.info.4".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Firma electronica (Electronic Signature)".to_string(),
        description: "Se utilizara firma electronica para garantizar autenticidad".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["eIDAS".to_string()],
        remediation_guidance: Some("Implement electronic signatures for authenticity".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-005".to_string(),
        control_id: "mp.info.5".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Sellos de tiempo (Timestamps)".to_string(),
        description: "Se utilizaran sellos de tiempo para garantizar no repudio".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["eIDAS".to_string()],
        remediation_guidance: Some("Implement trusted timestamps for non-repudiation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-006".to_string(),
        control_id: "mp.info.6".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Limpieza de documentos (Document Sanitization)".to_string(),
        description: "Se eliminaran metadatos y datos ocultos antes de publicar".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-15".to_string()],
        remediation_guidance: Some("Sanitize documents before publication".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-INF-007".to_string(),
        control_id: "mp.info.7".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Copias de seguridad (Backups)".to_string(),
        description: "Se realizaran copias de seguridad de la informacion".to_string(),
        category: "Informacion".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Implement regular tested backups".to_string()),
    });

    // ========================================================================
    // Medidas de Proteccion - Proteccion de los Servicios
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ENS-SRV-001".to_string(),
        control_id: "mp.s.1".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion del correo electronico (Email Protection)".to_string(),
        description: "Se protegera el servicio de correo electronico".to_string(),
        category: "Servicios".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string()],
        remediation_guidance: Some("Implement email security controls including SPF, DKIM, DMARC".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-SRV-002".to_string(),
        control_id: "mp.s.2".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion de servicios y aplicaciones web (Web Protection)".to_string(),
        description: "Se protegeran los servicios web frente a ataques".to_string(),
        category: "Servicios".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["OWASP".to_string()],
        remediation_guidance: Some("Implement WAF and secure coding practices".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ENS-SRV-003".to_string(),
        control_id: "mp.s.3".to_string(),
        framework: ComplianceFramework::EnsSpain,
        title: "Proteccion frente a denegacion de servicio (DoS Protection)".to_string(),
        description: "Se protegeran los servicios frente a ataques de denegacion".to_string(),
        category: "Servicios".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-5".to_string()],
        remediation_guidance: Some("Implement DDoS protection measures".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant ENS controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication
    if title_lower.contains("authentication") || title_lower.contains("password") || title_lower.contains("mfa") {
        mappings.push(("op.acc.5".to_string(), Severity::Critical));
        mappings.push(("op.acc.1".to_string(), Severity::High));
    }

    // Access control
    if title_lower.contains("access") || title_lower.contains("privilege") || title_lower.contains("authorization") {
        mappings.push(("op.acc.4".to_string(), Severity::High));
        mappings.push(("op.acc.3".to_string(), Severity::High));
    }

    // Remote access
    if title_lower.contains("remote") || title_lower.contains("vpn") || title_lower.contains("rdp") {
        mappings.push(("op.acc.7".to_string(), Severity::Critical));
    }

    // Encryption
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("cipher") {
        mappings.push(("mp.com.2".to_string(), Severity::Critical));
        mappings.push(("mp.info.3".to_string(), Severity::Critical));
    }

    // Network security
    if title_lower.contains("network") || title_lower.contains("firewall") || title_lower.contains("segment") {
        mappings.push(("mp.com.1".to_string(), Severity::Critical));
        mappings.push(("mp.com.4".to_string(), Severity::High));
    }

    // Malware
    if title_lower.contains("malware") || title_lower.contains("virus") || title_lower.contains("ransomware") {
        mappings.push(("op.exp.6".to_string(), Severity::Critical));
    }

    // Logging / Monitoring
    if title_lower.contains("log") || title_lower.contains("audit") || title_lower.contains("monitor") {
        mappings.push(("op.exp.8".to_string(), Severity::High));
        mappings.push(("op.exp.10".to_string(), Severity::High));
    }

    // Intrusion detection
    if title_lower.contains("intrusion") || title_lower.contains("ids") || title_lower.contains("ips") {
        mappings.push(("op.mon.1".to_string(), Severity::High));
    }

    // Web application
    if title_lower.contains("xss") || title_lower.contains("injection") || title_lower.contains("web") {
        mappings.push(("mp.s.2".to_string(), Severity::Critical));
    }

    // DoS / DDoS
    if title_lower.contains("dos") || title_lower.contains("ddos") || title_lower.contains("denial") {
        mappings.push(("mp.s.3".to_string(), Severity::High));
    }

    // Email
    if title_lower.contains("email") || title_lower.contains("phishing") || title_lower.contains("spf")
        || title_lower.contains("dkim") {
        mappings.push(("mp.s.1".to_string(), Severity::High));
    }

    // Backup
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("mp.info.7".to_string(), Severity::High));
    }

    // Personal data / GDPR
    if title_lower.contains("personal data") || title_lower.contains("gdpr") || title_lower.contains("privacy") {
        mappings.push(("mp.info.1".to_string(), Severity::Critical));
    }

    // Configuration
    if title_lower.contains("config") || title_lower.contains("misconfigur") {
        mappings.push(("op.exp.2".to_string(), Severity::High));
        mappings.push(("op.exp.3".to_string(), Severity::High));
    }

    // Default mapping
    if mappings.is_empty() {
        mappings.push(("op.pl.1".to_string(), Severity::Medium));
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
            assert_eq!(control.framework, ComplianceFramework::EnsSpain);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("SQL Injection vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "mp.s.2"));

        let auth_mappings = map_vulnerability("Weak authentication mechanism", None, None, None);
        assert!(auth_mappings.iter().any(|(id, _)| id == "op.acc.5"));
    }
}
