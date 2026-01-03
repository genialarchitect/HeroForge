//! Extended Reality (XR) security assessment

use super::types::*;
use anyhow::Result;

/// Assess XR device and application security
pub async fn assess_xr_security(devices: &[XRDeviceConfig]) -> Result<Vec<XRFinding>> {
    let mut findings = Vec::new();

    for device in devices {
        // Assess device firmware security
        findings.extend(assess_device_firmware_security(device));

        // Assess privacy in spatial computing (room scanning, object recognition)
        findings.extend(assess_spatial_computing_privacy(device));

        // Assess biometric data protection (eye tracking, facial recognition)
        findings.extend(assess_biometric_data_protection(device));

        // Assess metaverse platform security
        findings.extend(assess_metaverse_platform_security(device));

        // Assess digital twin security
        findings.extend(assess_digital_twin_security(device));

        // Assess motion tracking privacy
        findings.extend(assess_motion_tracking_privacy(device));

        // Assess voice recognition privacy
        findings.extend(assess_voice_recognition_privacy(device));

        // Assess environment mapping data protection
        findings.extend(assess_environment_mapping_protection(device));

        // Assess application permission analysis
        findings.extend(assess_application_permissions(device));
    }

    Ok(findings)
}

/// Assess device firmware security
fn assess_device_firmware_security(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    // All XR devices need firmware security assessment
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::DeviceSecurity,
        severity: Severity::Medium,
        description: format!(
            "{:?} device ({:?} platform) requires firmware security verification",
            device.device_type, device.platform
        ),
        recommendation: "Verify firmware is up-to-date and has not been tampered with. Enable secure boot if available.".to_string(),
        privacy_impact: PrivacyImpact::Medium,
    });

    // Check platform-specific firmware concerns
    match device.platform {
        XRPlatform::MetaQuest => {
            findings.push(XRFinding {
                device_id: device.device_id.clone(),
                finding_type: XRRiskType::DeviceSecurity,
                severity: Severity::High,
                description: "Meta Quest devices have known issues with sideloading unsigned firmware".to_string(),
                recommendation: "Disable developer mode in production environments and monitor for unauthorized firmware modifications.".to_string(),
                privacy_impact: PrivacyImpact::High,
            });
        }
        XRPlatform::HoloLens => {
            findings.push(XRFinding {
                device_id: device.device_id.clone(),
                finding_type: XRRiskType::DeviceSecurity,
                severity: Severity::Medium,
                description: "HoloLens requires Windows Defender Device Guard for enterprise deployments".to_string(),
                recommendation: "Enable Device Guard and BitLocker encryption for enterprise HoloLens deployments.".to_string(),
                privacy_impact: PrivacyImpact::Medium,
            });
        }
        _ => {}
    }

    findings
}

/// Assess privacy implications of spatial computing features
fn assess_spatial_computing_privacy(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    // Room scanning and environment mapping are privacy-critical
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::PrivacyInSpatialComputing,
        severity: Severity::High,
        description: format!(
            "{:?} device performs continuous spatial scanning which can map private spaces",
            device.device_type
        ),
        recommendation: "Implement strict data minimization for spatial data. Encrypt spatial maps at rest and in transit. Provide clear user consent mechanisms.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // Object recognition privacy concerns
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::EnvironmentScanning,
        severity: Severity::High,
        description: "Object recognition can identify sensitive items (documents, screens, personal belongings)".to_string(),
        recommendation: "Limit object recognition to necessary categories. Avoid storing or transmitting recognized object data.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // AR vs VR specific concerns
    match device.device_type {
        XRDeviceType::AR | XRDeviceType::MR | XRDeviceType::Glasses => {
            findings.push(XRFinding {
                device_id: device.device_id.clone(),
                finding_type: XRRiskType::PrivacyInSpatialComputing,
                severity: Severity::Critical,
                description: "AR/MR devices continuously capture real-world environments including bystanders".to_string(),
                recommendation: "Implement visual indicators when cameras are active. Provide bystander privacy modes.".to_string(),
                privacy_impact: PrivacyImpact::Critical,
            });
        }
        _ => {}
    }

    findings
}

/// Assess biometric data protection
fn assess_biometric_data_protection(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    // Eye tracking privacy
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::EyeTrackingPrivacy,
        severity: Severity::Critical,
        description: "Eye tracking data can reveal medical conditions, cognitive state, interests, and intentions".to_string(),
        recommendation: "Process eye tracking data locally only. Never transmit raw gaze data. Use aggregated metrics if needed.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // Facial recognition concerns
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::BiometricDataLeakage,
        severity: Severity::Critical,
        description: "Facial tracking for avatars can leak biometric identifiers and emotional states".to_string(),
        recommendation: "Do not store facial recognition templates. Use anonymized avatar expressions where possible.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // IPD (Interpupillary Distance) as unique identifier
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::BiometricDataLeakage,
        severity: Severity::High,
        description: "IPD measurements can serve as a biometric identifier across sessions".to_string(),
        recommendation: "Do not log or transmit IPD measurements. Store only on-device for comfort settings.".to_string(),
        privacy_impact: PrivacyImpact::High,
    });

    findings
}

/// Assess metaverse platform security
fn assess_metaverse_platform_security(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    if !device.applications.is_empty() {
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::MetaverseSecurity,
            severity: Severity::High,
            description: format!(
                "Device has {} metaverse/social applications installed which may have avatar and social interaction risks",
                device.applications.len()
            ),
            recommendation: "Review privacy policies of metaverse platforms. Limit personal information in avatars. Be aware of social engineering risks in VR.".to_string(),
            privacy_impact: PrivacyImpact::High,
        });

        // Avatar impersonation risks
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::MetaverseSecurity,
            severity: Severity::Medium,
            description: "Metaverse platforms may allow avatar impersonation or harassment".to_string(),
            recommendation: "Enable personal boundary settings. Use platform reporting tools. Implement avatar verification for enterprise use.".to_string(),
            privacy_impact: PrivacyImpact::Medium,
        });

        // Virtual economy risks
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::MetaverseSecurity,
            severity: Severity::Medium,
            description: "Virtual assets and transactions in metaverse platforms may be vulnerable to theft or fraud".to_string(),
            recommendation: "Use multi-factor authentication for virtual asset transactions. Be wary of phishing in virtual environments.".to_string(),
            privacy_impact: PrivacyImpact::Low,
        });
    }

    findings
}

/// Assess digital twin security
fn assess_digital_twin_security(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    // Digital twin of physical spaces
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::DigitalTwinSecurity,
        severity: Severity::High,
        description: "XR devices can create detailed digital twins of physical spaces including security-sensitive areas".to_string(),
        recommendation: "Restrict XR device usage in sensitive areas. Implement geofencing. Audit digital twin access logs.".to_string(),
        privacy_impact: PrivacyImpact::High,
    });

    // Industrial/enterprise digital twin concerns
    if matches!(device.platform, XRPlatform::HoloLens) {
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::DigitalTwinSecurity,
            severity: Severity::Critical,
            description: "Enterprise HoloLens deployments may capture proprietary facility layouts and equipment".to_string(),
            recommendation: "Implement strict access controls on digital twin data. Use on-premise storage for sensitive facility data.".to_string(),
            privacy_impact: PrivacyImpact::Critical,
        });
    }

    findings
}

/// Assess motion tracking privacy
fn assess_motion_tracking_privacy(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::MotionTrackingPrivacy,
        severity: Severity::High,
        description: "Full body motion tracking creates unique movement signatures that can identify individuals".to_string(),
        recommendation: "Limit motion data retention. Anonymize motion data before transmission. Inform users about motion tracking.".to_string(),
        privacy_impact: PrivacyImpact::High,
    });

    // Hand tracking specifics
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::MotionTrackingPrivacy,
        severity: Severity::High,
        description: "Hand tracking can capture typing patterns, gestures, and potentially sign language".to_string(),
        recommendation: "Do not record hand tracking during keyboard input. Implement privacy zones where tracking is paused.".to_string(),
        privacy_impact: PrivacyImpact::High,
    });

    // Haptic device concerns
    if matches!(device.device_type, XRDeviceType::Haptic) {
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::MotionTrackingPrivacy,
            severity: Severity::Medium,
            description: "Haptic devices can track precise finger movements and force feedback patterns".to_string(),
            recommendation: "Limit haptic data storage. Process force feedback locally when possible.".to_string(),
            privacy_impact: PrivacyImpact::Medium,
        });
    }

    findings
}

/// Assess voice recognition privacy
fn assess_voice_recognition_privacy(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::VoiceRecognitionPrivacy,
        severity: Severity::High,
        description: "Voice commands and ambient audio capture can expose private conversations".to_string(),
        recommendation: "Use push-to-talk instead of always-on voice recognition. Process voice locally. Provide clear audio capture indicators.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // Voice biometrics
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::VoiceRecognitionPrivacy,
        severity: Severity::High,
        description: "Voice data can be used to create voice biometric profiles and deepfakes".to_string(),
        recommendation: "Do not retain voice recordings beyond immediate processing. Do not create voice profiles without explicit consent.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    findings
}

/// Assess environment mapping data protection
fn assess_environment_mapping_protection(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::EnvironmentScanning,
        severity: Severity::High,
        description: "Environment maps contain detailed 3D information about private and sensitive spaces".to_string(),
        recommendation: "Encrypt environment maps with user-controlled keys. Implement map expiration policies. Allow users to delete maps.".to_string(),
        privacy_impact: PrivacyImpact::Critical,
    });

    // Cloud sync concerns
    findings.push(XRFinding {
        device_id: device.device_id.clone(),
        finding_type: XRRiskType::EnvironmentScanning,
        severity: Severity::High,
        description: "Environment maps synced to cloud services expand the attack surface for spatial data".to_string(),
        recommendation: "Disable cloud sync for environment maps in sensitive deployments. Use end-to-end encryption if sync is required.".to_string(),
        privacy_impact: PrivacyImpact::High,
    });

    findings
}

/// Assess application permissions
fn assess_application_permissions(device: &XRDeviceConfig) -> Vec<XRFinding> {
    let mut findings = Vec::new();

    if !device.applications.is_empty() {
        findings.push(XRFinding {
            device_id: device.device_id.clone(),
            finding_type: XRRiskType::DeviceSecurity,
            severity: Severity::Medium,
            description: format!(
                "Review permissions for {} installed applications: {}",
                device.applications.len(),
                device.applications.join(", ")
            ),
            recommendation: "Audit application permissions regularly. Remove unused applications. Use enterprise app management.".to_string(),
            privacy_impact: PrivacyImpact::Medium,
        });

        // Application-specific permission concerns
        for app in &device.applications {
            let app_lower = app.to_lowercase();
            if app_lower.contains("social") || app_lower.contains("chat") || app_lower.contains("meet") {
                findings.push(XRFinding {
                    device_id: device.device_id.clone(),
                    finding_type: XRRiskType::MetaverseSecurity,
                    severity: Severity::Medium,
                    description: format!("Social application '{}' may share avatar and presence data", app),
                    recommendation: "Review privacy settings for social applications. Limit data sharing with third parties.".to_string(),
                    privacy_impact: PrivacyImpact::High,
                });
            }
        }
    }

    findings
}

/// Comprehensive XR security assessment result
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct XRSecurityAssessment {
    pub devices_assessed: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub findings_by_type: std::collections::HashMap<String, usize>,
    pub recommendations: Vec<String>,
}

/// Generate a comprehensive assessment summary
pub fn generate_assessment_summary(findings: &[XRFinding]) -> XRSecurityAssessment {
    let mut assessment = XRSecurityAssessment::default();
    assessment.total_findings = findings.len();

    let mut findings_by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for finding in findings {
        match finding.severity {
            Severity::Critical => assessment.critical_findings += 1,
            Severity::High => assessment.high_findings += 1,
            Severity::Medium => assessment.medium_findings += 1,
            Severity::Low | Severity::Info => assessment.low_findings += 1,
        }

        let type_name = format!("{:?}", finding.finding_type);
        *findings_by_type.entry(type_name).or_insert(0) += 1;
    }

    assessment.findings_by_type = findings_by_type;

    // Generate prioritized recommendations
    if assessment.critical_findings > 0 {
        assessment.recommendations.push(
            "CRITICAL: Address biometric data protection immediately - eye tracking and facial recognition data require immediate security review.".to_string()
        );
    }
    if assessment.high_findings > 0 {
        assessment.recommendations.push(
            "HIGH: Review spatial computing privacy controls and implement data minimization.".to_string()
        );
    }
    assessment.recommendations.push(
        "Implement XR-specific security policies covering biometric data, spatial mapping, and voice capture.".to_string()
    );
    assessment.recommendations.push(
        "Train users on XR privacy risks including bystander awareness and social engineering in virtual environments.".to_string()
    );

    assessment
}
