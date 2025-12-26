// Vendor Risk Management Module
//
// Provides comprehensive vendor risk management capabilities:
// - Vendor lifecycle management
// - Risk assessments
// - Security questionnaires
// - Continuous monitoring
// - Contract tracking

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{
    AssessmentType, DataAccessLevel, QuestionType, QuestionnaireQuestion, QuestionnaireResponse,
    RiskLevel, ScoringMethod, Vendor, VendorApprovalStatus, VendorAssessment, VendorCategory,
    VendorQuestionnaire, VendorStatus, VendorTier,
};

/// Vendor risk management engine
pub struct VendorManager {
    vendors: HashMap<String, Vendor>,
    assessments: HashMap<String, Vec<VendorAssessment>>,
    questionnaires: HashMap<String, VendorQuestionnaire>,
    responses: HashMap<String, Vec<QuestionnaireResponse>>,
    vendor_counter: u32,
}

impl VendorManager {
    pub fn new() -> Self {
        Self {
            vendors: HashMap::new(),
            assessments: HashMap::new(),
            questionnaires: HashMap::new(),
            responses: HashMap::new(),
            vendor_counter: 0,
        }
    }

    /// Create a new vendor
    pub fn create_vendor(
        &mut self,
        name: String,
        category: VendorCategory,
        tier: VendorTier,
        services_provided: Option<String>,
        data_access_level: DataAccessLevel,
        data_types_accessed: Vec<String>,
    ) -> Vendor {
        self.vendor_counter += 1;
        let id = uuid::Uuid::new_v4().to_string();
        let vendor_id = format!("VND-{:04}", self.vendor_counter);
        let now = Utc::now();

        let vendor = Vendor {
            id: id.clone(),
            vendor_id,
            name,
            category,
            tier,
            status: VendorStatus::Prospective,
            primary_contact_name: None,
            primary_contact_email: None,
            services_provided,
            data_access_level,
            data_types_accessed,
            contract_start_date: None,
            contract_end_date: None,
            contract_value: None,
            inherent_risk_score: None,
            residual_risk_score: None,
            last_assessment_date: None,
            next_assessment_date: None,
            soc2_report: false,
            iso_27001_certified: false,
            other_certifications: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        self.vendors.insert(id, vendor.clone());
        vendor
    }

    /// Update vendor status
    pub fn update_vendor_status(&mut self, vendor_id: &str, status: VendorStatus) -> Result<(), VendorError> {
        let vendor = self.vendors.get_mut(vendor_id).ok_or(VendorError::NotFound)?;
        vendor.status = status;
        vendor.updated_at = Utc::now();
        Ok(())
    }

    /// Update vendor contact
    pub fn update_vendor_contact(
        &mut self,
        vendor_id: &str,
        contact_name: Option<String>,
        contact_email: Option<String>,
    ) -> Result<(), VendorError> {
        let vendor = self.vendors.get_mut(vendor_id).ok_or(VendorError::NotFound)?;
        if let Some(name) = contact_name {
            vendor.primary_contact_name = Some(name);
        }
        if let Some(email) = contact_email {
            vendor.primary_contact_email = Some(email);
        }
        vendor.updated_at = Utc::now();
        Ok(())
    }

    /// Update contract information
    pub fn update_contract(
        &mut self,
        vendor_id: &str,
        start_date: Option<NaiveDate>,
        end_date: Option<NaiveDate>,
        value: Option<f64>,
    ) -> Result<(), VendorError> {
        let vendor = self.vendors.get_mut(vendor_id).ok_or(VendorError::NotFound)?;
        vendor.contract_start_date = start_date;
        vendor.contract_end_date = end_date;
        vendor.contract_value = value;
        vendor.updated_at = Utc::now();
        Ok(())
    }

    /// Update certifications
    pub fn update_certifications(
        &mut self,
        vendor_id: &str,
        soc2_report: Option<bool>,
        iso_27001_certified: Option<bool>,
        other_certifications: Option<Vec<String>>,
    ) -> Result<(), VendorError> {
        let vendor = self.vendors.get_mut(vendor_id).ok_or(VendorError::NotFound)?;
        if let Some(soc2) = soc2_report {
            vendor.soc2_report = soc2;
        }
        if let Some(iso) = iso_27001_certified {
            vendor.iso_27001_certified = iso;
        }
        if let Some(certs) = other_certifications {
            vendor.other_certifications = certs;
        }
        vendor.updated_at = Utc::now();
        Ok(())
    }

    /// Calculate inherent risk score
    fn calculate_inherent_risk(vendor: &Vendor) -> u8 {
        let mut score: u8 = 0;

        // Tier-based risk (higher tier = lower risk number but more critical)
        score += match vendor.tier {
            VendorTier::Tier1 => 5, // Critical
            VendorTier::Tier2 => 3, // Important
            VendorTier::Tier3 => 1, // Standard
        };

        // Data access level
        score += match vendor.data_access_level {
            DataAccessLevel::Restricted => 5,
            DataAccessLevel::Confidential => 4,
            DataAccessLevel::Limited => 2,
            DataAccessLevel::None => 0,
        };

        // Number of data types
        score += std::cmp::min(vendor.data_types_accessed.len() as u8, 5);

        std::cmp::min(score, 25)
    }

    /// Create a vendor assessment
    pub fn create_assessment(
        &mut self,
        vendor_id: &str,
        assessor_id: String,
        assessment_type: AssessmentType,
        questionnaire_id: Option<String>,
        questionnaire_score: Option<f64>,
        risk_areas: Vec<String>,
        findings: Vec<String>,
        recommendations: Option<String>,
    ) -> Result<VendorAssessment, VendorError> {
        let vendor = self.vendors.get_mut(vendor_id).ok_or(VendorError::NotFound)?;

        // Calculate overall risk rating based on score and certifications
        let base_score = questionnaire_score.unwrap_or(50.0);
        let cert_bonus = if vendor.soc2_report { 10.0 } else { 0.0 }
            + if vendor.iso_27001_certified { 10.0 } else { 0.0 };

        let adjusted_score = base_score + cert_bonus;
        let overall_risk_rating = match adjusted_score as u32 {
            0..=40 => RiskLevel::Critical,
            41..=60 => RiskLevel::High,
            61..=80 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        let now = Utc::now();
        let assessment = VendorAssessment {
            id: uuid::Uuid::new_v4().to_string(),
            vendor_id: vendor_id.to_string(),
            assessment_type,
            assessment_date: now.date_naive(),
            assessor_id,
            questionnaire_id,
            questionnaire_score,
            risk_areas,
            findings,
            recommendations,
            overall_risk_rating: overall_risk_rating.clone(),
            approval_status: VendorApprovalStatus::Pending,
            approval_notes: None,
            approved_by: None,
            approved_at: None,
            created_at: now,
        };

        // Update vendor risk scores
        vendor.inherent_risk_score = Some(Self::calculate_inherent_risk(vendor));
        vendor.residual_risk_score = Some(match overall_risk_rating {
            RiskLevel::Critical => 20,
            RiskLevel::High => 15,
            RiskLevel::Medium => 10,
            RiskLevel::Low => 5,
        });
        vendor.last_assessment_date = Some(now.date_naive());

        // Calculate next assessment date based on risk and tier
        let months = match (&vendor.tier, &overall_risk_rating) {
            (VendorTier::Tier1, _) | (_, RiskLevel::Critical) => 3,  // Quarterly
            (VendorTier::Tier2, _) | (_, RiskLevel::High) => 6,       // Semi-annual
            _ => 12,                                                   // Annual
        };
        vendor.next_assessment_date = Some(now.date_naive() + chrono::Duration::days(months * 30));
        vendor.updated_at = now;

        self.assessments
            .entry(vendor_id.to_string())
            .or_default()
            .push(assessment.clone());

        Ok(assessment)
    }

    /// Approve or reject assessment
    pub fn decide_assessment(
        &mut self,
        assessment_id: &str,
        approved_by: String,
        approval_status: VendorApprovalStatus,
        notes: Option<String>,
    ) -> Result<VendorAssessment, VendorError> {
        for assessments in self.assessments.values_mut() {
            if let Some(assessment) = assessments.iter_mut().find(|a| a.id == assessment_id) {
                assessment.approval_status = approval_status.clone();
                assessment.approval_notes = notes;
                assessment.approved_by = Some(approved_by);
                assessment.approved_at = Some(Utc::now());

                // Update vendor status if approved
                if approval_status == VendorApprovalStatus::Approved {
                    if let Some(vendor) = self.vendors.get_mut(&assessment.vendor_id) {
                        vendor.status = VendorStatus::Active;
                        vendor.updated_at = Utc::now();
                    }
                }

                return Ok(assessment.clone());
            }
        }
        Err(VendorError::AssessmentNotFound)
    }

    /// Create a questionnaire
    pub fn create_questionnaire(
        &mut self,
        name: String,
        description: Option<String>,
        questions: Vec<QuestionnaireQuestion>,
        scoring_method: ScoringMethod,
    ) -> VendorQuestionnaire {
        let id = uuid::Uuid::new_v4().to_string();

        let questionnaire = VendorQuestionnaire {
            id: id.clone(),
            name,
            description,
            version: "1.0".to_string(),
            questions,
            scoring_method,
            is_active: true,
            created_at: Utc::now(),
        };

        self.questionnaires.insert(id, questionnaire.clone());
        questionnaire
    }

    /// Submit questionnaire response
    pub fn submit_questionnaire_response(
        &mut self,
        vendor_id: &str,
        questionnaire_id: &str,
        assessment_id: Option<String>,
        responses: HashMap<String, serde_json::Value>,
    ) -> Result<QuestionnaireResponse, VendorError> {
        if !self.vendors.contains_key(vendor_id) {
            return Err(VendorError::NotFound);
        }

        let questionnaire = self.questionnaires.get(questionnaire_id)
            .ok_or(VendorError::QuestionnaireNotFound)?;

        // Calculate score based on scoring method
        let score = self.calculate_questionnaire_score(questionnaire, &responses);

        let response = QuestionnaireResponse {
            id: uuid::Uuid::new_v4().to_string(),
            vendor_id: vendor_id.to_string(),
            questionnaire_id: questionnaire_id.to_string(),
            assessment_id,
            responses,
            score: Some(score),
            submitted_at: Some(Utc::now()),
            reviewed_at: None,
            reviewed_by: None,
            created_at: Utc::now(),
        };

        self.responses
            .entry(vendor_id.to_string())
            .or_default()
            .push(response.clone());

        Ok(response)
    }

    /// Calculate questionnaire score
    fn calculate_questionnaire_score(
        &self,
        questionnaire: &VendorQuestionnaire,
        responses: &HashMap<String, serde_json::Value>,
    ) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for question in &questionnaire.questions {
            if let Some(answer) = responses.get(&question.id) {
                let question_score = match question.question_type {
                    QuestionType::YesNo => {
                        if answer.as_bool().unwrap_or(false) { 1.0 } else { 0.0 }
                    }
                    QuestionType::Rating => {
                        answer.as_f64().unwrap_or(0.0) / 5.0 // Assuming 1-5 rating
                    }
                    QuestionType::MultipleChoice => {
                        // Score based on position in options (last = best)
                        if let Some(selected) = answer.as_str() {
                            if let Some(options) = &question.options {
                                let pos = options.iter().position(|o| o == selected).unwrap_or(0);
                                (pos as f64 + 1.0) / options.len() as f64
                            } else {
                                0.5
                            }
                        } else {
                            0.5
                        }
                    }
                    QuestionType::Text | QuestionType::Upload => 0.5, // Neutral for text/upload
                };

                total_score += question_score * question.weight;
                total_weight += question.weight;
            }
        }

        if total_weight > 0.0 {
            (total_score / total_weight) * 100.0
        } else {
            0.0
        }
    }

    /// Get vendor by ID
    pub fn get_vendor(&self, vendor_id: &str) -> Option<&Vendor> {
        self.vendors.get(vendor_id)
    }

    /// List all vendors
    pub fn list_vendors(
        &self,
        status: Option<VendorStatus>,
        tier: Option<VendorTier>,
        category: Option<VendorCategory>,
    ) -> Vec<&Vendor> {
        self.vendors
            .values()
            .filter(|v| {
                status.as_ref().map_or(true, |s| &v.status == s)
                    && tier.as_ref().map_or(true, |t| &v.tier == t)
                    && category.as_ref().map_or(true, |c| &v.category == c)
            })
            .collect()
    }

    /// Get assessments for a vendor
    pub fn get_assessments(&self, vendor_id: &str) -> Vec<&VendorAssessment> {
        self.assessments
            .get(vendor_id)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }

    /// Get questionnaire responses for a vendor
    pub fn get_responses(&self, vendor_id: &str) -> Vec<&QuestionnaireResponse> {
        self.responses
            .get(vendor_id)
            .map(|r| r.iter().collect())
            .unwrap_or_default()
    }

    /// Get vendors due for assessment
    pub fn get_vendors_due_assessment(&self) -> Vec<&Vendor> {
        let today = Utc::now().date_naive();
        self.vendors
            .values()
            .filter(|v| {
                v.status == VendorStatus::Active
                    && v.next_assessment_date.map_or(true, |d| d <= today)
            })
            .collect()
    }

    /// Get high-risk vendors
    pub fn get_high_risk_vendors(&self) -> Vec<&Vendor> {
        self.vendors
            .values()
            .filter(|v| {
                v.status == VendorStatus::Active
                    && v.residual_risk_score.map_or(false, |s| s >= 15)
            })
            .collect()
    }

    /// Get vendor statistics
    pub fn get_statistics(&self) -> VendorStatistics {
        let total = self.vendors.len() as u32;
        let active = self.vendors
            .values()
            .filter(|v| v.status == VendorStatus::Active)
            .count() as u32;

        let critical = self.vendors
            .values()
            .filter(|v| v.category == VendorCategory::Critical)
            .count() as u32;

        let high_risk = self.get_high_risk_vendors().len() as u32;
        let due_assessment = self.get_vendors_due_assessment().len() as u32;

        let avg_score: f64 = self.vendors
            .values()
            .filter_map(|v| v.residual_risk_score)
            .map(|s| s as f64)
            .sum::<f64>()
            / self.vendors.values().filter(|v| v.residual_risk_score.is_some()).count().max(1) as f64;

        VendorStatistics {
            total_vendors: total,
            active_vendors: active,
            critical_vendors: critical,
            high_risk_vendors: high_risk,
            vendors_due_assessment: due_assessment,
            avg_vendor_risk_score: avg_score,
        }
    }
}

impl Default for VendorManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorStatistics {
    pub total_vendors: u32,
    pub active_vendors: u32,
    pub critical_vendors: u32,
    pub high_risk_vendors: u32,
    pub vendors_due_assessment: u32,
    pub avg_vendor_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VendorError {
    NotFound,
    AssessmentNotFound,
    QuestionnaireNotFound,
    ValidationError(String),
}

impl std::fmt::Display for VendorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Vendor not found"),
            Self::AssessmentNotFound => write!(f, "Assessment not found"),
            Self::QuestionnaireNotFound => write!(f, "Questionnaire not found"),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for VendorError {}

/// Helper function to create a standard security questionnaire
pub fn create_standard_questionnaire() -> (String, Option<String>, Vec<QuestionnaireQuestion>, ScoringMethod) {
    let questions = vec![
        QuestionnaireQuestion {
            id: "q1".to_string(),
            section: "Information Security".to_string(),
            question: "Does your organization have a documented information security policy?".to_string(),
            question_type: QuestionType::YesNo,
            options: None,
            weight: 1.5,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q2".to_string(),
            section: "Information Security".to_string(),
            question: "How often do you conduct security assessments?".to_string(),
            question_type: QuestionType::MultipleChoice,
            options: Some(vec![
                "Never".to_string(),
                "Ad-hoc".to_string(),
                "Annually".to_string(),
                "Quarterly".to_string(),
            ]),
            weight: 1.0,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q3".to_string(),
            section: "Access Control".to_string(),
            question: "Is multi-factor authentication implemented?".to_string(),
            question_type: QuestionType::YesNo,
            options: None,
            weight: 2.0,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q4".to_string(),
            section: "Access Control".to_string(),
            question: "Rate your access control maturity (1-5)".to_string(),
            question_type: QuestionType::Rating,
            options: None,
            weight: 1.5,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q5".to_string(),
            section: "Data Protection".to_string(),
            question: "Is data encrypted at rest and in transit?".to_string(),
            question_type: QuestionType::YesNo,
            options: None,
            weight: 2.0,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q6".to_string(),
            section: "Incident Response".to_string(),
            question: "Do you have a documented incident response plan?".to_string(),
            question_type: QuestionType::YesNo,
            options: None,
            weight: 1.5,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q7".to_string(),
            section: "Business Continuity".to_string(),
            question: "How often is your disaster recovery plan tested?".to_string(),
            question_type: QuestionType::MultipleChoice,
            options: Some(vec![
                "Never".to_string(),
                "When issues occur".to_string(),
                "Annually".to_string(),
                "Semi-annually or more".to_string(),
            ]),
            weight: 1.0,
            required: true,
        },
        QuestionnaireQuestion {
            id: "q8".to_string(),
            section: "Compliance".to_string(),
            question: "What security certifications does your organization hold?".to_string(),
            question_type: QuestionType::Text,
            options: None,
            weight: 1.0,
            required: false,
        },
    ];

    (
        "Standard Security Questionnaire".to_string(),
        Some("Standard security assessment questionnaire for vendor evaluation".to_string()),
        questions,
        ScoringMethod::Weighted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_lifecycle() {
        let mut manager = VendorManager::new();

        // Create vendor
        let vendor = manager.create_vendor(
            "Acme Cloud Services".to_string(),
            VendorCategory::Critical,
            VendorTier::Tier1,
            Some("Cloud hosting and infrastructure".to_string()),
            DataAccessLevel::Confidential,
            vec!["PII".to_string(), "Financial".to_string()],
        );

        assert_eq!(vendor.status, VendorStatus::Prospective);
        assert!(vendor.vendor_id.starts_with("VND-"));

        // Update certifications
        manager.update_certifications(
            &vendor.id,
            Some(true),
            Some(true),
            Some(vec!["PCI-DSS".to_string()]),
        ).unwrap();

        let updated = manager.get_vendor(&vendor.id).unwrap();
        assert!(updated.soc2_report);
        assert!(updated.iso_27001_certified);
    }

    #[test]
    fn test_vendor_assessment() {
        let mut manager = VendorManager::new();

        let vendor = manager.create_vendor(
            "Test Vendor".to_string(),
            VendorCategory::High,
            VendorTier::Tier2,
            None,
            DataAccessLevel::Limited,
            vec![],
        );

        // Create assessment
        let assessment = manager.create_assessment(
            &vendor.id,
            "assessor-1".to_string(),
            AssessmentType::Initial,
            None,
            Some(75.0),
            vec!["Password policy".to_string()],
            vec!["No MFA".to_string()],
            Some("Implement MFA".to_string()),
        ).unwrap();

        assert_eq!(assessment.overall_risk_rating, RiskLevel::Medium);
        assert_eq!(assessment.approval_status, VendorApprovalStatus::Pending);

        // Approve
        manager.decide_assessment(
            &assessment.id,
            "approver-1".to_string(),
            VendorApprovalStatus::Approved,
            None,
        ).unwrap();

        let updated_vendor = manager.get_vendor(&vendor.id).unwrap();
        assert_eq!(updated_vendor.status, VendorStatus::Active);
    }

    #[test]
    fn test_questionnaire() {
        let mut manager = VendorManager::new();

        let (name, desc, questions, method) = create_standard_questionnaire();
        let questionnaire = manager.create_questionnaire(name, desc, questions, method);

        assert_eq!(questionnaire.questions.len(), 8);

        // Create vendor and submit response
        let vendor = manager.create_vendor(
            "Test Vendor".to_string(),
            VendorCategory::Medium,
            VendorTier::Tier3,
            None,
            DataAccessLevel::None,
            vec![],
        );

        let mut responses = HashMap::new();
        responses.insert("q1".to_string(), serde_json::Value::Bool(true));
        responses.insert("q3".to_string(), serde_json::Value::Bool(true));
        responses.insert("q5".to_string(), serde_json::Value::Bool(true));
        responses.insert("q4".to_string(), serde_json::Value::from(4));

        let response = manager.submit_questionnaire_response(
            &vendor.id,
            &questionnaire.id,
            None,
            responses,
        ).unwrap();

        assert!(response.score.is_some());
    }
}
