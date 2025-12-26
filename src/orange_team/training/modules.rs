//! Training module content management

use crate::orange_team::types::*;
use chrono::Utc;
use uuid::Uuid;

/// Module content manager
pub struct ModuleManager {
    modules: Vec<TrainingModule>,
}

impl ModuleManager {
    /// Create a new module manager
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Create a new training module
    pub fn create_module(
        &mut self,
        course_id: Uuid,
        title: &str,
        content_type: ContentType,
        content: serde_json::Value,
        duration_minutes: u32,
    ) -> TrainingModule {
        let order_index = self.modules.iter().filter(|m| m.course_id == course_id).count() as u32;

        let module = TrainingModule {
            id: Uuid::new_v4(),
            course_id,
            title: title.to_string(),
            content_type,
            content_data: content,
            order_index,
            duration_minutes,
            created_at: Utc::now(),
        };

        self.modules.push(module.clone());
        module
    }

    /// Get modules for a course
    pub fn get_course_modules(&self, course_id: Uuid) -> Vec<&TrainingModule> {
        let mut modules: Vec<_> = self.modules.iter().filter(|m| m.course_id == course_id).collect();
        modules.sort_by_key(|m| m.order_index);
        modules
    }

    /// Get a specific module
    pub fn get_module(&self, id: Uuid) -> Option<&TrainingModule> {
        self.modules.iter().find(|m| m.id == id)
    }

    /// Reorder modules
    pub fn reorder_modules(&mut self, course_id: Uuid, module_ids: &[Uuid]) -> bool {
        for (index, &id) in module_ids.iter().enumerate() {
            if let Some(module) = self.modules.iter_mut().find(|m| m.id == id && m.course_id == course_id) {
                module.order_index = index as u32;
            } else {
                return false;
            }
        }
        true
    }

    /// Delete a module
    pub fn delete_module(&mut self, id: Uuid) -> bool {
        if let Some(pos) = self.modules.iter().position(|m| m.id == id) {
            self.modules.remove(pos);
            return true;
        }
        false
    }
}

impl Default for ModuleManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create video module content
pub fn create_video_content(video_url: &str, transcript: Option<&str>, captions_url: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "type": "video",
        "video_url": video_url,
        "transcript": transcript,
        "captions_url": captions_url,
        "autoplay": false,
        "controls": true
    })
}

/// Create interactive module content
pub fn create_interactive_content(slides: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "type": "interactive",
        "slides": slides,
        "navigation": "linear",
        "require_completion": true
    })
}

/// Create text module content
pub fn create_text_content(html_content: &str, resources: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "type": "text",
        "content": html_content,
        "resources": resources,
        "format": "html"
    })
}

/// Create simulation module content
pub fn create_simulation_content(scenario: &str, steps: Vec<serde_json::Value>, success_criteria: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "simulation",
        "scenario": scenario,
        "steps": steps,
        "success_criteria": success_criteria,
        "allow_retry": true
    })
}
