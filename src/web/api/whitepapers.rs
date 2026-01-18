use actix_web::{HttpResponse, Result, web};

/// Get list of available whitepapers (no authentication required - marketing content)
pub async fn list_whitepapers() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "whitepapers": [
            {
                "id": "unified-security",
                "title": "Transforming the Cybersecurity Landscape Through Unified Security Operations",
                "description": "Examines how HeroForge's innovative colored teams architecture with 86+ modules, 45 compliance frameworks, and AI-powered operations addresses critical gaps in the current cybersecurity landscape.",
                "version": "2.0",
                "date": "January 2026"
            },
            {
                "id": "novel-approach",
                "title": "Breaking the Mold: HeroForge's Novel Approach to Enterprise Cybersecurity",
                "description": "Explores 8 novel approaches including AI-powered security operations, finding lifecycle management, automated passive reconnaissance, and capabilities unavailable in fragmented security stacks.",
                "version": "2.0",
                "date": "January 2026"
            }
        ]
    })))
}

/// Get whitepaper content by ID (no authentication required - marketing content)
pub async fn get_whitepaper(path: web::Path<String>) -> Result<HttpResponse> {
    let id = path.into_inner();

    let filename = match id.as_str() {
        "unified-security" => "HeroForge_WhitePaper.md",
        "novel-approach" => "HeroForge_Novel_Approach_WhitePaper.md",
        _ => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Whitepaper not found"
            })));
        }
    };

    // Try multiple locations for the whitepaper files
    let possible_paths = vec![
        format!("./docs/whitepapers/{}", filename),
        format!("/data/whitepapers/{}", filename),
        format!("./{}", filename),
    ];

    for path in possible_paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return Ok(HttpResponse::Ok()
                .content_type("text/markdown; charset=utf-8")
                .body(content));
        }
    }

    Ok(HttpResponse::NotFound().json(serde_json::json!({
        "error": "Whitepaper file not found"
    })))
}
