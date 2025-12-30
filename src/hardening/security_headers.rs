//! HTTP security headers enforcement

pub struct SecurityHeaders {}

impl SecurityHeaders {
    pub fn get_recommended_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ]
    }
}
