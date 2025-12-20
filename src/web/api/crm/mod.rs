//! CRM API endpoints
//!
//! Provides REST API endpoints for Customer Relationship Management including:
//! - Customer management (CRUD operations)
//! - Contact management
//! - Engagement/project tracking
//! - Contract management
//! - SLA definitions
//! - Time tracking
//! - Communication logging
//! - CRM dashboard statistics

pub mod communications;
pub mod contacts;
pub mod contracts;
pub mod customers;
pub mod dashboard;
pub mod engagements;
pub mod portal_users;
pub mod sla;
pub mod time_tracking;

use actix_web::web;

/// Configure CRM routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Dashboard
        .route("/crm/dashboard", web::get().to(dashboard::get_dashboard))
        // Customer endpoints
        .route("/crm/customers", web::get().to(customers::list_customers))
        .route("/crm/customers", web::post().to(customers::create_customer))
        .route("/crm/customers/{id}", web::get().to(customers::get_customer))
        .route("/crm/customers/{id}", web::put().to(customers::update_customer))
        .route("/crm/customers/{id}", web::delete().to(customers::delete_customer))
        .route("/crm/customers/{id}/summary", web::get().to(customers::get_customer_summary))
        // Contact endpoints
        .route("/crm/customers/{customer_id}/contacts", web::get().to(contacts::list_contacts))
        .route("/crm/customers/{customer_id}/contacts", web::post().to(contacts::create_contact))
        .route("/crm/contacts/{id}", web::get().to(contacts::get_contact))
        .route("/crm/contacts/{id}", web::put().to(contacts::update_contact))
        .route("/crm/contacts/{id}", web::delete().to(contacts::delete_contact))
        // Engagement endpoints
        .route("/crm/engagements", web::get().to(engagements::list_engagements))
        .route("/crm/customers/{customer_id}/engagements", web::get().to(engagements::list_customer_engagements))
        .route("/crm/customers/{customer_id}/engagements", web::post().to(engagements::create_engagement))
        .route("/crm/engagements/{id}", web::get().to(engagements::get_engagement))
        .route("/crm/engagements/{id}", web::put().to(engagements::update_engagement))
        .route("/crm/engagements/{id}", web::delete().to(engagements::delete_engagement))
        // Milestone endpoints
        .route("/crm/engagements/{engagement_id}/milestones", web::get().to(engagements::list_milestones))
        .route("/crm/engagements/{engagement_id}/milestones", web::post().to(engagements::create_milestone))
        .route("/crm/milestones/{id}", web::put().to(engagements::update_milestone))
        .route("/crm/milestones/{id}", web::delete().to(engagements::delete_milestone))
        // Contract endpoints
        .route("/crm/contracts", web::get().to(contracts::list_contracts))
        .route("/crm/customers/{customer_id}/contracts", web::get().to(contracts::list_customer_contracts))
        .route("/crm/customers/{customer_id}/contracts", web::post().to(contracts::create_contract))
        .route("/crm/contracts/{id}", web::get().to(contracts::get_contract))
        .route("/crm/contracts/{id}", web::put().to(contracts::update_contract))
        .route("/crm/contracts/{id}", web::delete().to(contracts::delete_contract))
        // SLA endpoints
        .route("/crm/sla-templates", web::get().to(sla::list_sla_templates))
        .route("/crm/sla-templates", web::post().to(sla::create_sla_template))
        .route("/crm/customers/{customer_id}/sla", web::get().to(sla::get_customer_sla))
        .route("/crm/customers/{customer_id}/sla", web::post().to(sla::set_customer_sla))
        .route("/crm/sla/{id}", web::delete().to(sla::delete_sla))
        // Time tracking endpoints
        .route("/crm/time", web::get().to(time_tracking::list_time_entries))
        .route("/crm/engagements/{engagement_id}/time", web::get().to(time_tracking::list_engagement_time))
        .route("/crm/engagements/{engagement_id}/time", web::post().to(time_tracking::create_time_entry))
        .route("/crm/time/{id}", web::delete().to(time_tracking::delete_time_entry))
        // Communication endpoints
        .route("/crm/customers/{customer_id}/communications", web::get().to(communications::list_communications))
        .route("/crm/customers/{customer_id}/communications", web::post().to(communications::create_communication))
        .route("/crm/communications/{id}", web::delete().to(communications::delete_communication))
        // Portal user management endpoints
        .route("/crm/customers/{customer_id}/portal-users", web::get().to(portal_users::list_portal_users))
        .route("/crm/customers/{customer_id}/portal-users", web::post().to(portal_users::create_portal_user_handler))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}", web::get().to(portal_users::get_portal_user))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}", web::put().to(portal_users::update_portal_user_handler))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}", web::delete().to(portal_users::delete_portal_user_handler))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}/activate", web::post().to(portal_users::activate_portal_user_handler))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}/deactivate", web::post().to(portal_users::deactivate_portal_user_handler))
        .route("/crm/customers/{customer_id}/portal-users/{user_id}/reset-password", web::post().to(portal_users::reset_portal_user_password));
}
