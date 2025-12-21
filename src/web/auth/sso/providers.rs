//! SSO Provider Presets - Configuration templates for popular identity providers
//!
//! This module provides preset configurations for common enterprise identity providers.

use super::types::{
    AttributeMapping, OidcConfig, ProviderPreset, SamlConfig, SsoProviderType,
};

/// Get all available provider presets
pub fn get_provider_presets() -> Vec<ProviderPreset> {
    vec![
        okta_preset(),
        azure_ad_preset(),
        google_workspace_preset(),
        onelogin_preset(),
        ping_identity_preset(),
        generic_saml_preset(),
        generic_oidc_preset(),
        auth0_preset(),
        keycloak_preset(),
        jumpcloud_preset(),
    ]
}

/// Get a specific provider preset by ID
pub fn get_provider_preset(id: &str) -> Option<ProviderPreset> {
    get_provider_presets().into_iter().find(|p| p.id == id)
}

fn okta_preset() -> ProviderPreset {
    ProviderPreset {
        id: "okta".to_string(),
        name: "Okta".to_string(),
        description: "Enterprise identity management platform".to_string(),
        provider_type: SsoProviderType::Saml,
        icon: "okta".to_string(),
        default_config: serde_json::to_value(SamlConfig {
            idp_entity_id: "http://www.okta.com/<your-org-id>".to_string(),
            idp_sso_url: "https://<your-domain>.okta.com/app/<app-id>/sso/saml".to_string(),
            idp_slo_url: Some("https://<your-domain>.okta.com/app/<app-id>/slo/saml".to_string()),
            idp_certificate: String::new(),
            sign_requests: true,
            require_signed_response: true,
            require_signed_assertion: true,
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "groups".to_string(),
                target: "groups".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Okta SAML Configuration

1. In your Okta Admin Console, go to Applications > Create App Integration
2. Select SAML 2.0 and click Next
3. Configure the following:
   - App Name: HeroForge
   - Single sign-on URL: https://your-domain/api/sso/callback/saml
   - Audience URI (SP Entity ID): https://your-domain/api/sso/metadata/{provider-id}
   - Name ID format: EmailAddress
4. Configure attribute statements:
   - email: user.email
   - firstName: user.firstName
   - lastName: user.lastName
   - groups: appuser.groups (if using group sync)
5. Download the IdP metadata or certificate
6. Copy the IdP SSO URL, Entity ID, and certificate to this configuration
"#.to_string(),
    }
}

fn azure_ad_preset() -> ProviderPreset {
    ProviderPreset {
        id: "azure_ad".to_string(),
        name: "Microsoft Entra ID (Azure AD)".to_string(),
        description: "Microsoft's cloud-based identity and access management service".to_string(),
        provider_type: SsoProviderType::Oidc,
        icon: "microsoft".to_string(),
        default_config: serde_json::to_value(OidcConfig {
            issuer_url: "https://login.microsoftonline.com/<tenant-id>/v2.0".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
                "User.Read".to_string(),
            ],
            use_pkce: true,
            response_type: "code".to_string(),
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "preferred_username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "given_name".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "family_name".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "groups".to_string(),
                target: "groups".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Microsoft Entra ID (Azure AD) Configuration

1. Go to Azure Portal > Microsoft Entra ID > App registrations
2. Click "New registration"
3. Configure:
   - Name: HeroForge
   - Supported account types: Choose based on your needs
   - Redirect URI: Web - https://your-domain/api/sso/callback/oidc
4. After creation, note the Application (client) ID and Directory (tenant) ID
5. Go to Certificates & secrets > New client secret
6. Copy the secret value (shown only once)
7. Go to Token configuration > Add groups claim (if using group sync)
8. Configure API permissions:
   - Microsoft Graph: email, openid, profile, User.Read
9. Grant admin consent for the permissions
10. Enter the tenant ID, client ID, and client secret in this configuration
"#.to_string(),
    }
}

fn google_workspace_preset() -> ProviderPreset {
    ProviderPreset {
        id: "google_workspace".to_string(),
        name: "Google Workspace".to_string(),
        description: "Google's suite of cloud computing and collaboration tools".to_string(),
        provider_type: SsoProviderType::Oidc,
        icon: "google".to_string(),
        default_config: serde_json::to_value(OidcConfig {
            issuer_url: "https://accounts.google.com".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            use_pkce: true,
            response_type: "code".to_string(),
            authorization_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "name".to_string(),
                target: "display_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "given_name".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "family_name".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Google Workspace Configuration

1. Go to Google Cloud Console > APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth client ID"
3. If prompted, configure the consent screen:
   - User Type: Internal (for Workspace) or External
   - App name: HeroForge
   - Authorized domains: your-domain
4. Create OAuth client ID:
   - Application type: Web application
   - Name: HeroForge SSO
   - Authorized redirect URIs: https://your-domain/api/sso/callback/oidc
5. Copy the Client ID and Client secret
6. Enable the following APIs: Google+ API (for userinfo)
7. For Workspace-only access, restrict the app to your domain in Workspace Admin
"#.to_string(),
    }
}

fn onelogin_preset() -> ProviderPreset {
    ProviderPreset {
        id: "onelogin".to_string(),
        name: "OneLogin".to_string(),
        description: "Cloud-based identity and access management provider".to_string(),
        provider_type: SsoProviderType::Saml,
        icon: "onelogin".to_string(),
        default_config: serde_json::to_value(SamlConfig {
            idp_entity_id: "https://app.onelogin.com/saml/metadata/<connector-id>".to_string(),
            idp_sso_url: "https://<subdomain>.onelogin.com/trust/saml2/http-post/sso/<connector-id>".to_string(),
            idp_slo_url: Some("https://<subdomain>.onelogin.com/trust/saml2/http-redirect/slo/<connector-id>".to_string()),
            idp_certificate: String::new(),
            sign_requests: true,
            require_signed_response: true,
            require_signed_assertion: true,
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "User.email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "User.Username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "User.FirstName".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "User.LastName".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "memberOf".to_string(),
                target: "groups".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## OneLogin Configuration

1. In OneLogin Admin, go to Applications > Add App
2. Search for "SAML Custom Connector (Advanced)" and add it
3. Configure:
   - Display Name: HeroForge
   - Audience (EntityID): https://your-domain/api/sso/metadata/{provider-id}
   - Recipient: https://your-domain/api/sso/callback/saml
   - ACS (Consumer) URL: https://your-domain/api/sso/callback/saml
   - ACS (Consumer) URL Validator: ^https://your-domain/api/sso/callback/saml$
   - Single Logout URL: https://your-domain/api/sso/logout (optional)
4. Under Parameters, add the attribute mappings
5. Under SSO, copy the Issuer URL, SAML 2.0 Endpoint, and X.509 Certificate
6. Assign users/groups to the application
"#.to_string(),
    }
}

fn ping_identity_preset() -> ProviderPreset {
    ProviderPreset {
        id: "ping_identity".to_string(),
        name: "Ping Identity".to_string(),
        description: "Enterprise identity security solutions".to_string(),
        provider_type: SsoProviderType::Saml,
        icon: "ping".to_string(),
        default_config: serde_json::to_value(SamlConfig {
            idp_entity_id: "https://sso.connect.pingidentity.com/<issuer-id>".to_string(),
            idp_sso_url: "https://sso.connect.pingidentity.com/<issuer-id>/saml20/idp/sso".to_string(),
            idp_slo_url: Some("https://sso.connect.pingidentity.com/<issuer-id>/saml20/idp/slo".to_string()),
            idp_certificate: String::new(),
            sign_requests: true,
            require_signed_response: true,
            require_signed_assertion: true,
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "firstName".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "lastName".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "memberOf".to_string(),
                target: "groups".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Ping Identity Configuration

1. In PingOne Admin Console, go to Applications > Add Application
2. Select SAML Application
3. Configure:
   - Application Name: HeroForge
   - ACS URLs: https://your-domain/api/sso/callback/saml
   - Entity ID: https://your-domain/api/sso/metadata/{provider-id}
4. Configure attribute mappings:
   - email
   - username
   - firstName
   - lastName
5. Download the IdP metadata
6. Extract the Entity ID, SSO URL, and certificate from the metadata
"#.to_string(),
    }
}

fn generic_saml_preset() -> ProviderPreset {
    ProviderPreset {
        id: "generic_saml".to_string(),
        name: "Generic SAML 2.0".to_string(),
        description: "Configure any SAML 2.0 compliant identity provider".to_string(),
        provider_type: SsoProviderType::Saml,
        icon: "saml".to_string(),
        default_config: serde_json::to_value(SamlConfig::default()).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Generic SAML 2.0 Configuration

Configure your SAML 2.0 identity provider with:

**Service Provider (SP) Information:**
- Entity ID: https://your-domain/api/sso/metadata/{provider-id}
- ACS URL: https://your-domain/api/sso/callback/saml
- SLO URL: https://your-domain/api/sso/logout (optional)
- NameID Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress

**From your IdP, obtain:**
- IdP Entity ID
- IdP SSO URL
- IdP SLO URL (optional)
- IdP X.509 Certificate (PEM format)

**Required Attribute Mappings:**
- email (required)
- username (optional)
- firstName/givenName (optional)
- lastName/surname (optional)
- groups/memberOf (optional)
"#.to_string(),
    }
}

fn generic_oidc_preset() -> ProviderPreset {
    ProviderPreset {
        id: "generic_oidc".to_string(),
        name: "Generic OpenID Connect".to_string(),
        description: "Configure any OpenID Connect compliant identity provider".to_string(),
        provider_type: SsoProviderType::Oidc,
        icon: "oidc".to_string(),
        default_config: serde_json::to_value(OidcConfig::default()).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "preferred_username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "name".to_string(),
                target: "display_name".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Generic OpenID Connect Configuration

Configure your OIDC identity provider with:

**Client Configuration:**
- Application Type: Web
- Redirect URI: https://your-domain/api/sso/callback/oidc
- Post-logout Redirect URI: https://your-domain (optional)
- Grant Types: Authorization Code
- Token Endpoint Auth Method: client_secret_post (recommended)

**From your IdP, obtain:**
- Issuer URL (for auto-discovery)
- Client ID
- Client Secret

**Required Scopes:**
- openid
- email
- profile

**Standard Claim Mappings:**
- sub: unique identifier
- email: email address
- preferred_username: username
- name: display name
- given_name: first name
- family_name: last name
- groups: group memberships (if supported)
"#.to_string(),
    }
}

fn auth0_preset() -> ProviderPreset {
    ProviderPreset {
        id: "auth0".to_string(),
        name: "Auth0".to_string(),
        description: "Identity platform for application builders".to_string(),
        provider_type: SsoProviderType::Oidc,
        icon: "auth0".to_string(),
        default_config: serde_json::to_value(OidcConfig {
            issuer_url: "https://<your-tenant>.auth0.com/".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            use_pkce: true,
            response_type: "code".to_string(),
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "nickname".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "name".to_string(),
                target: "display_name".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Auth0 Configuration

1. In Auth0 Dashboard, go to Applications > Create Application
2. Select "Regular Web Applications"
3. In Settings, configure:
   - Name: HeroForge
   - Application Login URI: https://your-domain/login
   - Allowed Callback URLs: https://your-domain/api/sso/callback/oidc
   - Allowed Logout URLs: https://your-domain
   - Allowed Web Origins: https://your-domain
4. Copy the Domain, Client ID, and Client Secret
5. In the tenant settings, ensure email verification is enabled
6. (Optional) Set up Rules/Actions for group claims
"#.to_string(),
    }
}

fn keycloak_preset() -> ProviderPreset {
    ProviderPreset {
        id: "keycloak".to_string(),
        name: "Keycloak".to_string(),
        description: "Open source identity and access management".to_string(),
        provider_type: SsoProviderType::Oidc,
        icon: "keycloak".to_string(),
        default_config: serde_json::to_value(OidcConfig {
            issuer_url: "https://<keycloak-host>/realms/<realm-name>".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
                "roles".to_string(),
            ],
            use_pkce: true,
            response_type: "code".to_string(),
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "preferred_username".to_string(),
                target: "username".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "name".to_string(),
                target: "display_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "given_name".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "family_name".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "groups".to_string(),
                target: "groups".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## Keycloak Configuration

1. In Keycloak Admin Console, select your realm
2. Go to Clients > Create client
3. Configure:
   - Client type: OpenID Connect
   - Client ID: heroforge
   - Client authentication: On
   - Authorization: Off
4. In Settings:
   - Valid redirect URIs: https://your-domain/api/sso/callback/oidc
   - Valid post logout redirect URIs: https://your-domain
   - Web origins: https://your-domain
5. In Credentials, copy the Client secret
6. (Optional) Add group mappers in Client scopes
7. The issuer URL is: https://<keycloak>/realms/<realm>
"#.to_string(),
    }
}

fn jumpcloud_preset() -> ProviderPreset {
    ProviderPreset {
        id: "jumpcloud".to_string(),
        name: "JumpCloud".to_string(),
        description: "Cloud directory platform for secure identity management".to_string(),
        provider_type: SsoProviderType::Saml,
        icon: "jumpcloud".to_string(),
        default_config: serde_json::to_value(SamlConfig {
            idp_entity_id: "https://sso.jumpcloud.com/saml2/<application-id>".to_string(),
            idp_sso_url: "https://sso.jumpcloud.com/saml2/<application-id>".to_string(),
            idp_slo_url: None,
            idp_certificate: String::new(),
            sign_requests: false,
            require_signed_response: true,
            require_signed_assertion: true,
            ..Default::default()
        }).unwrap(),
        default_attribute_mappings: vec![
            AttributeMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
                default_value: None,
            },
            AttributeMapping {
                source: "firstname".to_string(),
                target: "first_name".to_string(),
                required: false,
                default_value: None,
            },
            AttributeMapping {
                source: "lastname".to_string(),
                target: "last_name".to_string(),
                required: false,
                default_value: None,
            },
        ],
        setup_instructions: r#"
## JumpCloud Configuration

1. In JumpCloud Admin Portal, go to SSO
2. Click + Add New Application
3. Select Custom SAML App
4. Configure:
   - Display Label: HeroForge
   - IdP Entity ID: leave default or customize
   - SP Entity ID: https://your-domain/api/sso/metadata/{provider-id}
   - ACS URL: https://your-domain/api/sso/callback/saml
   - SAMLSubject NameID: email
   - SAMLSubject NameID Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
5. Add attribute mappings as needed
6. Download the certificate
7. Copy the IdP Entity ID and SSO URL
"#.to_string(),
    }
}
