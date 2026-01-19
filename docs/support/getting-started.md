# Getting Started with HeroForge

Welcome to HeroForge, a comprehensive network reconnaissance and security assessment platform for authorized penetration testing.

## Prerequisites

Before you begin, ensure you have:

- **Authorization**: Written permission to test your target systems
- **Account**: A registered HeroForge account
- **System Requirements**: Modern web browser (Chrome, Firefox, Safari, Edge)

## Quick Start Guide

### 1. Create Your Account

1. Navigate to [heroforge.genialarchitect.io/register](https://heroforge.genialarchitect.io/register)
2. Fill in your details:
   - Username
   - Email address
   - Strong password (minimum 12 characters, with uppercase, lowercase, numbers, and symbols)
3. Accept the Terms of Service and Privacy Policy
4. Click "Create Account"
5. Verify your email address via the confirmation link

### 2. Log In

1. Go to [heroforge.genialarchitect.io/login](https://heroforge.genialarchitect.io/login)
2. Enter your username and password
3. If MFA is enabled, enter your verification code
4. You'll be redirected to the Dashboard

### 3. Run Your First Scan

1. From the Dashboard, click **New Scan** or navigate to the Scans page
2. Configure your scan:
   - **Name**: Give your scan a descriptive name
   - **Targets**: Enter IP addresses, hostnames, or CIDR ranges (e.g., `192.168.1.0/24`)
   - **Scan Type**: Choose from:
     - TCP Connect (default, no special privileges required)
     - TCP SYN (faster, requires root/admin)
     - UDP (for UDP services)
     - Comprehensive (TCP + UDP)
   - **Ports**: Specify ports to scan (e.g., `22,80,443` or `1-1000`)
3. Click **Start Scan**
4. Monitor progress in real-time via the scan detail page

### 4. Review Results

After the scan completes:

1. View discovered hosts and open ports
2. Check detected services and their versions
3. Review any identified vulnerabilities
4. Export results in various formats (JSON, HTML, PDF, CSV)

## Key Features

- **Network Reconnaissance**: Discover hosts, ports, and services
- **Vulnerability Scanning**: Identify security weaknesses
- **Compliance Assessment**: Check against 45+ frameworks (PCI-DSS, HIPAA, SOC 2, etc.)
- **Asset Management**: Track and manage discovered assets
- **Real-time Progress**: WebSocket-based live updates during scans
- **Report Generation**: Professional reports in multiple formats

## Security Best Practices

1. **Always get authorization** before scanning any systems
2. **Enable MFA** on your account for enhanced security
3. **Scope your scans** appropriately - only scan what you're authorized to test
4. **Protect your credentials** and API keys
5. **Review results carefully** before sharing reports

## Next Steps

- Read the [CLI Reference](./cli-reference.md) for command-line usage
- Explore the [Web Dashboard Guide](./web-dashboard.md) for detailed UI navigation
- Check the [FAQ](./faq.md) for common questions
- See [Troubleshooting](./troubleshooting.md) if you encounter issues

## Need Help?

- **Email**: support@heroforge.security
- **Documentation**: [heroforge.genialarchitect.io/docs](https://heroforge.genialarchitect.io/docs)
- **Community**: Join our Discord/Slack for community support
