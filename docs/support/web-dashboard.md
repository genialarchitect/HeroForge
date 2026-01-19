# Web Dashboard Guide

The HeroForge web dashboard provides a comprehensive interface for managing scans, viewing results, and analyzing security findings.

## Accessing the Dashboard

1. Navigate to [heroforge.genialarchitect.io](https://heroforge.genialarchitect.io)
2. Log in with your credentials
3. You'll land on the main Dashboard page

## Dashboard Overview

The Dashboard provides a high-level view of your security posture:

- **Recent Scans**: Quick access to your latest scan activities
- **Vulnerability Summary**: Charts showing vulnerability counts by severity
- **Asset Overview**: Total discovered assets and their status
- **Compliance Status**: Summary of compliance framework assessments

## Navigation

The main navigation includes:

### Scans

- **All Scans**: List of all scans with status, date, and target information
- **New Scan**: Create and configure a new scan
- **Scan Templates**: Reusable scan configurations
- **Scan Comparison**: Compare results between two scans

### Assets

- **Asset Inventory**: All discovered hosts, services, and devices
- **Asset Discovery**: Automated asset enumeration tools
- **Asset Groups**: Organize assets by business unit, environment, etc.

### Vulnerabilities

- **All Vulnerabilities**: Comprehensive list with filtering and sorting
- **By Severity**: Filter by Critical, High, Medium, Low
- **Remediation**: Track remediation progress
- **Statistics**: Analytics and trending data

### Compliance

- **Frameworks**: Support for 45+ compliance frameworks
- **Assessments**: Run compliance checks against your assets
- **Manual Assessment**: Record manual verification results
- **Evidence**: Upload and manage compliance evidence

### Reports

- **Generate Report**: Create reports from scan results
- **Report Templates**: Customize report formats
- **Scheduled Reports**: Automate recurring reports
- **Export Options**: JSON, HTML, PDF, CSV, Markdown

### Settings

- **Profile**: Update your user information
- **Security**: Password, MFA, API keys
- **Notifications**: Email and webhook alerts
- **Integrations**: JIRA, ServiceNow, SIEM connections

## Running a Scan

### Step 1: Create New Scan

1. Click **Scans** > **New Scan**
2. Enter a descriptive **Scan Name**
3. Specify **Targets**:
   - Single IP: `192.168.1.1`
   - Hostname: `server.example.com`
   - CIDR range: `192.168.1.0/24`
   - Multiple targets (comma-separated)

### Step 2: Configure Scan Options

**Scan Type:**
- **TCP Connect**: Standard connection scan (default)
- **TCP SYN**: Half-open scan (faster, needs privileges)
- **UDP**: UDP service detection
- **Comprehensive**: Both TCP and UDP

**Port Configuration:**
- Common ports: `22,80,443,3389,8080`
- Port range: `1-1000`
- All ports: `1-65535`

**Advanced Options:**
- Service Detection: Identify service versions
- OS Fingerprinting: Detect operating systems
- Vulnerability Scanning: Check for known CVEs
- Enumeration Depth: Passive, Light, or Aggressive

### Step 3: Monitor Progress

After starting the scan:

1. View real-time progress on the scan detail page
2. Watch live updates as hosts and services are discovered
3. See vulnerability findings as they're detected
4. Progress bar shows overall completion percentage

### Step 4: Review Results

When complete, the results page shows:

- **Hosts**: Discovered systems with IP, hostname, OS
- **Ports**: Open ports with service details
- **Services**: Detected services and versions
- **Vulnerabilities**: Security findings with severity ratings

## Working with Vulnerabilities

### Vulnerability List

The vulnerability list supports:

- **Filtering**: By severity, status, host, service
- **Sorting**: By severity, date, CVSS score
- **Search**: Find specific CVEs or keywords
- **Bulk Actions**: Update status for multiple items

### Vulnerability Details

Click any vulnerability to see:

- **Description**: What the vulnerability is
- **Risk Level**: CVSS score and severity
- **Affected Assets**: Which systems are impacted
- **Remediation**: How to fix the issue
- **References**: Links to CVE, advisories, etc.

### Managing Status

Track remediation progress:

- **Open**: Not yet addressed
- **In Progress**: Being worked on
- **Resolved**: Fixed
- **Accepted Risk**: Acknowledged but not fixing
- **False Positive**: Not actually vulnerable

## Compliance Assessments

### Running an Assessment

1. Go to **Compliance** > **Assessments**
2. Select a framework (e.g., PCI-DSS 4.0)
3. Choose scope (all assets or specific groups)
4. Click **Run Assessment**

### Supported Frameworks

HeroForge supports 45+ compliance frameworks including:

- **General**: CIS, NIST 800-53, NIST CSF, ISO 27001
- **Industry**: PCI-DSS, HIPAA, SOC 2, GLBA
- **Government**: FedRAMP, CMMC, FISMA, StateRAMP
- **International**: NIS2, Cyber Essentials, ISM

### Manual Assessments

For controls that can't be automated:

1. Go to **Compliance** > **Manual Assessment**
2. Select the framework and control
3. Record your assessment results
4. Upload supporting evidence

## Generating Reports

### Report Types

- **Executive Summary**: High-level overview for management
- **Technical Report**: Detailed findings for IT teams
- **Compliance Report**: Framework-specific assessment results
- **Vulnerability Report**: Focus on security findings

### Creating a Report

1. Go to **Reports** > **Generate Report**
2. Select the source (scan, assessment, or all data)
3. Choose report template
4. Configure sections to include
5. Select output format
6. Click **Generate**

### Export Formats

- **PDF**: Professional formatted document
- **HTML**: Interactive web report
- **JSON**: Machine-readable data
- **CSV**: Spreadsheet-compatible
- **Markdown**: Documentation-friendly

## Tips and Tricks

1. **Use Templates**: Save scan configurations as templates for repeated use
2. **Schedule Scans**: Set up recurring scans for continuous monitoring
3. **Tag Assets**: Use tags to organize and filter assets
4. **Set Alerts**: Configure notifications for critical findings
5. **API Access**: Use the REST API for automation

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `?` | Show keyboard shortcuts |
| `g d` | Go to Dashboard |
| `g s` | Go to Scans |
| `g a` | Go to Assets |
| `g v` | Go to Vulnerabilities |
| `/` | Focus search |
| `Esc` | Close modal/dialog |

## See Also

- [Getting Started](./getting-started.md)
- [CLI Reference](./cli-reference.md)
- [FAQ](./faq.md)
- [Troubleshooting](./troubleshooting.md)
