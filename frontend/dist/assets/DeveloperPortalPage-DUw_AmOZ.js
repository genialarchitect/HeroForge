import{j as e}from"./vendor-state-oFDmcCcB.js";import{r as i,L as d}from"./vendor-react-5KxtEOLM.js";import{S as G,bz as l,a1 as f,bA as w,$ as x,O as C,b7 as b,b5 as k,d as y,J as u,Z as R,a as H,aa as D,bg as S,b1 as o,a0 as h,ai as O,n as F,a7 as K,y as L,ao as $,h as q,g as z,m as B,E as U,aO as W,ac as M,K as V}from"./vendor-ui-BlFJDRaq.js";const J=[{id:"1",name:"Production API Key",prefix:"hf_prod_",created:"2026-01-10",lastUsed:"2026-01-20",scopes:["scans:read","scans:write","assets:read","reports:read"]},{id:"2",name:"CI/CD Pipeline Key",prefix:"hf_ci_",created:"2026-01-15",lastUsed:"2026-01-19",scopes:["scans:write","reports:read"]}],j=[{language:"python",label:"Python",code:`from heroforge import HeroForge

# Initialize the client
client = HeroForge(api_key="hf_your_api_key")

# Create a new scan
scan = client.scans.create(
    target="192.168.1.0/24",
    scan_type="comprehensive",
    name="Network Assessment Q1"
)

# Wait for completion
scan.wait()

# Get results
print(f"Found {len(scan.vulnerabilities)} vulnerabilities")
for vuln in scan.vulnerabilities:
    print(f"  [{vuln.severity}] {vuln.title}")

# Generate report
report = scan.generate_report(format="pdf")
report.download("assessment_report.pdf")`},{language:"javascript",label:"Node.js",code:`const HeroForge = require('heroforge');

// Initialize the client
const client = new HeroForge({ apiKey: 'hf_your_api_key' });

// Create a new scan
const scan = await client.scans.create({
  target: 'example.com',
  scanType: 'quick',
  name: 'Web App Scan'
});

// Wait for completion
await scan.wait();

// Get results
console.log(\`Found \${scan.vulnerabilities.length} vulnerabilities\`);
scan.vulnerabilities.forEach(vuln => {
  console.log(\`  [\${vuln.severity}] \${vuln.title}\`);
});

// Generate report
const report = await scan.generateReport({ format: 'html' });
await report.download('report.html');`},{language:"bash",label:"cURL",code:`# Create a new scan
curl -X POST https://api.heroforge.io/v1/scans \\
  -H "Authorization: Bearer hf_your_api_key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "quick",
    "name": "Quick Network Scan"
  }'

# Get scan status
curl https://api.heroforge.io/v1/scans/{scan_id} \\
  -H "Authorization: Bearer hf_your_api_key"

# Get vulnerabilities
curl https://api.heroforge.io/v1/scans/{scan_id}/vulnerabilities \\
  -H "Authorization: Bearer hf_your_api_key"

# Download report
curl https://api.heroforge.io/v1/scans/{scan_id}/report?format=pdf \\
  -H "Authorization: Bearer hf_your_api_key" \\
  -o report.pdf`},{language:"go",label:"Go",code:`package main

import (
    "fmt"
    "github.com/heroforge/heroforge-go"
)

func main() {
    // Initialize the client
    client := heroforge.NewClient("hf_your_api_key")

    // Create a new scan
    scan, err := client.Scans.Create(&heroforge.ScanRequest{
        Target:   "10.0.0.0/24",
        ScanType: heroforge.ScanTypeComprehensive,
        Name:     "Infrastructure Scan",
    })
    if err != nil {
        panic(err)
    }

    // Wait for completion
    scan.Wait()

    // Print results
    fmt.Printf("Found %d vulnerabilities\\n", len(scan.Vulnerabilities))
    for _, v := range scan.Vulnerabilities {
        fmt.Printf("  [%s] %s\\n", v.Severity, v.Title)
    }
}`}],_={github:`name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run HeroForge Scan
        uses: heroforge/scan-action@v1
        with:
          api-key: \${{ secrets.HEROFORGE_API_KEY }}
          target: \${{ github.event.repository.name }}
          scan-type: quick
          fail-on: critical

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: heroforge-report
          path: heroforge-report.html`,gitlab:`security-scan:
  stage: test
  image: heroforge/scanner:latest
  variables:
    HEROFORGE_API_KEY: $HEROFORGE_API_KEY
  script:
    - heroforge scan --target $CI_PROJECT_NAME
      --scan-type quick
      --output report.html
      --fail-on critical
  artifacts:
    paths:
      - report.html
    reports:
      sast: heroforge-gl-sast.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"`,jenkins:`pipeline {
    agent any

    environment {
        HEROFORGE_API_KEY = credentials('heroforge-api-key')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    heroforge scan \\
                        --target ${JOB_NAME} \\
                        --scan-type comprehensive \\
                        --output heroforge-report.html \\
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'heroforge-report.html'
                    publishHTML([
                        reportName: 'HeroForge Security Report',
                        reportDir: '.',
                        reportFiles: 'heroforge-report.html'
                    ])
                }
            }
        }
    }
}`,azure:`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: HeroForgeScan@1
    inputs:
      apiKey: $(HEROFORGE_API_KEY)
      target: $(Build.Repository.Name)
      scanType: 'quick'
      failOn: 'critical'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'heroforge-report.html'
      artifactName: 'SecurityReport'`},Y=[{event:"scan.started",description:"Triggered when a scan begins"},{event:"scan.completed",description:"Triggered when a scan finishes successfully"},{event:"scan.failed",description:"Triggered when a scan fails"},{event:"vulnerability.found",description:"Triggered for each vulnerability discovered"},{event:"vulnerability.critical",description:"Triggered only for critical vulnerabilities"},{event:"report.generated",description:"Triggered when a report is ready"},{event:"asset.discovered",description:"Triggered when new assets are found"},{event:"compliance.violation",description:"Triggered for compliance violations"}];function se(){var v;const[r,c]=i.useState("overview"),[a,A]=i.useState("python"),[n,E]=i.useState("github"),[m,N]=i.useState(null),[g,P]=i.useState(null),[Q,T]=i.useState(!1),p=(s,t)=>{navigator.clipboard.writeText(s),N(t),setTimeout(()=>N(null),2e3)},I=[{id:"overview",label:"Overview",icon:e.jsx(o,{className:"w-4 h-4"})},{id:"sdk",label:"SDKs",icon:e.jsx(w,{className:"w-4 h-4"})},{id:"api",label:"REST API",icon:e.jsx(C,{className:"w-4 h-4"})},{id:"cicd",label:"CI/CD",icon:e.jsx(b,{className:"w-4 h-4"})},{id:"webhooks",label:"Webhooks",icon:e.jsx(k,{className:"w-4 h-4"})},{id:"keys",label:"API Keys",icon:e.jsx(V,{className:"w-4 h-4"})}];return e.jsxs("div",{className:"min-h-screen bg-gray-900",children:[e.jsx("header",{className:"bg-gray-800 border-b border-gray-700",children:e.jsx("div",{className:"max-w-7xl mx-auto px-4 py-4",children:e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs(d,{to:"/",className:"flex items-center gap-2",children:[e.jsx(G,{className:"w-8 h-8 text-cyan-500"}),e.jsx("span",{className:"text-xl font-bold text-white",children:"HeroForge"}),e.jsx("span",{className:"text-gray-500 ml-2",children:"| Developers"})]}),e.jsxs("nav",{className:"hidden md:flex items-center gap-6",children:[e.jsx(d,{to:"/docs",className:"text-gray-300 hover:text-white",children:"Docs"}),e.jsxs("a",{href:"https://github.com/heroforge",className:"text-gray-300 hover:text-white flex items-center gap-1",children:[e.jsx(l,{className:"w-4 h-4"}),"GitHub"]}),e.jsx(d,{to:"/login",className:"px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg",children:"Sign In"})]})]})})}),e.jsx("section",{className:"py-12 bg-gradient-to-b from-gray-800 to-gray-900 border-b border-gray-700",children:e.jsxs("div",{className:"max-w-7xl mx-auto px-4",children:[e.jsxs("div",{className:"flex items-center gap-3 mb-4",children:[e.jsx("div",{className:"p-2 bg-cyan-500/20 rounded-lg",children:e.jsx(f,{className:"w-6 h-6 text-cyan-500"})}),e.jsx("h1",{className:"text-3xl font-bold text-white",children:"Developer Portal"})]}),e.jsx("p",{className:"text-xl text-gray-400 max-w-2xl",children:"Integrate HeroForge security scanning into your applications, pipelines, and workflows."})]})}),e.jsx("div",{className:"bg-gray-800 border-b border-gray-700 sticky top-0 z-10",children:e.jsx("div",{className:"max-w-7xl mx-auto px-4",children:e.jsx("nav",{className:"flex gap-1 overflow-x-auto",children:I.map(s=>e.jsxs("button",{onClick:()=>c(s.id),className:`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${r===s.id?"text-cyan-400 border-cyan-400":"text-gray-400 border-transparent hover:text-white"}`,children:[s.icon,s.label]},s.id))})})}),e.jsxs("div",{className:"max-w-7xl mx-auto px-4 py-8",children:[r==="overview"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{className:"grid md:grid-cols-4 gap-4",children:[e.jsxs("button",{onClick:()=>c("sdk"),className:"p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group",children:[e.jsx(w,{className:"w-8 h-8 text-cyan-500 mb-3"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-1",children:"SDKs"}),e.jsx("p",{className:"text-sm text-gray-400",children:"Python, Node.js, Go libraries"}),e.jsx(x,{className:"w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2"})]}),e.jsxs("button",{onClick:()=>c("api"),className:"p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group",children:[e.jsx(C,{className:"w-8 h-8 text-purple-500 mb-3"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-1",children:"REST API"}),e.jsx("p",{className:"text-sm text-gray-400",children:"Full API reference docs"}),e.jsx(x,{className:"w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2"})]}),e.jsxs("button",{onClick:()=>c("cicd"),className:"p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group",children:[e.jsx(b,{className:"w-8 h-8 text-green-500 mb-3"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-1",children:"CI/CD"}),e.jsx("p",{className:"text-sm text-gray-400",children:"GitHub, GitLab, Jenkins"}),e.jsx(x,{className:"w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2"})]}),e.jsxs("button",{onClick:()=>c("webhooks"),className:"p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group",children:[e.jsx(k,{className:"w-8 h-8 text-amber-500 mb-3"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-1",children:"Webhooks"}),e.jsx("p",{className:"text-sm text-gray-400",children:"Real-time event notifications"}),e.jsx(x,{className:"w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2"})]})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsxs("div",{className:"p-6 border-b border-gray-700",children:[e.jsx("h2",{className:"text-xl font-bold text-white",children:"Quick Start"}),e.jsx("p",{className:"text-gray-400 mt-1",children:"Get up and running in minutes"})]}),e.jsx("div",{className:"border-b border-gray-700",children:e.jsx("div",{className:"flex gap-1 px-4 pt-2",children:j.map(s=>e.jsx("button",{onClick:()=>A(s.language),className:`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${a===s.language?"bg-gray-900 text-cyan-400":"text-gray-400 hover:text-white"}`,children:s.label},s.language))})}),e.jsxs("div",{className:"relative",children:[e.jsx("button",{onClick:()=>{var s;return p(((s=j.find(t=>t.language===a))==null?void 0:s.code)||"","quickstart")},className:"absolute top-4 right-4 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-400 hover:text-white",children:m==="quickstart"?e.jsx(y,{className:"w-4 h-4 text-green-500"}):e.jsx(u,{className:"w-4 h-4"})}),e.jsx("pre",{className:"p-6 bg-gray-900 text-gray-300 overflow-x-auto",children:e.jsx("code",{children:(v=j.find(s=>s.language===a))==null?void 0:v.code})})]}),e.jsxs("div",{className:"p-4 bg-gray-700/50 border-t border-gray-700",children:[e.jsx("p",{className:"text-sm text-gray-400 mb-2",children:"Install the SDK:"}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsxs("code",{className:"flex-1 px-3 py-2 bg-gray-900 rounded text-cyan-400 text-sm font-mono",children:[a==="python"&&"pip install heroforge",a==="javascript"&&"npm install heroforge",a==="go"&&"go get github.com/heroforge/heroforge-go",a==="bash"&&"# No installation required - use cURL directly"]}),e.jsx("button",{onClick:()=>p(a==="python"?"pip install heroforge":a==="javascript"?"npm install heroforge":a==="go"?"go get github.com/heroforge/heroforge-go":"","install"),className:"p-2 bg-gray-600 hover:bg-gray-500 rounded text-gray-300",children:m==="install"?e.jsx(y,{className:"w-4 h-4 text-green-500"}):e.jsx(u,{className:"w-4 h-4"})})]})]})]}),e.jsxs("div",{className:"grid md:grid-cols-3 gap-6",children:[e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(R,{className:"w-8 h-8 text-amber-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"Rate Limiting"}),e.jsx("p",{className:"text-gray-400 text-sm mb-4",children:"Free tier: 100 requests/hour. Pro: 1,000/hour. Enterprise: Unlimited."}),e.jsx("a",{href:"#",className:"text-cyan-400 text-sm hover:underline",children:"View limits →"})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(H,{className:"w-8 h-8 text-green-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"Authentication"}),e.jsx("p",{className:"text-gray-400 text-sm mb-4",children:"API keys with granular scopes. OAuth 2.0 for user-context operations."}),e.jsx("a",{href:"#",className:"text-cyan-400 text-sm hover:underline",children:"Auth guide →"})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(D,{className:"w-8 h-8 text-purple-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"Versioning"}),e.jsx("p",{className:"text-gray-400 text-sm mb-4",children:"Current version: v1. We maintain backward compatibility for 12 months."}),e.jsx("a",{href:"#",className:"text-cyan-400 text-sm hover:underline",children:"Changelog →"})]})]})]}),r==="sdk"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"text-2xl font-bold text-white mb-2",children:"Official SDKs"}),e.jsx("p",{className:"text-gray-400",children:"Native libraries for popular programming languages"})]}),e.jsxs("div",{className:"grid md:grid-cols-2 gap-6",children:[e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsxs("div",{className:"p-6 border-b border-gray-700",children:[e.jsxs("div",{className:"flex items-center gap-3 mb-4",children:[e.jsx("div",{className:"w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center",children:e.jsx(S,{className:"w-6 h-6 text-blue-500"})}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-semibold text-white",children:"Python SDK"}),e.jsx("p",{className:"text-sm text-gray-400",children:"heroforge-python"})]})]}),e.jsxs("div",{className:"flex items-center gap-4 text-sm",children:[e.jsx("span",{className:"text-gray-400",children:"v2.1.0"}),e.jsx("span",{className:"text-green-400",children:"● Stable"}),e.jsx("span",{className:"text-gray-400",children:"Python 3.8+"})]})]}),e.jsx("div",{className:"p-4 bg-gray-900",children:e.jsx("code",{className:"text-cyan-400 text-sm",children:"pip install heroforge"})}),e.jsxs("div",{className:"p-4 flex gap-3",children:[e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(l,{className:"w-4 h-4"})," GitHub"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(o,{className:"w-4 h-4"})," Docs"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(h,{className:"w-4 h-4"})," PyPI"]})]})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsxs("div",{className:"p-6 border-b border-gray-700",children:[e.jsxs("div",{className:"flex items-center gap-3 mb-4",children:[e.jsx("div",{className:"w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center",children:e.jsx(O,{className:"w-6 h-6 text-green-500"})}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-semibold text-white",children:"Node.js SDK"}),e.jsx("p",{className:"text-sm text-gray-400",children:"heroforge"})]})]}),e.jsxs("div",{className:"flex items-center gap-4 text-sm",children:[e.jsx("span",{className:"text-gray-400",children:"v2.0.3"}),e.jsx("span",{className:"text-green-400",children:"● Stable"}),e.jsx("span",{className:"text-gray-400",children:"Node 18+"})]})]}),e.jsx("div",{className:"p-4 bg-gray-900",children:e.jsx("code",{className:"text-cyan-400 text-sm",children:"npm install heroforge"})}),e.jsxs("div",{className:"p-4 flex gap-3",children:[e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(l,{className:"w-4 h-4"})," GitHub"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(o,{className:"w-4 h-4"})," Docs"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(h,{className:"w-4 h-4"})," npm"]})]})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsxs("div",{className:"p-6 border-b border-gray-700",children:[e.jsxs("div",{className:"flex items-center gap-3 mb-4",children:[e.jsx("div",{className:"w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center",children:e.jsx(F,{className:"w-6 h-6 text-cyan-500"})}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-semibold text-white",children:"Go SDK"}),e.jsx("p",{className:"text-sm text-gray-400",children:"heroforge-go"})]})]}),e.jsxs("div",{className:"flex items-center gap-4 text-sm",children:[e.jsx("span",{className:"text-gray-400",children:"v1.5.0"}),e.jsx("span",{className:"text-green-400",children:"● Stable"}),e.jsx("span",{className:"text-gray-400",children:"Go 1.21+"})]})]}),e.jsx("div",{className:"p-4 bg-gray-900",children:e.jsx("code",{className:"text-cyan-400 text-sm",children:"go get github.com/heroforge/heroforge-go"})}),e.jsxs("div",{className:"p-4 flex gap-3",children:[e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(l,{className:"w-4 h-4"})," GitHub"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(o,{className:"w-4 h-4"})," Docs"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(h,{className:"w-4 h-4"})," pkg.go.dev"]})]})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsxs("div",{className:"p-6 border-b border-gray-700",children:[e.jsxs("div",{className:"flex items-center gap-3 mb-4",children:[e.jsx("div",{className:"w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center",children:e.jsx(f,{className:"w-6 h-6 text-purple-500"})}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-semibold text-white",children:"CLI Tool"}),e.jsx("p",{className:"text-sm text-gray-400",children:"heroforge-cli"})]})]}),e.jsxs("div",{className:"flex items-center gap-4 text-sm",children:[e.jsx("span",{className:"text-gray-400",children:"v3.2.1"}),e.jsx("span",{className:"text-green-400",children:"● Stable"}),e.jsx("span",{className:"text-gray-400",children:"Linux, macOS, Windows"})]})]}),e.jsx("div",{className:"p-4 bg-gray-900",children:e.jsx("code",{className:"text-cyan-400 text-sm",children:"brew install heroforge/tap/heroforge"})}),e.jsxs("div",{className:"p-4 flex gap-3",children:[e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(l,{className:"w-4 h-4"})," GitHub"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(o,{className:"w-4 h-4"})," Docs"]}),e.jsxs("a",{href:"#",className:"flex items-center gap-1 text-sm text-gray-400 hover:text-white",children:[e.jsx(K,{className:"w-4 h-4"})," Releases"]})]})]})]})]}),r==="api"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"text-2xl font-bold text-white mb-2",children:"REST API Reference"}),e.jsxs("p",{className:"text-gray-400",children:["Base URL: ",e.jsx("code",{className:"text-cyan-400",children:"https://api.heroforge.io/v1"})]})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsx("div",{className:"p-4 border-b border-gray-700",children:e.jsx("h3",{className:"font-semibold text-white",children:"Endpoints"})}),e.jsx("div",{className:"divide-y divide-gray-700",children:[{method:"GET",path:"/scans",description:"List all scans"},{method:"POST",path:"/scans",description:"Create a new scan"},{method:"GET",path:"/scans/{id}",description:"Get scan details"},{method:"DELETE",path:"/scans/{id}",description:"Delete a scan"},{method:"GET",path:"/scans/{id}/vulnerabilities",description:"Get scan vulnerabilities"},{method:"GET",path:"/scans/{id}/report",description:"Generate/download report"},{method:"GET",path:"/assets",description:"List all assets"},{method:"POST",path:"/assets",description:"Create an asset"},{method:"GET",path:"/vulnerabilities",description:"List all vulnerabilities"},{method:"PATCH",path:"/vulnerabilities/{id}",description:"Update vulnerability status"}].map((s,t)=>e.jsxs("div",{className:"p-4 flex items-center gap-4 hover:bg-gray-700/50",children:[e.jsx("span",{className:`px-2 py-1 rounded text-xs font-mono font-bold ${s.method==="GET"?"bg-green-500/20 text-green-400":s.method==="POST"?"bg-blue-500/20 text-blue-400":s.method==="PATCH"?"bg-amber-500/20 text-amber-400":"bg-red-500/20 text-red-400"}`,children:s.method}),e.jsx("code",{className:"text-gray-300 font-mono text-sm",children:s.path}),e.jsx("span",{className:"text-gray-500 text-sm ml-auto",children:s.description})]},t))}),e.jsx("div",{className:"p-4 bg-gray-700/50 border-t border-gray-700",children:e.jsxs(d,{to:"/docs/api",className:"text-cyan-400 text-sm hover:underline flex items-center gap-1",children:["View full API documentation ",e.jsx(h,{className:"w-4 h-4"})]})})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 p-6",children:[e.jsx("h3",{className:"font-semibold text-white mb-4",children:"Authentication"}),e.jsx("p",{className:"text-gray-400 mb-4",children:"Include your API key in the Authorization header:"}),e.jsx("div",{className:"bg-gray-900 rounded-lg p-4",children:e.jsxs("code",{className:"text-gray-300",children:["Authorization: Bearer ",e.jsx("span",{className:"text-cyan-400",children:"hf_your_api_key"})]})})]})]}),r==="cicd"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"text-2xl font-bold text-white mb-2",children:"CI/CD Integrations"}),e.jsx("p",{className:"text-gray-400",children:"Integrate security scanning into your development pipeline"})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsx("div",{className:"border-b border-gray-700",children:e.jsx("div",{className:"flex gap-1 px-4 pt-2",children:[{id:"github",label:"GitHub Actions",icon:e.jsx(l,{className:"w-4 h-4"})},{id:"gitlab",label:"GitLab CI",icon:e.jsx(b,{className:"w-4 h-4"})},{id:"jenkins",label:"Jenkins",icon:e.jsx(L,{className:"w-4 h-4"})},{id:"azure",label:"Azure DevOps",icon:e.jsx($,{className:"w-4 h-4"})}].map(s=>e.jsxs("button",{onClick:()=>E(s.id),className:`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${n===s.id?"bg-gray-900 text-cyan-400":"text-gray-400 hover:text-white"}`,children:[s.icon,s.label]},s.id))})}),e.jsxs("div",{className:"relative",children:[e.jsx("button",{onClick:()=>p(_[n],`cicd-${n}`),className:"absolute top-4 right-4 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-400 hover:text-white",children:m===`cicd-${n}`?e.jsx(y,{className:"w-4 h-4 text-green-500"}):e.jsx(u,{className:"w-4 h-4"})}),e.jsx("pre",{className:"p-6 bg-gray-900 text-gray-300 overflow-x-auto text-sm",children:e.jsx("code",{children:_[n]})})]})]}),e.jsxs("div",{className:"grid md:grid-cols-3 gap-6",children:[e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(q,{className:"w-8 h-8 text-red-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"Fail on Severity"}),e.jsx("p",{className:"text-gray-400 text-sm",children:"Configure your pipeline to fail builds when critical or high severity vulnerabilities are found."})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(S,{className:"w-8 h-8 text-cyan-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"SARIF Export"}),e.jsx("p",{className:"text-gray-400 text-sm",children:"Export results in SARIF format for GitHub Security tab integration."})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx(z,{className:"w-8 h-8 text-green-500 mb-4"}),e.jsx("h3",{className:"text-lg font-semibold text-white mb-2",children:"PR Comments"}),e.jsx("p",{className:"text-gray-400 text-sm",children:"Automatically comment on pull requests with scan results summary."})]})]})]}),r==="webhooks"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"text-2xl font-bold text-white mb-2",children:"Webhooks"}),e.jsx("p",{className:"text-gray-400",children:"Receive real-time notifications for scan events"})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsx("div",{className:"p-4 border-b border-gray-700",children:e.jsx("h3",{className:"font-semibold text-white",children:"Available Events"})}),e.jsx("div",{className:"divide-y divide-gray-700",children:Y.map((s,t)=>e.jsxs("div",{className:"p-4 flex items-center gap-4",children:[e.jsx("code",{className:"text-cyan-400 font-mono text-sm bg-gray-900 px-2 py-1 rounded",children:s.event}),e.jsx("span",{className:"text-gray-400 text-sm",children:s.description})]},t))})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:[e.jsx("div",{className:"p-4 border-b border-gray-700",children:e.jsx("h3",{className:"font-semibold text-white",children:"Example Payload"})}),e.jsx("pre",{className:"p-6 bg-gray-900 text-gray-300 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "event": "vulnerability.critical",
  "timestamp": "2026-01-20T15:30:00Z",
  "data": {
    "scan_id": "scan_abc123",
    "vulnerability": {
      "id": "vuln_xyz789",
      "cve": "CVE-2026-1234",
      "title": "Remote Code Execution in Example Service",
      "severity": "critical",
      "cvss": 9.8,
      "affected_asset": "192.168.1.100",
      "port": 443
    }
  },
  "signature": "sha256=..."
}`})})]}),e.jsxs("div",{className:"bg-gray-800 rounded-xl p-6 border border-gray-700",children:[e.jsx("h3",{className:"font-semibold text-white mb-4",children:"Webhook Security"}),e.jsxs("p",{className:"text-gray-400 mb-4",children:["All webhooks include an HMAC-SHA256 signature in the ",e.jsx("code",{className:"text-cyan-400",children:"X-HeroForge-Signature"})," header. Verify this signature to ensure the webhook is authentic."]}),e.jsx("pre",{className:"p-4 bg-gray-900 rounded-lg text-gray-300 text-sm",children:e.jsx("code",{children:`import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)`})})]})]}),r==="keys"&&e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"text-2xl font-bold text-white mb-2",children:"API Keys"}),e.jsx("p",{className:"text-gray-400",children:"Manage your API keys and their permissions"})]}),e.jsxs("button",{onClick:()=>T(!0),className:"flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg",children:[e.jsx(B,{className:"w-5 h-5"}),"Create New Key"]})]}),e.jsx("div",{className:"bg-gray-800 rounded-xl border border-gray-700 overflow-hidden",children:e.jsx("div",{className:"divide-y divide-gray-700",children:J.map(s=>e.jsxs("div",{className:"p-6",children:[e.jsxs("div",{className:"flex items-start justify-between mb-4",children:[e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-semibold text-white",children:s.name}),e.jsxs("div",{className:"flex items-center gap-2 mt-1",children:[e.jsx("code",{className:"text-gray-400 font-mono text-sm",children:g===s.id?`${s.prefix}${"x".repeat(32)}`:`${s.prefix}${"•".repeat(32)}`}),e.jsx("button",{onClick:()=>P(g===s.id?null:s.id),className:"text-gray-500 hover:text-white",children:g===s.id?e.jsx(U,{className:"w-4 h-4"}):e.jsx(W,{className:"w-4 h-4"})})]})]}),e.jsx("button",{className:"text-red-400 hover:text-red-300 p-2",children:e.jsx(M,{className:"w-5 h-5"})})]}),e.jsx("div",{className:"flex flex-wrap gap-2 mb-4",children:s.scopes.map(t=>e.jsx("span",{className:"px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs",children:t},t))}),e.jsxs("div",{className:"flex items-center gap-6 text-sm text-gray-500",children:[e.jsxs("span",{children:["Created: ",new Date(s.created).toLocaleDateString()]}),e.jsxs("span",{children:["Last used: ",s.lastUsed?new Date(s.lastUsed).toLocaleDateString():"Never"]})]})]},s.id))})}),e.jsxs("div",{className:"bg-gray-800 rounded-xl border border-gray-700 p-6",children:[e.jsx("h3",{className:"font-semibold text-white mb-4",children:"Available Scopes"}),e.jsx("div",{className:"grid md:grid-cols-2 gap-4",children:[{scope:"scans:read",description:"Read scan results and history"},{scope:"scans:write",description:"Create and manage scans"},{scope:"assets:read",description:"View asset inventory"},{scope:"assets:write",description:"Create and manage assets"},{scope:"reports:read",description:"Generate and download reports"},{scope:"vulnerabilities:read",description:"View vulnerability details"},{scope:"vulnerabilities:write",description:"Update vulnerability status"},{scope:"webhooks:manage",description:"Manage webhook subscriptions"}].map(s=>e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx("code",{className:"text-cyan-400 font-mono text-sm",children:s.scope}),e.jsx("span",{className:"text-gray-400 text-sm",children:s.description})]},s.scope))})]})]})]}),e.jsx("footer",{className:"bg-gray-800 border-t border-gray-700 py-8 mt-16",children:e.jsx("div",{className:"max-w-7xl mx-auto px-4",children:e.jsxs("div",{className:"flex flex-wrap items-center justify-between gap-4",children:[e.jsxs("div",{className:"flex items-center gap-6 text-sm text-gray-400",children:[e.jsx("a",{href:"#",className:"hover:text-white",children:"API Status"}),e.jsx("a",{href:"#",className:"hover:text-white",children:"Changelog"}),e.jsx("a",{href:"#",className:"hover:text-white",children:"Support"})]}),e.jsx("p",{className:"text-gray-500 text-sm",children:"© 2026 HeroForge. All rights reserved."})]})})})]})}export{se as default};
