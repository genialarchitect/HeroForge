import{j as e}from"./vendor-state-DdX3IZQk.js";import{r as a}from"./vendor-react-Da1CiaFS.js";import{B as d,Q as p,P as $,aQ as u,j as G,a9 as H,S as D,bt as F,aA as B,aM as A,y as z,as as y,aF as M,aG as L}from"./vendor-ui-Cfxa9o3E.js";import{d as U}from"./index-C3P2Oms8.js";import"./vendor-charts-ed8SE4MW.js";const n={getPipelines:async()=>[{id:"1",name:"Main Build",platform:"github_actions",repository_url:"https://github.com/org/repo",enabled:!0,last_run_at:new Date().toISOString(),last_run_status:"passed",created_at:new Date().toISOString()},{id:"2",name:"Security Scan",platform:"gitlab_ci",repository_url:"https://gitlab.com/org/repo",enabled:!0,last_run_at:new Date().toISOString(),last_run_status:"failed",created_at:new Date().toISOString()}],getRuns:async t=>[{id:"1",pipeline_id:"1",branch:"main",commit_sha:"abc1234",trigger_type:"push",status:"completed",gate_status:"passed",findings_new:0,findings_fixed:3,findings_total:12,duration_seconds:145,started_at:new Date().toISOString(),completed_at:new Date().toISOString()},{id:"2",pipeline_id:"1",branch:"feature/auth",commit_sha:"def5678",trigger_type:"pr",pr_number:42,status:"completed",gate_status:"failed",findings_new:5,findings_fixed:0,findings_total:17,duration_seconds:178,started_at:new Date().toISOString(),completed_at:new Date().toISOString()},{id:"3",pipeline_id:"2",branch:"develop",commit_sha:"ghi9012",trigger_type:"schedule",status:"running",findings_new:0,findings_fixed:0,findings_total:0,started_at:new Date().toISOString()}],getPolicies:async()=>[{id:"1",name:"Block Critical",description:"Block merges when critical vulnerabilities found",policy_type:"block_merge",severity_threshold:"critical",block_on_critical:!0,enabled:!0},{id:"2",name:"Max 5 New Findings",description:"Block if more than 5 new findings",policy_type:"quality_gate",max_new_findings:5,block_on_critical:!0,enabled:!0}],getTemplate:async t=>({github_actions:`name: Genial Architect Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        env:
          HEROFORGE_URL: \${{ secrets.HEROFORGE_URL }}
          HEROFORGE_TOKEN: \${{ secrets.HEROFORGE_TOKEN }}
        run: |
          curl -X POST "$HEROFORGE_URL/api/cicd/webhook/github_actions" \\
            -H "Authorization: Bearer $HEROFORGE_TOKEN" \\
            -H "Content-Type: application/json" \\
            -d '{
              "repository": "\${{ github.repository }}",
              "branch": "\${{ github.ref_name }}",
              "commit": "\${{ github.sha }}",
              "pr_number": \${{ github.event.pull_request.number || 'null' }}
            }'`,gitlab_ci:`stages:
  - security

security-scan:
  stage: security
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "$HEROFORGE_URL/api/cicd/webhook/gitlab_ci" \\
        -H "Authorization: Bearer $HEROFORGE_TOKEN" \\
        -H "Content-Type: application/json" \\
        -d "{
          \\"repository\\": \\"$CI_PROJECT_PATH\\",
          \\"branch\\": \\"$CI_COMMIT_REF_NAME\\",
          \\"commit\\": \\"$CI_COMMIT_SHA\\",
          \\"mr_iid\\": \\"$CI_MERGE_REQUEST_IID\\"
        }"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH'`,jenkins:`pipeline {
    agent any

    environment {
        HEROFORGE_URL = credentials('heroforge-url')
        HEROFORGE_TOKEN = credentials('heroforge-token')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -X POST "$HEROFORGE_URL/api/cicd/webhook/jenkins" \\
                        -H "Authorization: Bearer $HEROFORGE_TOKEN" \\
                        -H "Content-Type: application/json" \\
                        -d "{
                            \\"repository\\": \\"$GIT_URL\\",
                            \\"branch\\": \\"$GIT_BRANCH\\",
                            \\"commit\\": \\"$GIT_COMMIT\\",
                            \\"build_number\\": \\"$BUILD_NUMBER\\"
                        }"
                '''
            }
        }
    }
}`,azure_devops:`trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Security
    jobs:
      - job: Scan
        steps:
          - script: |
              curl -X POST "$(HEROFORGE_URL)/api/cicd/webhook/azure_devops" \\
                -H "Authorization: Bearer $(HEROFORGE_TOKEN)" \\
                -H "Content-Type: application/json" \\
                -d '{
                  "repository": "$(Build.Repository.Name)",
                  "branch": "$(Build.SourceBranchName)",
                  "commit": "$(Build.SourceVersion)",
                  "pr_id": "$(System.PullRequest.PullRequestId)"
                }'
            displayName: 'Run Genial Architect Scan'`})[t]||"",getIdeSettings:async()=>({scan_on_save:!0,scan_on_open:!1,show_inline_hints:!0,severity_filter:["critical","high","medium"],excluded_paths:["node_modules","target","dist"],custom_rules_enabled:!0})},V=()=>{const[t,x]=a.useState("pipelines"),[j,_]=a.useState([]),[b,N]=a.useState([]),[f,v]=a.useState([]),[i,w]=a.useState(null),[r,S]=a.useState("github_actions"),[o,O]=a.useState(""),[E,m]=a.useState(!0);a.useEffect(()=>{R()},[]),a.useEffect(()=>{t==="templates"&&I(r)},[r,t]);const R=async()=>{try{m(!0);const[s,c,k,P]=await Promise.all([n.getPipelines(),n.getRuns(),n.getPolicies(),n.getIdeSettings()]);_(s),N(c),v(k),w(P)}catch{d.error("Failed to load CI/CD data")}finally{m(!1)}},I=async s=>{try{const c=await n.getTemplate(s);O(c)}catch{d.error("Failed to load template")}},C=()=>{navigator.clipboard.writeText(o),d.success("Template copied to clipboard")},h=s=>{switch(s){case"github_actions":return"🐙";case"gitlab_ci":return"🦊";case"jenkins":return"🔧";case"azure_devops":return"☁️";default:return"📦"}},l=s=>{switch(s){case"github_actions":return"GitHub Actions";case"gitlab_ci":return"GitLab CI";case"jenkins":return"Jenkins";case"azure_devops":return"Azure DevOps";default:return s}},g=s=>{switch(s){case"completed":case"passed":return e.jsx(L,{className:"h-5 w-5 text-green-400"});case"failed":return e.jsx(M,{className:"h-5 w-5 text-red-400"});case"running":return e.jsx(u,{className:"h-5 w-5 text-cyan-400 animate-spin"});case"pending":return e.jsx(y,{className:"h-5 w-5 text-yellow-400"});default:return e.jsx(y,{className:"h-5 w-5 text-gray-400"})}},T=s=>{if(!s)return null;switch(s){case"passed":return e.jsx("span",{className:"px-2 py-1 bg-green-600 text-white text-xs rounded",children:"Gate Passed"});case"failed":return e.jsx("span",{className:"px-2 py-1 bg-red-600 text-white text-xs rounded",children:"Gate Failed"});case"warning":return e.jsx("span",{className:"px-2 py-1 bg-yellow-600 text-white text-xs rounded",children:"Warning"});default:return null}};return e.jsx(U,{children:e.jsxs("div",{className:"p-6",children:[e.jsxs("div",{className:"flex items-center justify-between mb-6",children:[e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx(p,{className:"h-8 w-8 text-cyan-400"}),e.jsxs("div",{children:[e.jsx("h1",{className:"text-2xl font-bold text-white",children:"CI/CD Integration"}),e.jsx("p",{className:"text-gray-400",children:"Pipeline security and IDE integration"})]})]}),e.jsxs("button",{className:"flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500",children:[e.jsx($,{className:"h-4 w-4"}),"Add Pipeline"]})]}),e.jsx("div",{className:"flex gap-1 mb-6 border-b border-gray-700",children:["pipelines","runs","policies","templates","ide"].map(s=>e.jsx("button",{onClick:()=>x(s),className:`px-4 py-2 font-medium capitalize ${t===s?"text-cyan-400 border-b-2 border-cyan-400":"text-gray-400 hover:text-white"}`,children:s==="ide"?"IDE Settings":s},s))}),E?e.jsx("div",{className:"flex items-center justify-center py-12",children:e.jsx(u,{className:"h-8 w-8 text-cyan-400 animate-spin"})}):e.jsxs(e.Fragment,{children:[t==="pipelines"&&e.jsx("div",{className:"grid gap-4",children:j.map(s=>e.jsx("div",{className:"bg-gray-800 rounded-lg p-4",children:e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx("span",{className:"text-2xl",children:h(s.platform)}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-white",children:s.name}),e.jsxs("p",{className:"text-gray-400 text-sm",children:[l(s.platform)," • ",s.repository_url]})]})]}),e.jsxs("div",{className:"flex items-center gap-4",children:[s.last_run_status&&g(s.last_run_status),e.jsxs("label",{className:"flex items-center gap-2",children:[e.jsx("input",{type:"checkbox",checked:s.enabled,className:"rounded border-gray-600 bg-gray-700 text-cyan-500",readOnly:!0}),e.jsx("span",{className:"text-gray-400 text-sm",children:"Enabled"})]}),e.jsx("button",{className:"p-2 hover:bg-gray-700 rounded",children:e.jsx(G,{className:"h-4 w-4 text-gray-400"})})]})]})},s.id))}),t==="runs"&&e.jsx("div",{className:"bg-gray-800 rounded-lg overflow-hidden",children:e.jsxs("table",{className:"w-full",children:[e.jsx("thead",{className:"bg-gray-700",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Status"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Branch"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Commit"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Trigger"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Findings"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Gate"}),e.jsx("th",{className:"px-4 py-3 text-left text-gray-300",children:"Duration"})]})}),e.jsx("tbody",{children:b.map(s=>e.jsxs("tr",{className:"border-t border-gray-700 hover:bg-gray-750",children:[e.jsx("td",{className:"px-4 py-3",children:e.jsxs("div",{className:"flex items-center gap-2",children:[g(s.status),e.jsx("span",{className:"text-white capitalize",children:s.status})]})}),e.jsx("td",{className:"px-4 py-3",children:e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx(p,{className:"h-4 w-4 text-gray-400"}),e.jsx("span",{className:"text-white",children:s.branch})]})}),e.jsx("td",{className:"px-4 py-3",children:e.jsx("code",{className:"text-gray-300 bg-gray-700 px-2 py-1 rounded text-sm",children:s.commit_sha.substring(0,7)})}),e.jsx("td",{className:"px-4 py-3",children:e.jsxs("div",{className:"flex items-center gap-2",children:[s.trigger_type==="pr"&&e.jsx(H,{className:"h-4 w-4 text-cyan-400"}),e.jsx("span",{className:"text-gray-300 capitalize",children:s.trigger_type}),s.pr_number&&e.jsxs("span",{className:"text-gray-400",children:["#",s.pr_number]})]})}),e.jsx("td",{className:"px-4 py-3",children:e.jsxs("div",{className:"flex items-center gap-2 text-sm",children:[s.findings_new>0&&e.jsxs("span",{className:"text-red-400",children:["+",s.findings_new]}),s.findings_fixed>0&&e.jsxs("span",{className:"text-green-400",children:["-",s.findings_fixed]}),e.jsxs("span",{className:"text-gray-400",children:["(",s.findings_total," total)"]})]})}),e.jsx("td",{className:"px-4 py-3",children:T(s.gate_status)}),e.jsx("td",{className:"px-4 py-3 text-gray-300",children:s.duration_seconds?`${s.duration_seconds}s`:"-"})]},s.id))})]})}),t==="policies"&&e.jsx("div",{className:"grid gap-4",children:f.map(s=>e.jsxs("div",{className:"bg-gray-800 rounded-lg p-4",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx(D,{className:"h-6 w-6 text-cyan-400"}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-white",children:s.name}),e.jsx("p",{className:"text-gray-400 text-sm",children:s.description})]})]}),e.jsxs("div",{className:"flex items-center gap-4",children:[e.jsx("span",{className:`px-2 py-1 rounded text-xs ${s.enabled?"bg-green-600 text-white":"bg-gray-600 text-gray-300"}`,children:s.enabled?"Active":"Inactive"}),e.jsx("button",{className:"p-2 hover:bg-gray-700 rounded",children:e.jsx(F,{className:"h-4 w-4 text-gray-400"})})]})]}),e.jsxs("div",{className:"mt-4 flex flex-wrap gap-4 text-sm",children:[s.severity_threshold&&e.jsxs("div",{className:"text-gray-400",children:["Threshold: ",e.jsx("span",{className:"text-white capitalize",children:s.severity_threshold})]}),s.max_new_findings&&e.jsxs("div",{className:"text-gray-400",children:["Max New Findings: ",e.jsx("span",{className:"text-white",children:s.max_new_findings})]}),s.block_on_critical&&e.jsx("div",{className:"text-red-400",children:"Block on Critical"})]})]},s.id))}),t==="templates"&&e.jsxs("div",{children:[e.jsx("div",{className:"flex gap-2 mb-4",children:["github_actions","gitlab_ci","jenkins","azure_devops"].map(s=>e.jsxs("button",{onClick:()=>S(s),className:`flex items-center gap-2 px-4 py-2 rounded-lg ${r===s?"bg-cyan-600 text-white":"bg-gray-700 text-gray-300 hover:bg-gray-600"}`,children:[e.jsx("span",{children:h(s)}),e.jsx("span",{children:l(s)})]},s))}),e.jsxs("div",{className:"bg-gray-800 rounded-lg p-4",children:[e.jsxs("div",{className:"flex items-center justify-between mb-4",children:[e.jsxs("h3",{className:"text-lg font-medium text-white",children:[l(r)," Template"]}),e.jsxs("div",{className:"flex gap-2",children:[e.jsxs("button",{onClick:C,className:"flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600",children:[e.jsx(B,{className:"h-4 w-4"}),"Copy"]}),e.jsxs("button",{className:"flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600",children:[e.jsx(A,{className:"h-4 w-4"}),"Download"]})]})]}),e.jsx("pre",{className:"bg-gray-900 rounded p-4 overflow-x-auto text-sm text-gray-300",children:e.jsx("code",{children:o})})]})]}),t==="ide"&&i&&e.jsxs("div",{className:"max-w-2xl",children:[e.jsxs("div",{className:"bg-gray-800 rounded-lg p-6",children:[e.jsxs("h3",{className:"text-lg font-medium text-white mb-6 flex items-center gap-2",children:[e.jsx(z,{className:"h-5 w-5 text-cyan-400"}),"IDE Integration Settings"]}),e.jsxs("div",{className:"space-y-6",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{children:[e.jsx("div",{className:"text-white",children:"Scan on Save"}),e.jsx("div",{className:"text-gray-400 text-sm",children:"Run security scan when files are saved"})]}),e.jsx("input",{type:"checkbox",checked:i.scan_on_save,className:"rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5",readOnly:!0})]}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{children:[e.jsx("div",{className:"text-white",children:"Scan on Open"}),e.jsx("div",{className:"text-gray-400 text-sm",children:"Run security scan when files are opened"})]}),e.jsx("input",{type:"checkbox",checked:i.scan_on_open,className:"rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5",readOnly:!0})]}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{children:[e.jsx("div",{className:"text-white",children:"Show Inline Hints"}),e.jsx("div",{className:"text-gray-400 text-sm",children:"Display security findings inline in code"})]}),e.jsx("input",{type:"checkbox",checked:i.show_inline_hints,className:"rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5",readOnly:!0})]}),e.jsxs("div",{children:[e.jsx("div",{className:"text-white mb-2",children:"Severity Filter"}),e.jsx("div",{className:"flex flex-wrap gap-2",children:["critical","high","medium","low"].map(s=>e.jsxs("label",{className:"flex items-center gap-2 bg-gray-700 px-3 py-2 rounded",children:[e.jsx("input",{type:"checkbox",checked:i.severity_filter.includes(s),className:"rounded border-gray-600 bg-gray-600 text-cyan-500",readOnly:!0}),e.jsx("span",{className:"text-gray-300 capitalize",children:s})]},s))})]}),e.jsxs("div",{children:[e.jsx("div",{className:"text-white mb-2",children:"Excluded Paths"}),e.jsx("div",{className:"flex flex-wrap gap-2",children:i.excluded_paths.map(s=>e.jsx("span",{className:"bg-gray-700 text-gray-300 px-3 py-1 rounded-full text-sm",children:s},s))})]}),e.jsx("div",{className:"pt-4 border-t border-gray-700",children:e.jsx("button",{className:"px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500",children:"Save Settings"})})]})]}),e.jsxs("div",{className:"mt-6 bg-gray-800 rounded-lg p-6",children:[e.jsx("h3",{className:"text-lg font-medium text-white mb-4",children:"IDE Extensions"}),e.jsxs("div",{className:"grid gap-4",children:[e.jsxs("a",{href:"#",className:"flex items-center gap-4 bg-gray-700 p-4 rounded-lg hover:bg-gray-600",children:[e.jsx("div",{className:"text-3xl",children:"📘"}),e.jsxs("div",{children:[e.jsx("div",{className:"text-white font-medium",children:"VS Code Extension"}),e.jsx("div",{className:"text-gray-400 text-sm",children:"Real-time security scanning for Visual Studio Code"})]})]}),e.jsxs("a",{href:"#",className:"flex items-center gap-4 bg-gray-700 p-4 rounded-lg hover:bg-gray-600",children:[e.jsx("div",{className:"text-3xl",children:"🧠"}),e.jsxs("div",{children:[e.jsx("div",{className:"text-white font-medium",children:"JetBrains Plugin"}),e.jsx("div",{className:"text-gray-400 text-sm",children:"Security scanning for IntelliJ, PyCharm, WebStorm"})]})]})]})]})]})]})]})})};export{V as default};
