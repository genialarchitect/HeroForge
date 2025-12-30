//! CI/CD Workflow Templates
//!
//! Generates security workflow templates for various CI/CD platforms.

use super::types::{CiCdPlatformType, GenerateTemplateRequest, GeneratedTemplate};

/// Template generator for CI/CD security workflows
pub struct TemplateGenerator;

impl TemplateGenerator {
    /// Generate a workflow template for the specified platform
    pub fn generate(request: &GenerateTemplateRequest) -> Result<GeneratedTemplate, String> {
        let platform: CiCdPlatformType = request.platform.parse()?;

        match platform {
            CiCdPlatformType::GithubActions => Self::generate_github_actions(request),
            CiCdPlatformType::GitlabCi => Self::generate_gitlab_ci(request),
            CiCdPlatformType::Jenkins => Self::generate_jenkins(request),
            CiCdPlatformType::AzureDevops => Self::generate_azure_devops(request),
        }
    }

    /// Generate GitHub Actions workflow
    fn generate_github_actions(request: &GenerateTemplateRequest) -> Result<GeneratedTemplate, String> {
        let branch = request.branch.as_deref().unwrap_or("main");
        let schedule = request.schedule.as_deref().unwrap_or("0 0 * * 0");
        let quality_gate = request.quality_gate_enabled.unwrap_or(true);

        let mut content = format!(
            r#"name: Genial Architect Scan

on:
  push:
    branches: [ {branch}, develop ]
  pull_request:
    branches: [ {branch} ]
  schedule:
    - cron: '{schedule}'  # Scheduled scan
  workflow_dispatch:  # Manual trigger

env:
  HEROFORGE_URL: ${{{{ secrets.HEROFORGE_URL }}}}
  HEROFORGE_TOKEN: ${{{{ secrets.HEROFORGE_TOKEN }}}}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Genial Architect Scan
        id: heroforge-scan
        run: |
          RESPONSE=$(curl -s -X POST "${{{{ env.HEROFORGE_URL }}}}/api/cicd/webhook/github_actions" \
            -H "Authorization: Bearer ${{{{ env.HEROFORGE_TOKEN }}}}" \
            -H "Content-Type: application/json" \
            -H "X-GitHub-Event: ${{{{ github.event_name }}}}" \
            -d '{{
              "repository": "${{{{ github.repository }}}}",
              "commit": "${{{{ github.sha }}}}",
              "branch": "${{{{ github.ref_name }}}}",
              "pr_number": "${{{{ github.event.pull_request.number }}}}",
              "trigger": "${{{{ github.event_name }}}}"
            }}')

          echo "response=$RESPONSE" >> $GITHUB_OUTPUT
          SCAN_ID=$(echo $RESPONSE | jq -r '.scan_id // .id // empty')
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT
"#,
            branch = branch,
            schedule = schedule
        );

        if quality_gate {
            content.push_str(
                r#"
      - name: Wait for Scan Completion
        id: wait-scan
        run: |
          SCAN_ID="${{ steps.heroforge-scan.outputs.scan_id }}"
          if [ -z "$SCAN_ID" ]; then
            echo "No scan ID returned, skipping wait"
            exit 0
          fi

          MAX_ATTEMPTS=60
          ATTEMPT=0

          while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
            STATUS=$(curl -s -X GET "${{ env.HEROFORGE_URL }}/api/cicd/runs/$SCAN_ID" \
              -H "Authorization: Bearer ${{ env.HEROFORGE_TOKEN }}" | jq -r '.status // "pending"')

            if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
              echo "Scan completed with status: $STATUS"
              break
            fi

            echo "Waiting for scan to complete... (attempt $((ATTEMPT+1))/$MAX_ATTEMPTS)"
            sleep 10
            ATTEMPT=$((ATTEMPT+1))
          done

      - name: Check Quality Gate
        if: github.event_name == 'pull_request'
        run: |
          SCAN_ID="${{ steps.heroforge-scan.outputs.scan_id }}"
          if [ -z "$SCAN_ID" ]; then
            echo "No scan ID, skipping quality gate check"
            exit 0
          fi

          RESULT=$(curl -s -X GET "${{ env.HEROFORGE_URL }}/api/cicd/runs/$SCAN_ID/gate-status" \
            -H "Authorization: Bearer ${{ env.HEROFORGE_TOKEN }}")

          GATE_STATUS=$(echo $RESULT | jq -r '.status // "unknown"')
          echo "Quality Gate Status: $GATE_STATUS"

          if [ "$GATE_STATUS" = "failed" ]; then
            echo "Quality gate failed!"
            echo "$RESULT" | jq '.failed_conditions // []'
            exit 1
          fi

      - name: Comment on PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const scanId = '${{ steps.heroforge-scan.outputs.scan_id }}';
            if (!scanId) return;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Genial Architect Scan Results\n\nScan ID: \`${scanId}\`\n\nView full results at: ${{ env.HEROFORGE_URL }}/scans/${scanId}`
            });
"#,
            );
        }

        Ok(GeneratedTemplate {
            platform: "github_actions".to_string(),
            content,
            filename: ".github/workflows/heroforge-security.yml".to_string(),
            variables_required: vec!["HEROFORGE_URL".to_string(), "HEROFORGE_TOKEN".to_string()],
            setup_instructions: r#"## Setup Instructions

1. Add the following secrets to your GitHub repository:
   - Go to Settings > Secrets and variables > Actions
   - Add `HEROFORGE_URL`: Your HeroForge instance URL (e.g., https://heroforge.example.com)
   - Add `HEROFORGE_TOKEN`: Your HeroForge API token

2. Create the workflow file:
   - Create `.github/workflows/` directory if it doesn't exist
   - Save this template as `heroforge-security.yml`

3. Commit and push the changes

The workflow will run automatically on:
- Push to main/develop branches
- Pull requests targeting main
- Weekly schedule (configurable)
- Manual trigger via Actions tab
"#
            .to_string(),
        })
    }

    /// Generate GitLab CI workflow
    fn generate_gitlab_ci(request: &GenerateTemplateRequest) -> Result<GeneratedTemplate, String> {
        let quality_gate = request.quality_gate_enabled.unwrap_or(true);
        let schedule = request.schedule.as_deref().unwrap_or("0 0 * * 0");

        let mut content = format!(
            r#"# Genial Architect Scanning Pipeline
# Add to your .gitlab-ci.yml or as a separate include

stages:
  - security

variables:
  HEROFORGE_URL: $HEROFORGE_URL

.heroforge_common: &heroforge_common
  image: curlimages/curl:latest
  before_script:
    - apk add --no-cache jq

heroforge-security-scan:
  <<: *heroforge_common
  stage: security
  script:
    - |
      RESPONSE=$(curl -s -X POST "${{HEROFORGE_URL}}/api/cicd/webhook/gitlab_ci" \
        -H "Authorization: Bearer ${{HEROFORGE_TOKEN}}" \
        -H "Content-Type: application/json" \
        -H "X-Gitlab-Event: ${{CI_PIPELINE_SOURCE}}" \
        -d "{{
          \"project_id\": \"${{CI_PROJECT_ID}}\",
          \"project_path\": \"${{CI_PROJECT_PATH}}\",
          \"commit\": \"${{CI_COMMIT_SHA}}\",
          \"branch\": \"${{CI_COMMIT_REF_NAME}}\",
          \"pipeline_id\": \"${{CI_PIPELINE_ID}}\",
          \"mr_iid\": \"${{CI_MERGE_REQUEST_IID}}\"
        }}")

      echo "Response: $RESPONSE"
      SCAN_ID=$(echo $RESPONSE | jq -r '.scan_id // .id // empty')
      echo "SCAN_ID=$SCAN_ID" >> variables.env
"#
        );

        if quality_gate {
            content.push_str(
                r#"
      # Wait for scan completion
      MAX_ATTEMPTS=60
      ATTEMPT=0

      while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        STATUS=$(curl -s -X GET "${HEROFORGE_URL}/api/cicd/runs/$SCAN_ID" \
          -H "Authorization: Bearer ${HEROFORGE_TOKEN}" | jq -r '.status // "pending"')

        if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
          echo "Scan completed with status: $STATUS"
          break
        fi

        echo "Waiting for scan to complete... (attempt $((ATTEMPT+1))/$MAX_ATTEMPTS)"
        sleep 10
        ATTEMPT=$((ATTEMPT+1))
      done

      # Check quality gate
      GATE_RESULT=$(curl -s -X GET "${HEROFORGE_URL}/api/cicd/runs/$SCAN_ID/gate-status" \
        -H "Authorization: Bearer ${HEROFORGE_TOKEN}")

      GATE_STATUS=$(echo $GATE_RESULT | jq -r '.status // "unknown"')
      echo "Quality Gate Status: $GATE_STATUS"

      if [ "$GATE_STATUS" = "failed" ]; then
        echo "Quality gate failed!"
        echo "$GATE_RESULT" | jq '.failed_conditions // []'
        exit 1
      fi
"#,
            );
        }

        content.push_str(&format!(
            r#"
  artifacts:
    reports:
      dotenv: variables.env
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"

# Scheduled scan job
heroforge-scheduled-scan:
  <<: *heroforge_common
  stage: security
  script:
    - |
      curl -s -X POST "${{HEROFORGE_URL}}/api/cicd/webhook/gitlab_ci" \
        -H "Authorization: Bearer ${{HEROFORGE_TOKEN}}" \
        -H "Content-Type: application/json" \
        -d "{{
          \"project_id\": \"${{CI_PROJECT_ID}}\",
          \"project_path\": \"${{CI_PROJECT_PATH}}\",
          \"commit\": \"${{CI_COMMIT_SHA}}\",
          \"branch\": \"${{CI_COMMIT_REF_NAME}}\",
          \"trigger\": \"schedule\"
        }}"
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  # Configure schedule in GitLab CI/CD > Schedules: {schedule}
"#,
            schedule = schedule
        ));

        Ok(GeneratedTemplate {
            platform: "gitlab_ci".to_string(),
            content,
            filename: ".gitlab-ci.yml".to_string(),
            variables_required: vec!["HEROFORGE_URL".to_string(), "HEROFORGE_TOKEN".to_string()],
            setup_instructions: r#"## Setup Instructions

1. Add CI/CD variables to your GitLab project:
   - Go to Settings > CI/CD > Variables
   - Add `HEROFORGE_URL`: Your HeroForge instance URL
   - Add `HEROFORGE_TOKEN`: Your HeroForge API token (mark as masked)

2. Add the template to your `.gitlab-ci.yml`:
   - Either copy the content directly
   - Or use GitLab includes:
     ```yaml
     include:
       - local: '.gitlab/heroforge-security.yml'
     ```

3. (Optional) Set up scheduled pipelines:
   - Go to CI/CD > Schedules
   - Create a new schedule for weekly scans

The pipeline will run on:
- Merge requests
- Commits to default branch
- Scheduled triggers
- Manual triggers
"#
            .to_string(),
        })
    }

    /// Generate Jenkins pipeline
    fn generate_jenkins(request: &GenerateTemplateRequest) -> Result<GeneratedTemplate, String> {
        let quality_gate = request.quality_gate_enabled.unwrap_or(true);
        let branch = request.branch.as_deref().unwrap_or("main");

        let mut content = format!(
            r#"// Genial Architect Scanning Pipeline
// Save as Jenkinsfile in your repository root

pipeline {{
    agent any

    environment {{
        HEROFORGE_URL = credentials('heroforge-url')
        HEROFORGE_TOKEN = credentials('heroforge-token')
    }}

    triggers {{
        // Poll SCM every 15 minutes
        pollSCM('H/15 * * * *')
        // Weekly full scan
        cron('H 0 * * 0')
    }}

    stages {{
        stage('Security Scan') {{
            steps {{
                script {{
                    def response = httpRequest(
                        url: "${{HEROFORGE_URL}}/api/cicd/webhook/jenkins",
                        httpMode: 'POST',
                        customHeaders: [
                            [name: 'Authorization', value: "Bearer ${{HEROFORGE_TOKEN}}"],
                            [name: 'Content-Type', value: 'application/json']
                        ],
                        requestBody: """{{
                            "job_name": "${{env.JOB_NAME}}",
                            "build_number": "${{env.BUILD_NUMBER}}",
                            "commit": "${{env.GIT_COMMIT ?: 'unknown'}}",
                            "branch": "${{env.GIT_BRANCH ?: '{branch}'}}",
                            "url": "${{env.BUILD_URL}}"
                        }}"""
                    )

                    def result = readJSON text: response.content
                    env.SCAN_ID = result.scan_id ?: result.id
                    echo "Scan ID: ${{env.SCAN_ID}}"
                }}
            }}
        }}
"#,
            branch = branch
        );

        if quality_gate {
            content.push_str(
                r#"
        stage('Wait for Scan') {
            steps {
                script {
                    if (!env.SCAN_ID) {
                        echo "No scan ID, skipping wait"
                        return
                    }

                    def maxAttempts = 60
                    def attempt = 0
                    def status = 'pending'

                    while (attempt < maxAttempts && status == 'pending') {
                        def statusResponse = httpRequest(
                            url: "${HEROFORGE_URL}/api/cicd/runs/${env.SCAN_ID}",
                            httpMode: 'GET',
                            customHeaders: [
                                [name: 'Authorization', value: "Bearer ${HEROFORGE_TOKEN}"]
                            ]
                        )

                        def statusResult = readJSON text: statusResponse.content
                        status = statusResult.status ?: 'pending'

                        if (status == 'completed' || status == 'failed') {
                            echo "Scan completed with status: ${status}"
                            break
                        }

                        echo "Waiting for scan to complete... (attempt ${attempt + 1}/${maxAttempts})"
                        sleep(10)
                        attempt++
                    }
                }
            }
        }

        stage('Quality Gate') {
            when {
                expression { env.CHANGE_ID != null }  // PR builds only
            }
            steps {
                script {
                    if (!env.SCAN_ID) {
                        echo "No scan ID, skipping quality gate"
                        return
                    }

                    def gateResponse = httpRequest(
                        url: "${HEROFORGE_URL}/api/cicd/runs/${env.SCAN_ID}/gate-status",
                        httpMode: 'GET',
                        customHeaders: [
                            [name: 'Authorization', value: "Bearer ${HEROFORGE_TOKEN}"]
                        ]
                    )

                    def gateResult = readJSON text: gateResponse.content
                    def gateStatus = gateResult.status ?: 'unknown'

                    echo "Quality Gate Status: ${gateStatus}"

                    if (gateStatus == 'failed') {
                        error "Quality gate failed! See HeroForge for details."
                    }
                }
            }
        }
"#,
            );
        }

        content.push_str(
            r#"
    }

    post {
        always {
            script {
                if (env.SCAN_ID) {
                    echo "View full scan results at: ${HEROFORGE_URL}/scans/${env.SCAN_ID}"
                }
            }
        }
        failure {
            echo 'Security scan or quality gate failed'
        }
        success {
            echo 'Security scan passed'
        }
    }
}
"#,
        );

        Ok(GeneratedTemplate {
            platform: "jenkins".to_string(),
            content,
            filename: "Jenkinsfile".to_string(),
            variables_required: vec!["heroforge-url".to_string(), "heroforge-token".to_string()],
            setup_instructions: r#"## Setup Instructions

1. Configure Jenkins credentials:
   - Go to Jenkins > Manage Jenkins > Credentials
   - Add a "Secret text" credential with ID `heroforge-url` containing your HeroForge URL
   - Add a "Secret text" credential with ID `heroforge-token` containing your API token

2. Required Jenkins plugins:
   - HTTP Request Plugin (for httpRequest step)
   - Pipeline Utility Steps (for readJSON)

3. Add the Jenkinsfile:
   - Save this template as `Jenkinsfile` in your repository root
   - Or configure pipeline script from SCM

4. Configure the job:
   - Create a "Multibranch Pipeline" or "Pipeline" job
   - Point to your repository

The pipeline will run on:
- SCM changes (polled every 15 minutes)
- Weekly scheduled scan
- Manual triggers
- PR builds (with quality gate)
"#
            .to_string(),
        })
    }

    /// Generate Azure DevOps pipeline
    fn generate_azure_devops(request: &GenerateTemplateRequest) -> Result<GeneratedTemplate, String> {
        let quality_gate = request.quality_gate_enabled.unwrap_or(true);
        let branch = request.branch.as_deref().unwrap_or("main");

        // Build Azure DevOps template using string concatenation to avoid raw string prefix issues
        let mut content = String::new();
        content.push_str("# Genial Architect Scanning Pipeline for Azure DevOps\n");
        content.push_str("# Save as azure-pipelines.yml or add to your existing pipeline\n\n");
        content.push_str("trigger:\n");
        content.push_str("  branches:\n");
        content.push_str("    include:\n");
        content.push_str(&format!("      - {}\n", branch));
        content.push_str("      - develop\n");
        content.push_str("      - feature/*\n\n");
        content.push_str("pr:\n");
        content.push_str("  branches:\n");
        content.push_str("    include:\n");
        content.push_str(&format!("      - {}\n\n", branch));
        content.push_str("schedules:\n");
        content.push_str("  - cron: \"0 0 * * 0\"\n");
        content.push_str("    displayName: Weekly Security Scan\n");
        content.push_str("    branches:\n");
        content.push_str("      include:\n");
        content.push_str(&format!("        - {}\n", branch));
        content.push_str("    always: true\n\n");
        content.push_str("variables:\n");
        content.push_str("  - group: heroforge-credentials\n\n");
        content.push_str("stages:\n");
        content.push_str("  - stage: Security\n");
        content.push_str("    displayName: Security Scanning\n");
        content.push_str("    jobs:\n");
        content.push_str("      - job: HeroForgeScan\n");
        content.push_str("        displayName: Genial Architect Scan\n");
        content.push_str("        pool:\n");
        content.push_str("          vmImage: 'ubuntu-latest'\n");
        content.push_str("        steps:\n");
        content.push_str("          - checkout: self\n");
        content.push_str("            fetchDepth: 0\n\n");
        content.push_str("          - task: Bash@3\n");
        content.push_str("            displayName: 'Run HeroForge Scan'\n");
        content.push_str("            name: runScan\n");
        content.push_str("            inputs:\n");
        content.push_str("              targetType: 'inline'\n");
        content.push_str("              script: |\n");
        content.push_str("                RESPONSE=$(curl -s -X POST \"$(HEROFORGE_URL)/api/cicd/webhook/azure_devops\" \\\n");
        content.push_str("                  -H \"Authorization: Bearer $(HEROFORGE_TOKEN)\" \\\n");
        content.push_str("                  -H \"Content-Type: application/json\" \\\n");
        content.push_str("                  -d '{\n");
        content.push_str("                    \"project\": \"$(System.TeamProject)\",\n");
        content.push_str("                    \"repository\": \"$(Build.Repository.Name)\",\n");
        content.push_str("                    \"commit\": \"$(Build.SourceVersion)\",\n");
        content.push_str("                    \"branch\": \"$(Build.SourceBranchName)\",\n");
        content.push_str("                    \"build_id\": \"$(Build.BuildId)\",\n");
        content.push_str("                    \"pr_id\": \"$(System.PullRequest.PullRequestId)\"\n");
        content.push_str("                  }')\n\n");
        content.push_str("                echo \"Response: $RESPONSE\"\n");
        content.push_str("                SCAN_ID=$(echo $RESPONSE | jq -r '.scan_id // .id // empty')\n");
        content.push_str("                echo \"##vso[task.setvariable variable=SCAN_ID;isOutput=true]$SCAN_ID\"\n");

        if quality_gate {
            content.push_str("\n          - task: Bash@3\n");
            content.push_str("            displayName: 'Wait for Scan Completion'\n");
            content.push_str("            inputs:\n");
            content.push_str("              targetType: 'inline'\n");
            content.push_str("              script: |\n");
            content.push_str("                SCAN_ID=\"$(runScan.SCAN_ID)\"\n");
            content.push_str("                if [ -z \"$SCAN_ID\" ]; then\n");
            content.push_str("                  echo \"No scan ID returned, skipping wait\"\n");
            content.push_str("                  exit 0\n");
            content.push_str("                fi\n\n");
            content.push_str("                MAX_ATTEMPTS=60\n");
            content.push_str("                ATTEMPT=0\n\n");
            content.push_str("                while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do\n");
            content.push_str("                  STATUS=$(curl -s -X GET \"$(HEROFORGE_URL)/api/cicd/runs/$SCAN_ID\" \\\n");
            content.push_str("                    -H \"Authorization: Bearer $(HEROFORGE_TOKEN)\" | jq -r '.status // \"pending\"')\n\n");
            content.push_str("                  if [ \"$STATUS\" = \"completed\" ] || [ \"$STATUS\" = \"failed\" ]; then\n");
            content.push_str("                    echo \"Scan completed with status: $STATUS\"\n");
            content.push_str("                    break\n");
            content.push_str("                  fi\n\n");
            content.push_str("                  echo \"Waiting for scan to complete... (attempt $((ATTEMPT+1))/$MAX_ATTEMPTS)\"\n");
            content.push_str("                  sleep 10\n");
            content.push_str("                  ATTEMPT=$((ATTEMPT+1))\n");
            content.push_str("                done\n");

            content.push_str("\n          - task: Bash@3\n");
            content.push_str("            displayName: 'Check Quality Gate'\n");
            content.push_str("            condition: eq(variables['Build.Reason'], 'PullRequest')\n");
            content.push_str("            inputs:\n");
            content.push_str("              targetType: 'inline'\n");
            content.push_str("              script: |\n");
            content.push_str("                SCAN_ID=\"$(runScan.SCAN_ID)\"\n");
            content.push_str("                if [ -z \"$SCAN_ID\" ]; then\n");
            content.push_str("                  echo \"No scan ID, skipping quality gate\"\n");
            content.push_str("                  exit 0\n");
            content.push_str("                fi\n\n");
            content.push_str("                RESULT=$(curl -s -X GET \"$(HEROFORGE_URL)/api/cicd/runs/$SCAN_ID/gate-status\" \\\n");
            content.push_str("                  -H \"Authorization: Bearer $(HEROFORGE_TOKEN)\")\n\n");
            content.push_str("                GATE_STATUS=$(echo $RESULT | jq -r '.status // \"unknown\"')\n");
            content.push_str("                echo \"Quality Gate Status: $GATE_STATUS\"\n\n");
            content.push_str("                if [ \"$GATE_STATUS\" = \"failed\" ]; then\n");
            content.push_str("                  echo \"##vso[task.logissue type=error]Quality gate failed!\"\n");
            content.push_str("                  echo \"$RESULT\" | jq '.failed_conditions // []'\n");
            content.push_str("                  exit 1\n");
            content.push_str("                fi\n");
        }

        content.push_str("\n          - task: Bash@3\n");
        content.push_str("            displayName: 'Display Results Link'\n");
        content.push_str("            condition: always()\n");
        content.push_str("            inputs:\n");
        content.push_str("              targetType: 'inline'\n");
        content.push_str("              script: |\n");
        content.push_str("                SCAN_ID=\"$(runScan.SCAN_ID)\"\n");
        content.push_str("                if [ -n \"$SCAN_ID\" ]; then\n");
        content.push_str("                  echo \"View full scan results at: $(HEROFORGE_URL)/scans/$SCAN_ID\"\n");
        content.push_str("                fi\n");

        Ok(GeneratedTemplate {
            platform: "azure_devops".to_string(),
            content,
            filename: "azure-pipelines.yml".to_string(),
            variables_required: vec!["HEROFORGE_URL".to_string(), "HEROFORGE_TOKEN".to_string()],
            setup_instructions: r#"## Setup Instructions

1. Create a Variable Group in Azure DevOps:
   - Go to Pipelines > Library > Variable groups
   - Create a new group named `heroforge-credentials`
   - Add `HEROFORGE_URL`: Your HeroForge instance URL
   - Add `HEROFORGE_TOKEN`: Your API token (mark as secret)

2. Add the pipeline:
   - Create a new pipeline or update existing
   - Use the YAML file option
   - Save as `azure-pipelines.yml` in your repository

3. Configure pipeline permissions:
   - Ensure the pipeline has access to the variable group
   - Grant PR build access if using quality gates

The pipeline will run on:
- Push to main/develop/feature branches
- Pull requests targeting main
- Weekly schedule
"#
            .to_string(),
        })
    }

    /// Get list of available platforms
    pub fn get_available_platforms() -> Vec<PlatformInfo> {
        vec![
            PlatformInfo {
                id: "github_actions".to_string(),
                name: "GitHub Actions".to_string(),
                description: "Native GitHub CI/CD with YAML workflows".to_string(),
                filename: ".github/workflows/heroforge-security.yml".to_string(),
            },
            PlatformInfo {
                id: "gitlab_ci".to_string(),
                name: "GitLab CI".to_string(),
                description: "GitLab's integrated CI/CD with .gitlab-ci.yml".to_string(),
                filename: ".gitlab-ci.yml".to_string(),
            },
            PlatformInfo {
                id: "jenkins".to_string(),
                name: "Jenkins".to_string(),
                description: "Jenkins declarative pipeline with Jenkinsfile".to_string(),
                filename: "Jenkinsfile".to_string(),
            },
            PlatformInfo {
                id: "azure_devops".to_string(),
                name: "Azure DevOps".to_string(),
                description: "Azure Pipelines with YAML configuration".to_string(),
                filename: "azure-pipelines.yml".to_string(),
            },
        ]
    }
}

/// Information about a supported CI/CD platform
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub filename: String,
}
