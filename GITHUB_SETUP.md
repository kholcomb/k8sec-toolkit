# GitHub Repository Setup Notes

## Current Status
- Repository: https://github.com/kholcomb/k8sec-toolkit
- Main branch: Updated with k8sec-toolkit refactoring
- Develop branch: Active development branch
- GitFlow: Established

## Manual Setup Required

### 1. GitHub Actions Workflows
Due to GitHub App limitations, workflows need to be added manually:

The following workflow files need to be uploaded via GitHub web interface:
- `.github/workflows/ci.yml` - CI/CD pipeline
- `.github/workflows/security.yml` - Security scanning
- `.github/workflows/validate-workflows.yml` - Workflow validation

### 2. Branch Protection Rules
Set up branch protection via GitHub CLI or web interface:

```bash
# Protect main branch
gh api repos/kholcomb/k8sec-toolkit/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test","lint","build"]}' \
  --field enforce_admins=false \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field restrictions=null

# Protect develop branch
gh api repos/kholcomb/k8sec-toolkit/branches/develop/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test","lint"]}' \
  --field enforce_admins=false \
  --field required_pull_request_reviews=null \
  --field restrictions=null
```

### 3. Repository Settings
Configure the following in GitHub web interface:
- Default branch: `develop`
- Merge button settings: Enable squash merging
- Delete head branches: Enabled
- Require linear history: Enabled

### 4. GitHub Secrets
Set up the following secrets:
- `SEMGREP_APP_TOKEN` - For Semgrep security scanning
- `SNYK_TOKEN` - For Snyk vulnerability scanning (optional)

### 5. GitHub Apps
If using GitHub Apps, ensure the following permissions:
- Contents: Read/Write
- Pull requests: Read/Write
- Actions: Read/Write (for workflow files)
- Security events: Write (for SARIF uploads)

## GitFlow Workflow
Once branch protection is in place:

1. **Feature Development**: Create branches from `develop`
2. **Pull Requests**: Target `develop` branch
3. **Releases**: Merge `develop` to `main` for releases
4. **Hotfixes**: Branch from `main`, merge to both `main` and `develop`

## Current Branch Status
- `main`: Production-ready code (protected)
- `develop`: Integration branch (protected)
- Feature branches: `feature/*` pattern

## Next Steps
1. Manually upload GitHub Actions workflows
2. Set up branch protection rules
3. Configure repository settings
4. Test the complete CI/CD pipeline
5. Create first feature branch for tool integration