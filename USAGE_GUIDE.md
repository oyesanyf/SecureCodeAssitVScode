# Secure Coding Assistant – Usage Guide

This guide provides comprehensive instructions for using the Secure Coding Assistant VS Code extension, including all available commands, scan types, and features.

---

## Quick Start

1. **Open Command Palette**: `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
2. **Type "Secure Coding"** to see all available commands
3. **Select your desired command** from the list

---

## Available Commands

### 🔍 Scanning Commands

#### Scan Selection
- **Command**: `Secure Coding: Scan Selection`
- **Description**: Analyzes only the selected code for security vulnerabilities
- **How to use**:
  1. Select code in the editor
  2. Right-click → "Secure Coding: Scan Selection"
  3. Or use Command Palette → "Secure Coding: Scan Selection"

#### Scan File
- **Command**: `Secure Coding: Scan File`
- **Description**: Scans the entire active file for security issues
- **How to use**:
  1. Open the file you want to scan
  2. Right-click in the file explorer → "Secure Coding: Scan File"
  3. Or use Command Palette → "Secure Coding: Scan File"

#### Scan Folder
- **Command**: `Secure Coding: Scan Folder`
- **Description**: Recursively scans all supported files in the selected folder
- **How to use**:
  1. Right-click on a folder in the file explorer → "Secure Coding: Scan Folder"
  2. Or use Command Palette → "Secure Coding: Scan Folder"

#### Generate Fix
- **Command**: `Secure Coding: Generate Fix`
- **Description**: Uses AI to generate secure code fixes for detected vulnerabilities
- **How to use**:
  1. Right-click in the editor → "Secure Coding: Generate Fix"
  2. Or use Command Palette → "Secure Coding: Generate Fix"

---

### 📺 Output Commands

#### Show Output Channel
- **Command**: `Secure Coding: Show Output Channel`
- **Description**: Opens the output panel to view detailed scan results and fixes
- **How to use**: Command Palette → "Secure Coding: Show Output Channel"

---

### 🔑 API Key Management Commands

#### Add OpenAI API Key
- **Command**: `Secure Coding: Add OpenAI API Key`
- **Description**: Securely stores your OpenAI API key for GPT models
- **How to use**: Command Palette → "Secure Coding: Add OpenAI API Key"

#### Remove OpenAI API Key
- **Command**: `Secure Coding: Remove OpenAI API Key`
- **Description**: Removes the stored OpenAI API key from secure storage
- **How to use**: Command Palette → "Secure Coding: Remove OpenAI API Key"

#### Add Anthropic API Key
- **Command**: `Secure Coding: Add Anthropic API Key`
- **Description**: Securely stores your Anthropic API key for Claude models
- **How to use**: Command Palette → "Secure Coding: Add Anthropic API Key"

#### Remove Anthropic API Key
- **Command**: `Secure Coding: Remove Anthropic API Key`
- **Description**: Removes the stored Anthropic API key from secure storage
- **How to use**: Command Palette → "Secure Coding: Remove Anthropic API Key"

#### Add Google API Key
- **Command**: `Secure Coding: Add Google API Key`
- **Description**: Securely stores your Google API key for Gemini models
- **How to use**: Command Palette → "Secure Coding: Add Google API Key"

#### Remove Google API Key
- **Command**: `Secure Coding: Remove Google API Key`
- **Description**: Removes the stored Google API key from secure storage
- **How to use**: Command Palette → "Secure Coding: Remove Google API Key"

---

### 🔧 Custom Provider Commands

#### Add Custom LLM Provider
- **Command**: `Secure Coding: Add Custom LLM Provider`
- **Description**: Configure a custom LLM endpoint (OpenAI-compatible API format required)
- **How to use**: Command Palette → "Secure Coding: Add Custom LLM Provider"
- **Prompts for**:
  - Provider name (e.g., "MyCustomLLM")
  - API key
  - Endpoint URL (e.g., `https://api.myservice.com/v1/chat/completions`)

---

## Scan Types and File Support

### 🔍 Real-Time Scanning

The extension supports comprehensive real-time scanning for ALL file types:

#### Code Security Scanning
- **Languages**: JavaScript, TypeScript, Python, Java, C#, Go, Rust, PHP, Ruby, C, C++, Swift, Kotlin, etc.
- **Detects**: Injection flaws, XSS, authentication issues, crypto problems
- **Output**: `🔍 REAL-TIME CODE: Scanning app.js - Programming language: javascript`

#### Configuration Security
- **Files**: JSON, YAML, XML, Docker, Kubernetes, Terraform
- **Detects**: Misconfigurations, exposed secrets, insecure defaults
- **Output**: `🔍 REAL-TIME CONFIG: Scanning config.yaml - Configuration file: yaml`

#### Infrastructure as Code (IaC)
- **Files**: Terraform (.tf), ARM templates (.bicep), CloudFormation (.cfn)
- **Detects**: Cloud misconfigurations, insecure resources, compliance issues
- **Output**: `🔍 REAL-TIME IAC: Scanning main.tf - Infrastructure as Code: main.tf`

#### Software Composition Analysis (SCA)
- **Files**: package.json, requirements.txt, pom.xml, Cargo.toml, go.mod
- **Detects**: Vulnerable dependencies, license issues, outdated packages
- **Output**: `🔍 REAL-TIME SCA: Scanning package.json - Dependency file: package.json`

#### Sensitive Data Detection
- **Files**: .env files, certificates, key files, .secret files
- **Detects**: Hardcoded secrets, exposed credentials, API keys
- **Output**: `🔍 REAL-TIME SENSITIVE: Scanning .env - Potentially sensitive file: .env`

#### Database Security
- **Files**: SQL scripts, stored procedures
- **Detects**: SQL injection, privilege escalation, data exposure
- **Output**: `🔍 REAL-TIME DATABASE: Scanning queries.sql - Database file: sql`

#### Web Security
- **Files**: HTML, CSS, client-side scripts
- **Detects**: XSS vulnerabilities, CSRF issues, content security policy
- **Output**: `🔍 REAL-TIME WEB: Scanning index.html - Web file: html`

---

## Context Menu Integration

### Editor Context Menu (Right-click in code editor)
- **"Secure Coding: Scan Selection"** (when text is selected)
- **"Secure Coding: Generate Fix"** (always available)

### Explorer Context Menu (Right-click in file explorer)
- **"Secure Coding: Scan File"** (on any file)
- **"Secure Coding: Scan Folder"** (on any folder)

---

## Output Channel Features

The "Secure Coding Assistant" output channel provides:

- **Detailed vulnerability reports** with line numbers and severity
- **Security recommendations** with CWE and OWASP references
- **AI-generated fixes** with explanations
- **Performance metrics** for scan and fix generation times
- **Provider information** showing which LLM detected each issue
- **Batch processing results** with efficiency statistics

---

## Performance Optimization

### Fast Mode
- **Command**: `Secure Coding: Toggle Fast Mode`
- **Description**: Prioritizes speed over thoroughness
- **Use case**: Quick scans during development

### Comprehensive File Scanning
- **Command**: `Secure Coding: Toggle Comprehensive File Scanning`
- **Description**: Switches between all file types vs. core programming languages only
- **Use case**: Complete security coverage vs. performance

---

## Troubleshooting

### Common Issues

#### No scan results?
1. Ensure your API key is set and valid
2. Check your internet connection
3. Make sure you are using a supported file type
4. Verify the extension is enabled

#### Performance issues?
1. Use Core Mode for faster scanning (see settings)
2. Enable Fast Mode for speed priority
3. Increase scan delay in settings

#### Too many files being scanned?
1. Disable comprehensive scanning in settings
2. Use `.gitignore` patterns to exclude directories
3. Enable VS Code file skipping

### Getting Help

1. **Check Output Channel**: Always check the "Secure Coding Assistant" output channel for detailed error messages
2. **Settings Reset**: Try resetting extension settings to defaults
3. **Key Regeneration**: Generate a new API key if issues persist

---

## Best Practices

### Development Workflow
1. **Scan selection** for quick checks while coding
2. **Scan file** before committing changes
3. **Scan folder** for comprehensive project review
4. **Generate fixes** for AI-powered solutions

### Security Review
1. **Enable comprehensive scanning** for thorough security coverage
2. **Review all scan types** (code, config, IaC, SCA, sensitive data)
3. **Address high-severity issues** first
4. **Use AI-generated fixes** as starting points for manual review

### Performance Optimization
1. **Use Fast Mode** during active development
2. **Disable comprehensive scanning** on large codebases
3. **Exclude build directories** and dependencies
4. **Batch process** similar vulnerabilities together

---

## Keyboard Shortcuts

All commands are accessible via Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- Type "Secure Coding" to see all available commands
- Commands are organized by category for easy discovery
- No default keyboard shortcuts assigned (can be customized in VS Code settings)

---

## Additional Resources

- [Installation Guide](./INSTALLATION_GUIDE.md)
- [Comprehensive File Support](./COMPREHENSIVE_FILE_SUPPORT.md)
- [API Reference](./API_REFERENCE.md)
- [Technical Guide](./TECHNICAL_GUIDE.md) 