# SecureCodeVSCodePlugin

This repository contains security-related scripts and a VS Code extension designed to help identify and fix security vulnerabilities using static analysis and AI-assisted review.

---

## 🔐 Secure Coding Assistant (VS Code Extension)

A Visual Studio Code extension that helps identify and fix security vulnerabilities in your code through static analysis and AI-powered code review.

---

### 🔍 Features

- **Code Scanning**: Scan selected code, entire files, or complete folders for security vulnerabilities
- **Multiple LLM Providers**: Support for OpenAI, Anthropic, Google, and custom providers
- **Security Analysis**: Detects issues including:
  - Hardcoded credentials or secrets
  - Insecure cryptographic usage
  - SQL injection, XSS, command injection, and more
  - Path traversal, deserialization, and misconfigurations

---

### 🛠️ Installation

1. Open Visual Studio Code
2. Go to Extensions view (Ctrl+Shift+X)
3. Search for "Secure Coding Assistant"
4. Click **Install**

---

### ⚙️ Usage & Configuration

#### Provider Setup

1. Open Settings (Ctrl+,)
2. Search: `Secure Coding Assistant`
3. Choose provider: OpenAI, Anthropic, Google, or Custom

#### 🔑 API Key Configuration

**IMPORTANT**: You must configure an API key for your chosen LLM provider before scanning code.

##### Option 1: Using Command Palette (Recommended)

1. **Open Command Palette**: `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
2. **Type**: "Secure Coding: Add" to see available API key commands
3. **Select** your provider:
   - `Secure Coding: Add OpenAI API Key`
   - `Secure Coding: Add Anthropic API Key`
   - `Secure Coding: Add Google API Key`
4. **Paste your API key** when prompted
5. **Confirm** - Your key is securely stored in VS Code's secret storage

##### Option 2: Using Context Menus

1. **Right-click** anywhere in VS Code
2. **Look for** "Secure Coding" commands in the context menu
3. **Select** the appropriate "Add [Provider] API Key" command
4. **Enter your API key** when prompted

---

### 🌐 How to Obtain API Keys

#### OpenAI API Key
1. **Visit**: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. **Sign up/Login** to your OpenAI account
3. **Click** "Create new secret key"
4. **Copy** the generated key (starts with `sk-`)
5. **Add to extension** using `Secure Coding: Add OpenAI API Key`

#### Anthropic API Key (Claude)
1. **Visit**: [https://console.anthropic.com/](https://console.anthropic.com/)
2. **Sign up/Login** to your Anthropic account
3. **Navigate** to API Keys section
4. **Generate** a new API key
5. **Copy** the key and add using `Secure Coding: Add Anthropic API Key`

#### Google API Key (Gemini)
1. **Visit**: [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. **Sign in** with your Google account
3. **Click** "Create API Key"
4. **Copy** the generated key
5. **Add to extension** using `Secure Coding: Add Google API Key`

#### Custom LLM Provider Setup
1. **Use Command**: `Secure Coding: Add Custom LLM Provider`
2. **Enter Provider Name**: e.g., "MyCustomLLM"
3. **Enter API Key**: Your custom provider's API key
4. **Enter Endpoint URL**: e.g., `https://api.myservice.com/v1/chat/completions`
5. **Note**: Must be OpenAI-compatible API format

---

### 🔒 API Key Security

- **Secure Storage**: All API keys are stored in VS Code's built-in secret storage
- **No Plain Text**: Keys are never stored in settings files or workspace
- **Local Only**: Keys remain on your local machine
- **Easy Removal**: Use "Remove [Provider] API Key" commands to delete keys

#### Available Commands

##### 🔍 Scanning Commands

- **Scan Selection**: 
  - Right-click selected code → "Secure Coding: Scan Selection"
  - Or use Command Palette (Ctrl+Shift+P) → "Secure Coding: Scan Selection"
  - Analyzes only the selected code for security vulnerabilities

- **Scan File**: 
  - Right-click file in Explorer → "Secure Coding: Scan File"
  - Or use Command Palette → "Secure Coding: Scan File"
  - Scans the entire active file for security issues

- **Scan Folder**: 
  - Right-click folder in Explorer → "Secure Coding: Scan Folder"
  - Or use Command Palette → "Secure Coding: Scan Folder"
  - Recursively scans all supported files in the folder

- **Generate Fix**: 
  - Right-click in editor → "Secure Coding: Generate Fix"
  - Or use Command Palette → "Secure Coding: Generate Fix"
  - Uses AI to generate secure code fixes for detected vulnerabilities

##### 📺 Output Commands

- **Show Output Channel**: 
  - Command Palette → "Secure Coding: Show Output Channel"
  - Opens the output panel to view detailed scan results and fixes

##### 🔑 API Key Management Commands

- **Add OpenAI API Key**: 
  - Command Palette → "Secure Coding: Add OpenAI API Key"
  - Securely stores your OpenAI API key for GPT models

- **Remove OpenAI API Key**: 
  - Command Palette → "Secure Coding: Remove OpenAI API Key"
  - Removes the stored OpenAI API key from secure storage

- **Add Anthropic API Key**: 
  - Command Palette → "Secure Coding: Add Anthropic API Key"
  - Securely stores your Anthropic API key for Claude models

- **Remove Anthropic API Key**: 
  - Command Palette → "Secure Coding: Remove Anthropic API Key"
  - Removes the stored Anthropic API key from secure storage

- **Add Google API Key**: 
  - Command Palette → "Secure Coding: Add Google API Key"
  - Securely stores your Google API key for Gemini models

- **Remove Google API Key**: 
  - Command Palette → "Secure Coding: Remove Google API Key"
  - Removes the stored Google API key from secure storage

##### 🔧 Custom Provider Commands

- **Add Custom LLM Provider**: 
  - Command Palette → "Secure Coding: Add Custom LLM Provider"
  - Configure a custom LLM endpoint (OpenAI-compatible API format required)
  - Prompts for provider name, API key, and endpoint URL

##### 🚀 Quick Start Guide

1. **Install the extension** from VS Code marketplace
2. **Get an API key** from your chosen provider (see "How to Obtain API Keys" section above)
3. **Set your preferred LLM** in settings (`secureCodingAssistant.preferredLlm`)
4. **Add your API key** using `Ctrl+Shift+P` → "Secure Coding: Add [Provider] API Key"
5. **Test the setup** by scanning a small code snippet
6. **Start scanning** by right-clicking code/files or using Command Palette
7. **View results** in the "Secure Coding Assistant" output channel
8. **Generate fixes** using the "Generate Fix" command for AI-powered solutions

**⚡ First-Time Setup Checklist:**
- ✅ Extension installed
- ✅ API key obtained from provider
- ✅ Preferred LLM set in VS Code settings
- ✅ API key added using extension command
- ✅ Test scan completed successfully

##### 🎯 Context Menu Integration

The extension integrates seamlessly with VS Code's context menus:

- **Editor Context Menu** (right-click in code editor):
  - "Secure Coding: Scan Selection" (when text is selected)
  - "Secure Coding: Generate Fix" (always available)

- **Explorer Context Menu** (right-click in file explorer):
  - "Secure Coding: Scan File" (on any file)
  - "Secure Coding: Scan Folder" (on any folder)

##### ⌨️ Keyboard Shortcuts

All commands are accessible via Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- Type "Secure Coding" to see all available commands
- Commands are organized by category for easy discovery
- No default keyboard shortcuts assigned (can be customized in VS Code settings)

##### 📊 Output Channel Features

The "Secure Coding Assistant" output channel provides:

- **Detailed vulnerability reports** with line numbers and severity
- **Security recommendations** with CWE and OWASP references
- **AI-generated fixes** with explanations
- **Performance metrics** for scan and fix generation times
- **Provider information** showing which LLM detected each issue
- **Batch processing results** with efficiency statistics

---

### 🧩 Supported File Types

- **Code**: `.ts`, `.js`, `.py`, `.java`, `.c`, `.cpp`, `.go`, `.rs`, `.php`, `.rb`, `.cs`, `.swift`, `.kt`, `.m`, `.h`, `.hpp`
- **Config**: `.json`, `.yaml`, `.yml`
- **Web**: `.html`, `.css`, `.scss`, `.less`
- **Scripts**: `.sh`, `.ps1`, `.bat`

---

### 📦 Requirements

- Visual Studio Code `1.85.0+`
- API key for supported LLM (OpenAI, Claude, Gemini, etc.)

---

### ⚙️ Extension Settings

#### Core Configuration

- **`secureCodingAssistant.preferredLlm`**: Choose your preferred LLM provider
  - Options: `"OpenAI"`, `"Anthropic"`, `"Google"`, `"Custom"`
  - Default: `"OpenAI"`

#### OpenAI Settings

- **`secureCodingAssistant.openai.model`**: OpenAI model selection
  - Default: `"gpt-3.5-turbo"`
  - Recommended: `"gpt-4-turbo-preview"` for better accuracy

- **`secureCodingAssistant.openai.systemPrompt`**: System prompt for OpenAI
- **`secureCodingAssistant.openai.userPrompt`**: User prompt template for OpenAI

#### Performance & Retry Settings

- **`secureCodingAssistant.retry.maxRetries`**: Maximum API call retries
  - Default: `3`, Range: `0-10`

- **`secureCodingAssistant.retry.baseDelay`**: Base retry delay in milliseconds
  - Default: `1000`, Range: `100-10000`

- **`secureCodingAssistant.retry.maxDelay`**: Maximum retry delay in milliseconds
  - Default: `10000`, Range: `1000-60000`

- **`secureCodingAssistant.tokens.baseMaxTokens`**: Base maximum tokens for LLM responses
  - Default: `4000`, Range: `500-128000`

#### Performance Optimization

- **`secureCodingAssistant.performance.maxConcurrentFixes`**: Parallel fix generation limit
  - Default: `3`, Range: `1-10`

- **`secureCodingAssistant.performance.enableBatchProcessing`**: Group similar vulnerabilities
  - Default: `true`

- **`secureCodingAssistant.performance.prioritizeHighSeverity`**: Process high-severity issues first
  - Default: `true`

#### File Scanning Configuration

- **`secureCodingAssistant.sourceCodeExtensions`**: Supported file extensions
  - Default: `[".ts", ".js", ".py", ".java", ".c", ".cpp", ".go", ".rs", ".php", ".rb", ".cs", ".swift", ".kt", ".m", ".h", ".hpp", ".json", ".yaml", ".yml", ".xml", ".html", ".css", ".scss", ".less", ".sh", ".ps1", ".bat"]`

- **`secureCodingAssistant.excludedDirectories`**: Directories to skip during folder scans
  - Default: `["node_modules", "dist", "build", "out", "extension", "bin", "obj", ".git", ".svn", ".hg", ".vscode", ".vscode-test", "venv", "env", ".env", "__pycache__"]`

- **`secureCodingAssistant.defaultModel`**: Default model for analysis
  - Default: `"gpt-4-turbo-preview"`

- **`secureCodingAssistant.scanBatchSize`**: Files to process in parallel during folder scans
  - Default: `5`

---

### ⚠️ Known Issues

- Large files may take longer to scan
- Some complex patterns may require manual inspection
- Custom LLMs must follow OpenAI-compatible API format

---

### 🛠️ Troubleshooting API Keys

#### Common Issues and Solutions

**❌ "API Key not found" Error**
- **Solution**: Add your API key using the correct command for your chosen provider
- **Check**: Ensure you've set the correct `preferredLlm` in settings

**❌ "Invalid API Key" Error**
- **Solution**: Verify your API key is correct and active
- **For OpenAI**: Key should start with `sk-`
- **Try**: Remove and re-add the API key using the remove/add commands

**❌ "Provider not configured" Error**
- **Solution**: 
  1. Set `secureCodingAssistant.preferredLlm` in VS Code settings
  2. Add the corresponding API key for that provider

**❌ Custom LLM Provider Issues**
- **Check**: Endpoint URL is correct and accessible
- **Verify**: API follows OpenAI-compatible format
- **Test**: Try with built-in providers first to isolate issues

#### Verifying Your Setup

1. **Check Settings**: Open VS Code settings and search "Secure Coding Assistant"
2. **Verify Provider**: Ensure `preferredLlm` is set to your chosen provider
3. **Test API Key**: Try scanning a small code snippet
4. **Check Output**: View "Secure Coding Assistant" output channel for detailed error messages

#### Getting Help

- **Output Channel**: Always check the output channel for detailed error messages
- **Settings Reset**: Try resetting extension settings to defaults
- **Key Regeneration**: Generate a new API key if issues persist

---

### 🤝 Contributing

Contributions welcome!

1. Fork the repository
2. Create a feature branch:  
   `git checkout -b feature/my-feature`
3. Commit your changes:  
   `git commit -m 'Add some feature'`
4. Push the branch:  
   `git push origin feature/my-feature`
5. Open a Pull Request

---

### 📄 License

This project is licensed under the [MIT License](https://github.com/contextmedia/security_scripts/blob/HEAD/LICENSE).

---

### 🙏 Acknowledgments

- [OpenAI](https://openai.com) – GPT models
- [Anthropic](https://www.anthropic.com) – Claude models
- [Google](https://ai.google) – Gemini models
- [VS Code](https://code.visualstudio.com) – Extension platform
