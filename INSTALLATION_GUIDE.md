# Secure Coding Assistant – Detailed Installation Guide

This guide provides step-by-step instructions for setting up, building, and installing the Secure Coding Assistant VS Code extension from source. Follow each section in order for a smooth installation experience.

---

## 1. Prerequisites

Before you begin, ensure you have the following installed on your system:

- **Visual Studio Code**: Version 1.85.0 or higher ([Download VS Code](https://code.visualstudio.com/))
- **Node.js & npm**: [Download Node.js (includes npm)](https://nodejs.org/)
- **Git**: [Download Git](https://git-scm.com/downloads)
- **API Key**: For your preferred LLM provider (OpenAI, Anthropic, Google Gemini, or custom)
- **Supported OS**: Windows, macOS, or Linux

---

## 2. Clone the Repository

Open a terminal and run the following command to clone the repository to your local machine:

```sh
git clone https://github.com/oyesanyf/SecureCodeAssitVScode.git
cd SecureCodeAssitVScode
```

---

## 3. Install the Included VSIX File (Recommended)

If a prebuilt `.vsix` file (e.g., `secure-coding-assistant-0.0.1.vsix`) is included in the repository or release, you can install it directly without building from source. Follow these detailed steps:

### Step 1: Locate the VSIX File
- After cloning the repository, look for a file ending in `.vsix` (e.g., `secure-coding-assistant-0.0.1.vsix`) in the project root or in the release assets on GitHub.
- If you do not see a `.vsix` file, you may need to build it yourself (see the next section).

### Step 2: Open Visual Studio Code
- Launch Visual Studio Code on your computer.

### Step 3: Open the Extensions View
- Click the Extensions icon in the Activity Bar on the side of the window, or press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac).

### Step 4: Open the More Actions Menu
- In the Extensions view, click the `...` (More Actions) button in the top-right corner of the panel.
- From the dropdown menu, select **Install from VSIX...**

### Step 5: Select the VSIX File
- In the file dialog that appears, navigate to the folder where you cloned the repository or downloaded the `.vsix` file.
- Select the `.vsix` file (e.g., `secure-coding-assistant-0.0.1.vsix`) and click **Open**.

### Step 6: Wait for Installation
- VS Code will begin installing the extension. This may take a few moments.
- Once installation is complete, you should see a notification confirming the extension was installed successfully.

### Step 7: Reload or Restart VS Code (if prompted)
- Some installations may require you to reload the VS Code window. Click **Reload** if prompted, or close and reopen VS Code.

### Step 8: Verify Installation
- Go to the Extensions view (`Ctrl+Shift+X` or `Cmd+Shift+X`).
- Search for "Secure Coding Assistant" in the list of installed extensions.
- Ensure the extension appears and is enabled (the toggle should be "on").

### Troubleshooting
- **Can't find the VSIX file?**
  - Double-check the repository folder and any release assets on GitHub.
  - If missing, follow the build instructions to create the VSIX file.
- **Error: 'VSIX not a valid extension'?**
  - Make sure you selected the correct `.vsix` file and that it is not corrupted.
  - Try re-downloading or rebuilding the VSIX.
- **Permission denied or install fails?**
  - Ensure you have write permissions to your VS Code extensions directory.
  - Try running VS Code as administrator (Windows) or with elevated permissions (Mac/Linux).
- **Extension does not appear after install?**
  - Reload or restart VS Code.
  - Check for errors in the VS Code output panel (View > Output).

If you continue to have issues, refer to the [official VS Code documentation on installing extensions from VSIX](https://code.visualstudio.com/docs/editor/extension-marketplace#_install-from-a-vsix) or proceed to the build-from-source instructions below.

---

## 4. Install Dependencies

Install all required Node.js packages:

```sh
npm install
```

---

## 5. Build the Extension

Compile the TypeScript source code:

```sh
npm run compile
```

(Optional) Type-check the code for errors:

```sh
npx tsc -p .
```

---

## 6. Package the Extension (Create VSIX)

Use the VSCE tool to package the extension into a `.vsix` file:

```sh
npx vsce package
```

This will generate a file like `secure-coding-assistant-0.0.1.vsix` in your project directory.

---

## 7. Install the Extension in VS Code

### Option A: Install from VSIX File
1. Open Visual Studio Code.
2. Go to the Extensions view (`Ctrl+Shift+X`).
3. Click the `...` (More Actions) menu in the top-right, then select **Install from VSIX...**
4. Browse to and select the generated `.vsix` file.
5. Wait for the extension to install.

### Option B: Install from Marketplace (if available)
1. Open Visual Studio Code.
2. Go to the Extensions view (`Ctrl+Shift+X`).
3. Search for `Secure Coding Assistant`.
4. Click **Install**.

---

## 8. Post-Installation Setup

### 8.1 Set Your LLM Provider
1. Open Settings (`Ctrl+,`).
2. Search for `Secure Coding Assistant`.
3. Set your preferred LLM provider (OpenAI, Anthropic, Google, or Custom).

### 8.2 Add Your API Key
**You must add an API key for your chosen provider before scanning code.**

#### Using the Command Palette (Recommended)
1. Open Command Palette: `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac).
2. Type `Secure Coding: Add` to see available API key commands.
3. Select your provider (e.g., `Add OpenAI API Key`).
4. Paste your API key when prompted.

#### Using Context Menus
1. Right-click anywhere in VS Code.
2. Look for `Secure Coding` commands in the context menu.
3. Select the appropriate `Add [Provider] API Key` command.
4. Enter your API key when prompted.

---

## 9. Verifying Installation

1. Right-click on a code file or selection and choose `Secure Coding: Scan Selection` or `Scan File`.
2. View results in the `Secure Coding Assistant` output channel.
3. If you see scan results, your setup is complete!

---

## 10. Troubleshooting

- **No scan results?**
  - Ensure your API key is set and valid.
  - Check your internet connection.
  - Make sure you are using a supported file type.
- **Performance issues?**
  - Use Core Mode for faster scanning (see settings).
  - Enable Fast Mode for speed priority.
- **Too many files being scanned?**
  - Disable comprehensive scanning in settings.
  - Use `.gitignore` to exclude directories.

For more help, see the [README](./readme.md) or [COMPREHENSIVE_FILE_SUPPORT.md].

---

## 11. Uninstallation

1. Go to the Extensions view (`Ctrl+Shift+X`).
2. Find `Secure Coding Assistant` in the list.
3. Click the gear icon ⚙️ and select **Uninstall**.

---

## 12. Additional Resources

- [Comprehensive File Support](./COMPREHENSIVE_FILE_SUPPORT.md)
- [API Reference](./API_REFERENCE.md)
- [Technical Guide](./TECHNICAL_GUIDE.md)
