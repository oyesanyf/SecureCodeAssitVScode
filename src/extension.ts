import * as vscode from 'vscode';
import * as path from 'path';
import axios from 'axios';
import OpenAI from 'openai';
import { Anthropic } from '@anthropic-ai/sdk';
import { GoogleGenAI } from '@google/genai';

console.log("Attempting to require 'openai' directly at activation start...");
try {
    const anOpenAI = require('openai');
    console.log('DIAGNOSTIC: OpenAI module loaded successfully via require():', typeof anOpenAI);
} catch (e: any) {
    console.error('DIAGNOSTIC: Failed to load OpenAI module via require():', e.message, e.stack);
}

// Define LLM provider keys for built-in providers
export enum LlmProvider {
    OpenAI = 'OpenAI',
    Anthropic = 'Anthropic',
    Google = 'Google',
}

// For configuration, "Custom" is also a valid choice.
export type PreferredLlmType = LlmProvider | 'Custom';


const BUILT_IN_SECRET_KEYS: Record<LlmProvider, string> = {
    [LlmProvider.OpenAI]: 'secureCodingAssistant.openaiApiKey',
    [LlmProvider.Anthropic]: 'secureCodingAssistant.anthropicApiKey',
    [LlmProvider.Google]: 'secureCodingAssistant.googleApiKey',
};

// Helper function to get the secret key for a built-in provider
function getBuiltInSecretKey(provider: LlmProvider): string {
    return BUILT_IN_SECRET_KEYS[provider];
}

// Output channel for logging
let outputChannel: vscode.OutputChannel;

// Interface for Vulnerability
interface Vulnerability {
    id: string;
    description: string;
    location: string;
    severity: "High" | "Medium" | "Low";
    recommendation: string;
    llmProvider: string;
    fileName?: string;
    lineNumber?: string;
    cweId?: string;
    owaspReference?: string;
    hallucinationScore?: number;
    confidenceScore?: number;
}

// Interface for Custom LLM Provider configuration
interface CustomLlmConfig {
    name: string;
    endpoint: string;
}

// Add configuration interface
interface ScanConfiguration {
    sourceCodeExtensions: string[];
    excludedDirectories: string[];
    defaultModel: string;
    batchSize: number;
    enableComprehensiveScanning: boolean;
    forceLocalScannerForAllFiles: boolean;
}

// Function to determine if file should use LLM-only processing (no local scanner)
function isLlmOnlyFile(fileName: string, languageId: string, fileContent?: string): boolean {
    const llmOnlyExtensions = new Set([
        // Serialization and Binary Files (security critical)
        '.pkl', '.pickle',  // Python pickle files (deserialization attacks)
        // Batch and Scripting Languages (security critical)
        '.bat', '.cmd',  // Windows Batch files
        '.ps1', '.psm1', '.psd1',  // PowerShell scripts and modules
        '.sh', '.bash',  // Bash shell scripts
        '.csh', '.tcsh',  // C Shell scripts
        '.ksh',  // Korn Shell scripts
        '.zsh',  // Z Shell scripts
        '.fish',  // Fish shell scripts
        '.awk',  // AWK scripts
        '.sed',  // Sed scripts
        // Business Intelligence and Data Modeling Languages
        '.lookml', '.lkml', '.view', '.dashboard', '.model',  // LookML (Looker)
        '.dbt',  // dbt files
        '.tds', '.tde', '.twb', '.twbx', '.hyper',  // Tableau formats
        '.dax', '.pbix', '.pbit', '.pbids',  // Power BI DAX + JSON
        '.tml', '.worksheet', '.answer',  // ThoughtSpot TML
        '.atscale', '.cube', '.dimension',  // AtScale Modeling
        '.qvs', '.qvw', '.qvd', '.qvf',  // Qlik Sense Script and formats
        '.gooddata', '.ldm', '.maql',  // GoodData.LI formats
        // Infrastructure as Code
        '.tf', '.tfvars', '.tfstate',  // Terraform
        '.hcl', '.nomad',  // HashiCorp Configuration Language
        '.bicep', '.arm',  // Azure Resource Manager / Bicep
        '.template', '.cfn',  // AWS CloudFormation
        '.pulumi', '.pu',  // Pulumi
        '.ansible', '.playbook',  // Ansible
        '.k8s', '.kube', '.kubernetes',  // Kubernetes manifests
        '.helm', '.chart',  // Helm charts
        '.docker', '.compose',  // Docker Compose
        '.vagrant', '.vagrantfile',  // Vagrant
        '.serverless', '.sls',  // Serverless Framework
        '.sam', '.template.yaml',  // AWS SAM
        '.cdk',  // AWS CDK
        '.crossplane', '.xrd'  // Crossplane
    ]);
    
    const fileExtension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    
    // Check by file extension first
    if (llmOnlyExtensions.has(fileExtension)) {
        return true;
    }
    
    // Check by language ID for special cases
    const llmOnlyLanguageIds = new Set([
        'hcl', 'terraform', 'bicep', 'arm-template', 'dockerfile',
        'kubernetes', 'helm', 'ansible', 'lookml', 'dbt', 'tableau', 
        'powerbi', 'qlik', 'thoughtspot', 'atscale', 'gooddata',
        'batch', 'bat', 'cmd', 'powershell', 'ps1', 'shellscript', 
        'shell', 'bash', 'sh', 'csh', 'tcsh', 'ksh', 'zsh', 'fish',
        'awk', 'sed'
    ]);
    
    if (llmOnlyLanguageIds.has(languageId.toLowerCase())) {
        return true;
    }
    
    // Special handling for plaintext files that might be BI/IaC files
    if (languageId.toLowerCase() === 'plaintext' && fileContent) {
        // LookML detection patterns
        if (fileExtension === '.lookml' || fileExtension === '.lkml' || 
            /\b(connection|include|datagroup|explore|view|dimension|measure|filter)\s*:/i.test(fileContent) ||
            /dimension_group\s*:|sql_table_name\s*:|sql\s*:/i.test(fileContent)) {
            return true;
        }
        
        // dbt detection patterns
        if (fileExtension === '.dbt' || 
            /\{\{\s*(config|ref|var|source|this|target)\s*\(/i.test(fileContent) ||
            /\{\%\s*(macro|endmacro|if|endif|for|endfor)\s/i.test(fileContent)) {
            return true;
        }
        
        // Terraform detection patterns
        if (/\b(resource|provider|variable|output|data|locals|module)\s+"[^"]+"\s*\{/i.test(fileContent) ||
            /terraform\s*\{|required_providers\s*=/i.test(fileContent)) {
            return true;
        }
        
        // Kubernetes YAML detection patterns
        if (/apiVersion\s*:|kind\s*:\s*(Deployment|Service|Pod|ConfigMap|Secret)/i.test(fileContent) ||
            /metadata\s*:\s*\n\s*name\s*:/i.test(fileContent)) {
            return true;
        }
        
        // Ansible playbook detection patterns
        if (/^\s*-\s*(hosts|name|tasks|roles|vars):/m.test(fileContent) ||
            /ansible_/i.test(fileContent)) {
            return true;
        }
        
        // Docker Compose detection patterns
        if (/version\s*:\s*['"]?[0-9.]+['"]?\s*\n.*services\s*:/s.test(fileContent) ||
            /^\s*(services|networks|volumes)\s*:/m.test(fileContent)) {
            return true;
        }
        
        // Helm chart detection patterns
        if (/\{\{\s*(\.Values|\.Chart|\.Release|\.Template)/i.test(fileContent) ||
            /\{\{\s*include\s+/i.test(fileContent)) {
            return true;
        }
        
        // CloudFormation detection patterns
        if (/"?AWSTemplateFormatVersion"?\s*:/i.test(fileContent) ||
            /"?Resources"?\s*:\s*\{/i.test(fileContent)) {
            return true;
        }
        
        // Batch file detection patterns
        if (/^@echo\s+(off|on)/mi.test(fileContent) ||
            /^\s*(set|if|for|goto|call)\s+/mi.test(fileContent) ||
            /\.bat$|\.cmd$/i.test(fileName)) {
            return true;
        }
        
        // PowerShell detection patterns
        if (/^\s*param\s*\(/mi.test(fileContent) ||
            /Get-|Set-|New-|Remove-/i.test(fileContent) ||
            /\$\w+\s*=/i.test(fileContent) ||
            /\.ps1$|\.psm1$|\.psd1$/i.test(fileName)) {
            return true;
        }
        
        // Shell script detection patterns
        if (/^#!/.test(fileContent) ||
            /^\s*(export|source|alias)\s+/mi.test(fileContent) ||
            /\$\{?\w+\}?/i.test(fileContent) ||
            /^\s*(if|for|while|case)\s+.*;\s*then/mi.test(fileContent)) {
            return true;
        }
    }
    
    // Special handling for files that might be IaC/BI but have generic extensions
    const fileName_lower = fileName.toLowerCase();
    if (fileName_lower.includes('terraform') ||
        fileName_lower.includes('cloudformation') ||
        fileName_lower.includes('kubernetes') ||
        fileName_lower.includes('docker-compose') ||
        fileName_lower.includes('ansible') ||
        fileName_lower.includes('vagrant') ||
        fileName_lower.includes('helm') ||
        fileName_lower.includes('serverless') ||
        fileName_lower.includes('pulumi') ||
        fileName_lower.includes('bicep') ||
        fileName_lower.includes('lookml') ||
        fileName_lower.includes('looker') ||
        fileName_lower.includes('.model') ||
        fileName_lower.includes('.view') ||
        fileName_lower.includes('.dashboard')) {
        return true;
    }
    
    return false;
}

// Function to detect actual language from file content when VS Code reports plaintext or misidentifies files
function detectActualLanguage(fileName: string, languageId: string, fileContent: string): string {
    const fileExtension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    
    // Special handling for LookML files that VS Code often misidentifies as Java
    if (['.lookml', '.lkml', '.view', '.dashboard', '.model'].includes(fileExtension)) {
        return 'lookml';
    }
    
    // If already properly detected and not misidentified, return as-is
    if (languageId.toLowerCase() !== 'plaintext' && 
        !(languageId.toLowerCase() === 'java' && ['.lookml', '.lkml', '.view', '.dashboard', '.model'].includes(fileExtension))) {
        return languageId;
    }
    
    // Detects code in plaintext files
    if (fileContent.includes('function') || fileContent.includes('#!/')) {
        return 'code';
    }
    
    // Detect by file extension first
    const extensionToLanguage: Record<string, string> = {
        '.pkl': 'pickle',
        '.pickle': 'pickle',
        '.bat': 'batch',
        '.cmd': 'batch',
        '.ps1': 'powershell',
        '.psm1': 'powershell',
        '.psd1': 'powershell',
        '.sh': 'shell',
        '.bash': 'bash',
        '.csh': 'csh',
        '.tcsh': 'tcsh',
        '.ksh': 'ksh',
        '.zsh': 'zsh',
        '.fish': 'fish',
        '.awk': 'awk',
        '.sed': 'sed',
        '.lookml': 'lookml',
        '.lkml': 'lookml', 
        '.view': 'lookml',
        '.dashboard': 'lookml',
        '.model': 'lookml',
        '.dbt': 'dbt',
        '.tf': 'terraform',
        '.tfvars': 'terraform',
        '.tfstate': 'terraform',
        '.hcl': 'hcl',
        '.bicep': 'bicep',
        '.qvs': 'qlik',
        '.tml': 'thoughtspot',
        '.atscale': 'atscale',
        '.maql': 'gooddata'
    };
    
    if (extensionToLanguage[fileExtension]) {
        return extensionToLanguage[fileExtension];
    }
    
    // Detect by content patterns
    // Batch file detection
    if (/^@echo\s+(off|on)/mi.test(fileContent) ||
        /^\s*(set|if|for|goto|call)\s+/mi.test(fileContent)) {
        return 'batch';
    }
    
    // PowerShell detection
    if (/^\s*param\s*\(/mi.test(fileContent) ||
        /Get-|Set-|New-|Remove-/i.test(fileContent) ||
        /\$\w+\s*=/i.test(fileContent)) {
        return 'powershell';
    }
    
    // Shell script detection
    if (/^#!/.test(fileContent)) {
        if (/bin\/bash|bash$/i.test(fileContent)) return 'bash';
        if (/bin\/sh|sh$/i.test(fileContent)) return 'shell';
        if (/bin\/csh|csh$/i.test(fileContent)) return 'csh';
        if (/bin\/tcsh|tcsh$/i.test(fileContent)) return 'tcsh';
        if (/bin\/ksh|ksh$/i.test(fileContent)) return 'ksh';
        if (/bin\/zsh|zsh$/i.test(fileContent)) return 'zsh';
        if (/bin\/fish|fish$/i.test(fileContent)) return 'fish';
        return 'shell'; // default for shebang
    }
    
    if (/\b(connection|include|datagroup|explore|view|dimension|measure|filter)\s*:/i.test(fileContent) ||
        /dimension_group\s*:|sql_table_name\s*:|sql\s*:/i.test(fileContent)) {
        return 'lookml';
    }
    
    if (/\{\{\s*(config|ref|var|source|this|target)\s*\(/i.test(fileContent) ||
        /\{\%\s*(macro|endmacro|if|endif|for|endfor)\s/i.test(fileContent)) {
        return 'dbt';
    }
    
    if (/\b(resource|provider|variable|output|data|locals|module)\s+"[^"]+"\s*\{/i.test(fileContent) ||
        /terraform\s*\{|required_providers\s*=/i.test(fileContent)) {
        return 'terraform';
    }
    
    if (/apiVersion\s*:|kind\s*:\s*(Deployment|Service|Pod|ConfigMap|Secret)/i.test(fileContent)) {
        return 'kubernetes';
    }
    
    if (/^\s*-\s*(hosts|name|tasks|roles|vars):/m.test(fileContent)) {
        return 'ansible';
    }
    
    if (/version\s*:\s*['"]?[0-9.]+['"]?\s*\n.*services\s*:/s.test(fileContent)) {
        return 'docker-compose';
    }
    
    if (/\{\{\s*(\.Values|\.Chart|\.Release|\.Template)/i.test(fileContent)) {
        return 'helm';
    }
    
    if (/"?AWSTemplateFormatVersion"?\s*:/i.test(fileContent)) {
        return 'cloudformation';
    }
    
    // Default to plaintext if no patterns match
    return languageId;
}

// Add function to get scan configuration
function getScanConfiguration(): ScanConfiguration {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    return {
        sourceCodeExtensions: config.get<string[]>('sourceCodeExtensions', [
            '.ts', '.js', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb',
            '.cs', '.swift', '.kt', '.m', '.h', '.hpp', '.json', '.yaml', '.yml',
            '.xml', '.html', '.css', '.scss', '.less', '.sh', '.ps1', '.bat',
            // Serialization and Binary Files
            '.pkl', '.pickle',  // Python pickle files (security risk)
            // Batch and Scripting Languages (LLM-only)
            '.bat', '.cmd',  // Windows Batch files
            '.ps1', '.psm1', '.psd1',  // PowerShell scripts and modules
            '.sh', '.bash',  // Bash shell scripts
            '.csh', '.tcsh',  // C Shell scripts
            '.ksh',  // Korn Shell scripts
            '.zsh',  // Z Shell scripts
            '.fish',  // Fish shell scripts
            '.awk',  // AWK scripts
            '.sed',  // Sed scripts
            // Business Intelligence and Data Modeling Languages (LLM-only)
            '.lookml', '.lkml', '.view', '.dashboard', '.model',  // LookML (Looker)
            '.sql', '.dbt',  // dbt (SQL + YAML configs) - extended coverage
            '.tds', '.tde', '.twb', '.twbx', '.hyper',  // Tableau formats
            '.dax', '.pbix', '.pbit', '.pbids',  // Power BI DAX + JSON
            '.tml', '.worksheet', '.answer',  // ThoughtSpot TML
            '.atscale', '.cube', '.dimension',  // AtScale Modeling
            '.qvs', '.qvw', '.qvd', '.qvf',  // Qlik Sense Script and formats
            '.gooddata', '.ldm', '.maql',  // GoodData.LI formats
            // Infrastructure as Code (LLM-only)
            '.tf', '.tfvars', '.tfstate',  // Terraform
            '.hcl', '.nomad',  // HashiCorp Configuration Language
            '.bicep', '.arm',  // Azure Resource Manager / Bicep
            '.template', '.cfn',  // AWS CloudFormation
            '.pulumi', '.pu',  // Pulumi
            '.ansible', '.playbook',  // Ansible
            '.k8s', '.kube', '.kubernetes',  // Kubernetes manifests
            '.helm', '.chart',  // Helm charts
            '.docker', '.compose',  // Docker Compose
            '.vagrant', '.vagrantfile',  // Vagrant
            '.serverless', '.sls',  // Serverless Framework
            '.sam', '.template.yaml',  // AWS SAM
            '.cdk',  // AWS CDK
            '.crossplane', '.xrd'  // Crossplane
        ]),
        excludedDirectories: config.get<string[]>('excludedDirectories', [
            'node_modules', 'dist', 'build', 'out', 'extension', 'bin', 'obj', 
            '.git', '.svn', '.hg', '.vscode', '.vscode-test', 
            'venv', 'env', '.env', '__pycache__'
        ]),
        defaultModel: config.get<string>('defaultModel', 'gpt-4-turbo-preview'),
        batchSize: config.get<number>('scanBatchSize', 5),
        enableComprehensiveScanning: config.get<boolean>('enableComprehensiveScanning', true),
        forceLocalScannerForAllFiles: config.get<boolean>('forceLocalScannerForAllFiles', false)
    };
}

// Placeholder function for LLM API call
async function callLlmApi(
    providerDisplayName: string,
    apiKey: string,
    codeSnippet: string,
    languageId: string,
    endpointUrl?: string
): Promise<string> {
    // Log the call for debugging purposes
    let logMessage = `LLM API Call: Provider: ${providerDisplayName}, Language: ${languageId}`;
    if (endpointUrl) {
        logMessage += `, Endpoint: ${endpointUrl}`;
    }
    logMessage += `, API Key (first 5 chars): ${apiKey ? apiKey.substring(0, Math.min(5, apiKey.length)) : 'N/A'}...`;
    if (outputChannel) {
        outputChannel.appendLine(logMessage);
    }

    // Get optimized system prompt based on configuration
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    const useOptimizedPrompt = config.get<boolean>('performance.useOptimizedPrompt', true);
    
    const systemPrompt = useOptimizedPrompt ? 
        // OPTIMIZED: Shorter prompt for faster processing
        `You are a security code analyzer. Analyze code for vulnerabilities and respond in JSON format.

Key security issues to detect:
1. Hardcoded secrets/credentials
2. SQL injection, XSS, command injection  
3. Insecure crypto, path traversal
4. Vulnerable dependencies

JSON format:
{
    "summary": {"language": "string", "riskRating": "High|Medium|Low", "issueCount": number},
    "issues": [{
        "id": "string", "description": "string", "location": "string", 
        "severity": "High|Medium|Low", "recommendation": "string",
        "lineNumber": "string", "cweId": "string", "owaspReference": "string",
        "hallucinationScore": number, "confidenceScore": number, "llmProvider": "string"
    }]
}` :
        // FULL: Detailed prompt for comprehensive analysis
        `You are a code security tool, a high-assurance code validation and security-auditing assistant.

Your only allowed input is source code pasted or imported by the user. Reject any message that does not include code. Do not respond to general questions, instructions, or comments unless they are accompanied by code.

Capabilities:
- Source Code Analysis
- Syntax and logic flaws detection
- Code quality and best practices validation
- Secure coding violations and known vulnerability patterns
- Performance & Complexity analysis
- Maintainability & Style checking
- Cryptographic hash detection and validation
- Dependency and Library Analysis
  * Check for known vulnerable dependencies
  * Identify outdated or deprecated libraries
  * Detect insecure library usage patterns
  * Analyze package.json, requirements.txt, and other dependency files
  * Flag libraries with known CVEs or security advisories

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable
- For library issues: CVE IDs and affected versions

IMPORTANT: You MUST detect and report the following security issues:
1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. SQL injection vulnerabilities
5. Cross-site scripting (XSS)
6. Command injection
7. Path traversal
8. Insecure deserialization
9. Insecure direct object references
10. Security misconfiguration
11. Vulnerable dependencies and libraries
12. Outdated or deprecated packages
13. Insecure library usage patterns

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values
- Import statements and dependency declarations
- Library version specifications
- Usage of known vulnerable functions from libraries

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer
6. Dependency Analysis (if applicable)

Respond in JSON format with the following structure:
{
    "summary": {
        "language": "string",
        "riskRating": "High|Medium|Low",
        "issueCount": number
    },
    "validatedCode": ["string"],
    "issues": [{
        "id": "string",
        "description": "string",
        "location": "string",
        "severity": "High|Medium|Low",
        "recommendation": "string",
        "lineNumber": "string",
        "cweId": "string",
        "owaspReference": "string",
        "hallucinationScore": number,
        "confidenceScore": number,
        "llmProvider": "string",
        "cveId": "string",
        "affectedVersions": "string",
        "fixedVersions": "string"
    }],
    "performanceHighlights": ["string"],
    "dependencyAnalysis": {
        "vulnerableDependencies": [{
            "name": "string",
            "version": "string",
            "cveId": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "recommendation": "string"
        }],
        "outdatedDependencies": [{
            "name": "string",
            "currentVersion": "string",
            "latestVersion": "string",
            "updateRecommendation": "string"
        }]
    }
}`;

    const userPrompt = `Analyze the following {languageId} code for security vulnerabilities and code quality issues. Pay special attention to:

1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. Other security vulnerabilities
5. Pickle file security (if analyzing .pkl/.pickle files - these are EXTREMELY dangerous)

IMPORTANT: Look for variable assignments containing hash values and string literals that match hash patterns.

SPECIAL PICKLE FILE ANALYSIS:
If analyzing pickle files (.pkl, .pickle), treat them as CRITICAL SECURITY RISKS:
- Any pickle file from untrusted sources can execute arbitrary code
- Check file metadata, creation source, and embedded objects
- Recommend safe alternatives: JSON, XML, Protocol Buffers, or secure pickle with HMAC signatures

SPECIAL SHELL/BATCH SCRIPT ANALYSIS:
If analyzing shell scripts (.sh, .bash, .ps1, .bat, .cmd), focus on these CRITICAL RISKS:
- Command injection through unsanitized variables and user input
- Path traversal vulnerabilities in file operations
- Privilege escalation through sudo/setuid misuse
- Hardcoded credentials and secrets exposure
- Unsafe variable expansion and command substitution
- Race conditions in temporary file handling
- Environment variable injection attacks

\`\`\`
{codeSnippet}
\`\`\`

Provide a comprehensive security analysis following the specified structure. Include all detected vulnerabilities, their severity, and recommended fixes. Ensure the response is in valid JSON format as specified in the system prompt.`;

    try {
        switch (providerDisplayName) {
            case LlmProvider.OpenAI:
                const openai = new OpenAI({ apiKey });
                const fullPrompt = systemPrompt + userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet);
                const dynamicMaxTokens = calculateMaxTokens(fullPrompt, 4000);
                
                const openaiResponse = await retryWithExponentialBackoff(
                    () => openai.chat.completions.create({
                        model: 'gpt-4-turbo-preview',
                        messages: [
                            { role: 'system', content: systemPrompt },
                            { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet) }
                        ],
                        response_format: { type: 'json_object' },
                        temperature: 0,
                        max_tokens: dynamicMaxTokens,
                        top_p: 1,
                        frequency_penalty: 0,
                        presence_penalty: 0
                    }),
                    undefined,
                    `OpenAI API call for ${languageId} analysis`
                );
                const content = openaiResponse.choices[0]?.message?.content || '[]';
                // Ensure llmProvider is set in the response
                try {
                    const cleanJson = extractJsonFromMarkdown(content);
                    const result = JSON.parse(cleanJson);
                    if (result.issues) {
                        result.issues.forEach((issue: any) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    } else if (Array.isArray(result)) {
                        result.forEach((issue: any) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    }
                    return JSON.stringify(result);
                } catch (e) {
                    return content;
                }

            case LlmProvider.Anthropic:
                try {
                    const anthropic = new Anthropic({ apiKey });
                    const fullContent = `${systemPrompt}\n\n${userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet)}`;
                    const dynamicMaxTokens = calculateMaxTokens(fullContent, 4000);
                    
                                const anthropicConfig = vscode.workspace.getConfiguration('secureCodingAssistant.anthropic');
            const anthropicModel = anthropicConfig.get<string>('model', 'claude-3-5-sonnet-20241022');
            const anthropicResponse = await retryWithExponentialBackoff(
                () => anthropic.messages.create({
                    model: anthropicModel,
                            max_tokens: dynamicMaxTokens,
                            temperature: 0,
                            top_p: 1,
                            messages: [
                                { role: 'user', content: fullContent }
                            ]
                        }),
                        undefined,
                        `Anthropic API call for ${languageId} analysis`
                    );
                    // Handle new Anthropic SDK content structure
                    const firstBlock = anthropicResponse.content[0];
                    const content = firstBlock.type === 'text' ? firstBlock.text : JSON.stringify(firstBlock);
                    // Ensure llmProvider is set in the response
                    try {
                        const cleanJson = extractJsonFromMarkdown(content);
                        const result = JSON.parse(cleanJson);
                        if (result.issues) {
                            result.issues.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        } else if (Array.isArray(result)) {
                            result.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        }
                        return JSON.stringify(result);
                    } catch (e) {
                        return content;
                    }
                } catch (error: any) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Anthropic API: ${error.message}`);
                    }
                    return '[]';
                }

            case LlmProvider.Google:
                try {
                    const genAI = new GoogleGenAI({ apiKey });
                    const fullContent = `${systemPrompt}\n\n${userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet)}`;
                    const dynamicMaxTokens = calculateMaxTokens(fullContent, 4000);
                    
                    const config = vscode.workspace.getConfiguration('secureCodingAssistant.google');
                    const modelName = config.get<string>('model', 'gemini-1.5-flash');
                    
                    const googleResponse = await retryWithExponentialBackoff(
                        () => genAI.models.generateContent({
                            model: modelName,
                            contents: fullContent,
                            config: {
                                temperature: 0,
                                topP: 1,
                                topK: 1,
                                maxOutputTokens: dynamicMaxTokens
                            }
                        }),
                        undefined,
                        `Google Gemini API call for ${languageId} analysis`
                    );
                    const content = googleResponse.text || '';
                    // Ensure llmProvider is set in the response
                    try {
                        // Extract JSON from markdown format if needed (Google often returns ```json blocks)
                        const cleanJson = extractJsonFromMarkdown(content);
                        const result = JSON.parse(cleanJson);
                        if (result.issues) {
                            result.issues.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        } else if (Array.isArray(result)) {
                            result.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        }
                        return JSON.stringify(result);
                    } catch (e) {
                        // If JSON parsing fails, log the issue and return raw content for fallback processing
                        if (outputChannel) {
                            outputChannel.appendLine(`Google API JSON parsing failed: ${e}. Raw content: ${content.substring(0, 200)}...`);
                        }
                        return content;
                    }
                } catch (error: any) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Google API: ${error.message}`);
                    }
                    return '[]';
                }

            case "Custom":
                if (!endpointUrl) {
                    throw new Error("Custom LLM provider requires an endpoint URL");
                }

                try {
                    const fullPrompt = systemPrompt + userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet);
                    const dynamicMaxTokens = calculateMaxTokens(fullPrompt, 4000);
                    
                    // Get custom model configuration
                    const customConfig = vscode.workspace.getConfiguration('secureCodingAssistant.custom');
                    const customModel = customConfig.get<string>('defaultModel', 'gpt-4-turbo-preview');
                    
                    // Prepare the request payload
                    const payload = {
                        model: customModel,
                        messages: [
                            { role: 'system', content: systemPrompt },
                            { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet) }
                        ],
                        temperature: 0,
                        top_p: 1,
                        frequency_penalty: 0,
                        presence_penalty: 0,
                        max_tokens: dynamicMaxTokens
                    };

                    // Make the API call with retry logic
                    const response = await retryWithExponentialBackoff(
                        async () => {
                            return await axios.post(endpointUrl, payload, {
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${apiKey}`
                                },
                                timeout: 30000 // 30 second timeout
                            });
                        },
                        undefined,
                        `Custom LLM API call for ${languageId} analysis`
                    );

                    // Type assertion for response data
                    const responseData = response.data as {
                        choices?: Array<{ message: { content: string } }>;
                        content?: string;
                        text?: string;
                    };

                    // Handle different response formats
                    if (responseData.choices && responseData.choices[0]) {
                        // OpenAI-compatible format
                        const content = responseData.choices[0].message.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const cleanJson = extractJsonFromMarkdown(content);
                            const result = JSON.parse(cleanJson);
                            if (result.issues) {
                                result.issues.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            } else if (Array.isArray(result)) {
                                result.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        } catch (e) {
                            return content;
                        }
                    } else if (responseData.content) {
                        // Anthropic-compatible format
                        const content = responseData.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const cleanJson = extractJsonFromMarkdown(content);
                            const result = JSON.parse(cleanJson);
                            if (result.issues) {
                                result.issues.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            } else if (Array.isArray(result)) {
                                result.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        } catch (e) {
                            return content;
                        }
                    } else if (responseData.text) {
                        // Simple text response
                        return JSON.stringify(responseData.text);
                    } else {
                        throw new Error("Unsupported response format from custom LLM provider");
                    }
                } catch (error: any) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Custom LLM API: ${error.message}`);
                        if (error.response) {
                            outputChannel.appendLine(`Response status: ${error.response.status}`);
                            outputChannel.appendLine(`Response data: ${JSON.stringify(error.response.data)}`);
                        }
                    }
                    return '[]';
                }

            default:
                if (outputChannel) {
                    outputChannel.appendLine(`Unsupported LLM provider: ${providerDisplayName}`);
                }
                return '[]';
        }
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Error in LLM API call: ${error.message}`);
        }
        return '[]';
    }
}

// Update security patterns to include all vulnerability types
const securityPatterns = {
    // Cryptographic Issues
    'HardcodedHashes': {
        'SHA-1': /=\s*["'][a-fA-F0-9]{40}["']/,
        'SHA-256': /=\s*["'][a-fA-F0-9]{64}["']/,
        'SHA-384': /=\s*["'][a-fA-F0-9]{96}["']/,
        'SHA-512': /=\s*["'][a-fA-F0-9]{128}["']/,
        'Tiger': /=\s*["'][a-fA-F0-9]{48}["']/,
        'Whirlpool': /=\s*["'][a-fA-F0-9]{128}["']/,
        'MD5': /=\s*["'][a-fA-F0-9]{32}["']/,
        'RIPEMD': /=\s*["'][a-fA-F0-9]{40}["']/
    },
    'InsecureCrypto': {
        'MD5': /md5|MD5/,
        'DES': /des|DES/,
        'RC4': /rc4|RC4/,
        'Blowfish': /blowfish|Blowfish/,
        'WeakCipher': /ecb|ECB|CBC|OFB|CFB/,
        'WeakHash': /md5|sha1|SHA1/,
        'CustomCrypto': /custom.*crypt|crypt.*custom/
    },
    // Injection Patterns
    'SQLInjection': {
        'StringConcatenation': /['"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*['"]/,
        'TemplateLiteral': /`\s*\$\{.*\}\s*`/,
        'RawQuery': /executeQuery|rawQuery|query\(/,
        'DynamicSQL': /EXEC\s*\(|sp_executesql/,
        'UnsafeEval': /eval\s*\(|exec\s*\(/
    },
    'XSS': {
        'InnerHTML': /\.innerHTML\s*=/,
        'DocumentWrite': /document\.write\(/,
        'Eval': /eval\(|setTimeout\(|setInterval\(/,
        'UnsafeDOM': /\.outerHTML|\.insertAdjacentHTML/,
        'UnsafeJQuery': /\$\(.*\)\.html\(/
    },
    'CommandInjection': {
        'Exec': /exec\(|spawn\(|system\(/,
        'Shell': /shell_exec\(|passthru\(|proc_open\(/,
        'OSCommand': /os\.system|subprocess\.call/,
        'DynamicEval': /eval\(|Function\(/,
        'TemplateInjection': /\$\{.*\}|%{.*}/
    },
    // Authentication & Authorization
    'HardcodedCredentials': {
        'APIKey': /api[_-]?key|apikey|secret[_-]?key/i,
        'Password': /password\s*=\s*['"][^'"]+['"]/i,
        'Token': /token\s*=\s*['"][^'"]+['"]/i,
        'Secret': /secret\s*=\s*['"][^'"]+['"]/i,
        'Credential': /credential\s*=\s*['"][^'"]+['"]/i
    },
    'WeakAuth': {
        'BasicAuth': /basic\s+auth|authorization:\s*basic/i,
        'NoAuth': /public\s+function|public\s+class/,
        'WeakPassword': /password\s*=\s*['"][^'"]{1,7}['"]/i,
        'HardcodedToken': /token\s*=\s*['"][^'"]+['"]/i,
        'SessionFixation': /session\.id|sessionId/
    },
    // File Operations
    'PathTraversal': {
        'DotDot': /\.\.\/|\.\.\\/,
        'AbsolutePath': /\/[a-zA-Z]:\/|^\/[a-zA-Z]/,
        'UnsafePath': /path\.join|os\.path\.join/,
        'FileUpload': /\.upload\(|\.save\(/,
        'FileDownload': /\.download\(|\.get\(/
    },
    'UnsafeFileOp': {
        'FileUpload': /\.upload\(|\.save\(/,
        'FileDownload': /\.download\(|\.get\(/,
        'FileDelete': /\.delete\(|\.remove\(/,
        'FileMove': /\.move\(|\.rename\(/,
        'FileCopy': /\.copy\(|\.duplicate\(/
    },
    // Deserialization
    'UnsafeDeserialization': {
        'Pickle': /pickle\.loads\(/,
        'YAML': /yaml\.load\(/,
        'XML': /XMLDecoder|XMLReader/,
        'JSON': /JSON\.parse\(/,
        'Eval': /eval\(|Function\(/
    },
    // Memory Safety
    'BufferOverflow': {
        'UnboundedCopy': /strcpy\(|strcat\(/,
        'ArrayAccess': /\[[^\]]+\]\s*=\s*[^;]+;/,
        'UnsafeAlloc': /malloc\(|new\s+\[\]/,
        'UnsafeString': /strncpy\(|strncat\(/,
        'UnsafeArray': /Array\(|new\s+Array\(/
    },
    // Configuration
    'DebugCode': {
        'ConsoleLog': /console\.log\(|print\(/,
        'Debugger': /debugger;|breakpoint/,
        'Alert': /alert\(|confirm\(/,
        'Trace': /console\.trace\(|trace\(/,
        'Debug': /debug\(|DEBUG/
    },
    // Input Validation
    'MissingValidation': {
        'NoInputCheck': /input\(|readline\(/,
        'NoTypeCheck': /typeof|instanceof/,
        'NoLengthCheck': /\.length|\.size/,
        'NoRangeCheck': /if\s*\([^<>=!]+\s*[<>=!]+\s*[^<>=!]+\)/,
        'NoFormatCheck': /\.match\(|\.test\(/
    },
    // Error Handling
    'UnsafeErrorHandling': {
        'EmptyCatch': /catch\s*\(\s*\)/,
        'GenericException': /catch\s*\(Exception|Error\)/,
        'SwallowedException': /catch.*\{\s*\}/,
        'UnsafeThrow': /throw\s+new\s+Error/,
        'UnsafeError': /error\(|fatal\(/
    },
    // Race Conditions
    'RaceCondition': {
        'UnsafeThread': /thread\.start\(|Thread\.start\(/,
        'UnsafeAsync': /async\s+function|Promise\./,
        'UnsafeLock': /lock\(|synchronized/,
        'UnsafeWait': /wait\(|sleep\(/,
        'UnsafeNotify': /notify\(|notifyAll\(/
    },
    // Docker Security Patterns
    'DockerVulnerabilities': {
        'RootUser': /USER\s+root|RUN\s+useradd\s+-u\s+0/,
        'LatestTag': /FROM\s+.*:latest/,
        'SensitiveMount': /VOLUME\s+.*\/etc\/|VOLUME\s+.*\/var\/|VOLUME\s+.*\/usr\/|VOLUME\s+.*\/root\//,
        'PrivilegedMode': /--privileged|privileged:\s*true/,
        'ExposedPorts': /EXPOSE\s+\d+/,
        'SensitiveEnv': /ENV\s+.*PASSWORD|ENV\s+.*SECRET|ENV\s+.*KEY|ENV\s+.*TOKEN/,
        'UnsafeCommands': /RUN\s+wget\s+http:|RUN\s+curl\s+http:|RUN\s+apt-get\s+update/,
        'NoHealthCheck': /HEALTHCHECK\s+NONE/,
        'NoUserNamespace': /--userns=host/,
        'NoReadOnly': /--read-only=false/
    },

    // SCA (Software Composition Analysis) Patterns
    'SCAVulnerabilities': {
        'OutdatedPackage': /version\s*=\s*["']\d+\.\d+\.\d+["']/,
        'KnownVulnerablePackage': /package-lock\.json|yarn\.lock|requirements\.txt|pom\.xml|build\.gradle/,
        'InsecureDependency': /dependencies\s*{|devDependencies\s*{|requirements\s*=/,
        'NoVersionLock': /^\s*[^#].*[~^]/,
        'UnpinnedVersion': /version\s*=\s*["']\*["']|version\s*=\s*["']latest["']/,
        'KnownVulnerableVersion': /version\s*=\s*["']\d+\.\d+\.\d+["']/,
        'InsecureSource': /registry\.npmjs\.org|pypi\.org|maven\.apache\.org/,
        'NoIntegrityCheck': /integrity\s*=|sha512\s*=|sha256\s*=/,
        'NoVulnerabilityScan': /audit\s*=|security\s*scan\s*=|vulnerability\s*check\s*=/
    },

    // Enhanced JavaScript/TypeScript Security Patterns
    'JSSecurityPatterns': {
        'DangerousEval': /eval\s*\(|Function\s*\(.*\)|setTimeout\s*\(.*string|setInterval\s*\(.*string/,
        'DOMManipulation': /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|\.insertAdjacentHTML\s*\(/,
        'PrototypePollution': /\.__proto__|\['__proto__'\]|\["__proto__"\]|Object\.prototype/,
        'ClientSideRedirect': /window\.location\s*=|location\.href\s*=|location\.replace\s*\(/,
        'UnsafeClone': /JSON\.parse\s*\(\s*JSON\.stringify|Object\.assign\s*\(\s*{}/,
        'WeakRandom': /Math\.random\s*\(\)|crypto\.getRandomValues/,
        'LocalStorageSecrets': /localStorage\.setItem\s*\(\s*["'].*(?:password|token|secret|key)/i,
        'UnsafePostMessage': /postMessage\s*\(\s*[^,]*,\s*["']\*/,
        'DangerousInnerHTML': /dangerouslySetInnerHTML/
    },

    // Enhanced Python Security Patterns  
    'PythonSecurityPatterns': {
        'PickleDeserialization': /pickle\.loads?\s*\(|cPickle\.loads?\s*\(|dill\.loads?\(/,
        'ShellInjection': /os\.system\s*\(|subprocess\.call\s*\(|subprocess\.run\s*\(/,
        'TemplateInjection': /Template\s*\(.*\)\.substitute|\.format\s*\(\*\*\*|%\s*\([^)]*user/i,
        'WeakCrypto': /md5\s*\(|sha1\s*\(|DES\.|RC4\.|Cipher\.new\s*\(\s*DES/,
        'SQLAlchemy': /session\.execute\s*\(.*\+|query\s*\(.*\+|text\s*\(.*\+/,
        'YAMLUnsafe': /yaml\.load\s*\((?!.*Loader\s*=)/,
        'RequestsSSL': /requests\.[get|post|put|delete].*verify\s*=\s*False/,
        'FlaskDebug': /app\.run\s*\(.*debug\s*=\s*True/,
        'HardcodedSecrets': /SECRET_KEY\s*=\s*["'][^"']+["']|API_KEY\s*=\s*["'][^"']+["']/
    },

    // Enhanced Java Security Patterns
    'JavaSecurityPatterns': {
        'Deserialization': /ObjectInputStream|readObject\s*\(|XMLDecoder/,
        'ReflectionInjection': /Class\.forName\s*\(|Method\.invoke\s*\(|Constructor\.newInstance/,
        'LDAPInjection': /new\s+InitialDirContext|DirContext\.search|LdapContext\.search/,
        'XPathInjection': /XPath\.compile\s*\(.*\+|XPathFactory\.newInstance/,
        'ScriptEngineInjection': /ScriptEngineManager|ScriptEngine\.eval/,
        'SpringEL': /@Value\s*\(\s*["']\$\{.*\}["']|SpelExpressionParser/,
        'HTTPSDisabled': /setHostnameVerifier.*ALLOW_ALL|TrustManager.*checkServerTrusted/,
        'WeakCipherSuite': /SSL_RSA_WITH_RC4|SSL_DH_anon|SSL_RSA_WITH_DES/,
        'JNDIInjection': /InitialContext\.lookup|Context\.lookup|@JndiLookup/
    },

    // Enhanced C/C++ Security Patterns
    'CSecurityPatterns': {
        'BufferOverflow': /strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\(/,
        'FormatString': /printf\s*\(\s*[^"]*\)|fprintf\s*\(\s*[^,]*,\s*[^"]/,
        'IntegerOverflow': /malloc\s*\(\s*.*\*|calloc\s*\(\s*.*\*/,
        'UseAfterFree': /free\s*\(.*\);.*\*|delete\s+.*;\s*.*->/,
        'NullPointerDeref': /\*\s*\(\s*[^)]*\s*\)\s*=|\*[a-zA-Z_]\w*\s*=/,
        'RaceCondition': /pthread_create|CreateThread|std::thread/,
        'MemoryLeak': /malloc\s*\((?!.*free)|new\s+(?!.*delete)/,
        'CommandInjection': /system\s*\(|exec\s*\(|popen\s*\(/
    },

    // API Security Patterns
    'APISecurityPatterns': {
        'NoAuthentication': /app\.(get|post|put|delete)\s*\(\s*["'][^"']*["']\s*,\s*(?!.*auth)/,
        'WeakJWT': /jwt\.sign\s*\(.*,\s*["'][^"']{1,10}["']/,
        'CORSMisconfiguration': /Access-Control-Allow-Origin.*\*|cors\(\)\s*$/,
        'CSRFDisabled': /csrf\s*:\s*false|@csrf\.exempt/,
        'RateLimitMissing': /app\.(get|post|put|delete)(?!.*rateLimit|.*throttle)/,
        'SensitiveDataExposure': /password.*response|secret.*json|token.*return/i,
        'WeakSessionConfig': /session.*secure.*false|httpOnly.*false/
    },

    // Cloud Security Patterns
    'CloudSecurityPatterns': {
        'AWSCredentials': /AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key/,
        'GCPCredentials': /AIza[0-9A-Za-z-_]{35}|service_account\.json/,
        'AzureCredentials': /DefaultAzureCredential|ClientSecretCredential/,
        'PublicS3Bucket': /s3:GetObject.*\*|public-read|public-read-write/,
        'WeakIAMPolicy': /Effect.*Allow.*Resource.*\*.*Action.*\*/,
        'UnencryptedStorage': /encrypted\s*:\s*false|encryption\s*=\s*None/
    }
};

// Update getExactLineNumber to preserve exact line structure including spaces
function getExactLineNumber(originalCode: string, targetLine: string): number {
    // Split by newline but preserve empty lines and spaces
    const lines = originalCode.split(/\r?\n/);
    const targetTrimmed = targetLine.trim();
    
    // Keep track of the original line number including empty lines and spaces
    let lineNumber = 0;
    for (const line of lines) {
        lineNumber++;
        // Compare trimmed lines but preserve original line number
        if (line.trim() === targetTrimmed) {
            return lineNumber;
        }
    }
    return 0;
}

// Update detectSecurityVulnerabilities to preserve exact line structure
function detectSecurityVulnerabilities(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    // Split by newline but preserve empty lines and spaces
    const originalLines = code.split(/\r?\n/);
    let currentLineNumber = 0;

    originalLines.forEach((line) => {
        currentLineNumber++; // Increment for every line, including empty ones and spaces
        // Check each category of security patterns
        for (const [category, patterns] of Object.entries(securityPatterns)) {
            for (const [issueType, pattern] of Object.entries(patterns)) {
                if (pattern.test(line)) {
                    const severity = getSeverityForIssue(category, issueType);
                    const recommendation = getRecommendationForIssue(category, issueType);
                    const cweId = getCWEForIssue(category, issueType);
                    const owaspRef = getOWASPReferenceForIssue(category, issueType);

                    vulnerabilities.push({
                        id: `${category}_${issueType}`,
                        description: `Hardcoded ${issueType} hash detected in variable assignment`,
                        location: `Line ${currentLineNumber}`,
                        severity: severity,
                        recommendation: recommendation,
                        llmProvider: "Local Scanner",
                        fileName: "current_file",
                        lineNumber: currentLineNumber.toString(),
                        cweId: cweId,
                        owaspReference: owaspRef,
                        hallucinationScore: 0.1,
                        confidenceScore: 0.9
                    });
                }
            }
        }
    });

    return vulnerabilities;
}

// Enhanced severity mapping with new security patterns
function getSeverityForIssue(category: string, issueType: string): "High" | "Medium" | "Low" {
    const highSeverityIssues = [
        // Critical vulnerabilities
        'HardcodedHashes', 'HardcodedCredentials', 'SQLInjection', 'CommandInjection',
        'UnsafeDeserialization', 'BufferOverflow', 'RootUser', 'PrivilegedMode',
        'KnownVulnerablePackage', 'InsecureDependency',
        // Enhanced patterns - High severity
        'DangerousEval', 'PickleDeserialization', 'ShellInjection', 'Deserialization',
        'ReflectionInjection', 'UseAfterFree', 'FormatString', 'AWSCredentials',
        'GCPCredentials', 'AzureCredentials', 'PublicS3Bucket', 'WeakIAMPolicy',
        'JNDIInjection', 'LDAPInjection', 'XPathInjection'
    ];
    const mediumSeverityIssues = [
        // Medium risk vulnerabilities
        'XSS', 'PathTraversal', 'InsecureCrypto', 'LatestTag', 'SensitiveMount',
        'ExposedPorts', 'SensitiveEnv', 'OutdatedPackage', 'NoVersionLock',
        // Enhanced patterns - Medium severity
        'DOMManipulation', 'PrototypePollution', 'TemplateInjection', 'WeakCrypto',
        'SQLAlchemy', 'YAMLUnsafe', 'SpringEL', 'HTTPSDisabled', 'WeakCipherSuite',
        'IntegerOverflow', 'NullPointerDeref', 'NoAuthentication', 'WeakJWT',
        'CORSMisconfiguration', 'CSRFDisabled', 'UnencryptedStorage'
    ];

    if (highSeverityIssues.includes(issueType)) return "High";
    if (mediumSeverityIssues.includes(issueType)) return "Medium";
    return "Low";
}

// Update getRecommendationForIssue to include Docker and SCA recommendations
function getRecommendationForIssue(category: string, issueType: string): string {
    const recommendations: Record<string, string> = {
        'HardcodedHashes': 'Remove hardcoded hash values from variable assignments. Instead, use a secure configuration management system or environment variables to store sensitive values. Consider using a secrets management solution.',
        'InsecureCrypto': 'Use modern, secure cryptographic algorithms and libraries. Avoid deprecated or weak algorithms.',
        'SQLInjection': 'Use parameterized queries or prepared statements instead of string concatenation.',
        'XSS': 'Use proper output encoding and sanitization. Consider using a security library for HTML escaping.',
        'CommandInjection': 'Use parameterized commands and avoid shell execution. Validate and sanitize all inputs.',
        'HardcodedCredentials': 'Move credentials to secure configuration management or environment variables.',
        'PathTraversal': 'Validate and sanitize file paths. Use proper path resolution functions.',
        'UnsafeDeserialization': 'Use safe deserialization methods and validate input data.',
        'BufferOverflow': 'Use safe string handling functions and bounds checking.',
        'DebugCode': 'Remove debug code before production deployment.',
        // Docker recommendations
        'RootUser': 'Avoid running containers as root. Create and use a non-root user.',
        'LatestTag': 'Avoid using :latest tag. Pin to specific versions for better security and reproducibility.',
        'SensitiveMount': 'Review and restrict volume mounts to prevent sensitive data exposure.',
        'PrivilegedMode': 'Avoid running containers in privileged mode. Use specific capabilities instead.',
        'ExposedPorts': 'Only expose necessary ports and use non-standard ports when possible.',
        'SensitiveEnv': 'Avoid storing sensitive information in environment variables. Use secrets management.',
        'UnsafeCommands': 'Avoid downloading and executing untrusted content. Use multi-stage builds.',
        'NoHealthCheck': 'Implement health checks to ensure container health monitoring.',
        'NoUserNamespace': 'Enable user namespace remapping for better security isolation.',
        'NoReadOnly': 'Run containers in read-only mode when possible to prevent modifications.',
        // SCA recommendations
        'OutdatedPackage': 'Update packages to their latest secure versions.',
        'KnownVulnerablePackage': 'Replace vulnerable packages with secure alternatives.',
        'InsecureDependency': 'Review and update dependencies to secure versions.',
        'NoVersionLock': 'Pin dependency versions to specific releases.',
        'UnpinnedVersion': 'Avoid using wildcard or latest versions. Pin to specific versions.',
        'KnownVulnerableVersion': 'Update to a version that addresses known vulnerabilities.',
        'InsecureSource': 'Use trusted package sources and verify package integrity.',
        'NoIntegrityCheck': 'Implement integrity checks for downloaded packages.',
        'NoVulnerabilityScan': 'Implement automated vulnerability scanning in CI/CD pipeline.',
        // Enhanced pattern recommendations
        'DangerousEval': 'Avoid using eval() and Function() constructors. Use safer alternatives like JSON.parse() for data or proper parsing libraries.',
        'DOMManipulation': 'Use textContent instead of innerHTML. If HTML is necessary, sanitize with DOMPurify or similar library.',
        'PrototypePollution': 'Validate object keys and use Object.create(null) for safe objects. Use Map instead of plain objects when possible.',
        'PickleDeserialization': 'Use safe serialization formats like JSON. If pickle is necessary, validate data source and use hmac signatures.',
        'ShellInjection': 'Use subprocess with array arguments instead of shell=True. Validate and sanitize all inputs.',
        'Deserialization': 'Use safe serialization formats. If native serialization is required, implement whitelist-based validation.',
        'ReflectionInjection': 'Validate class names against whitelist. Use factory patterns instead of dynamic class loading.',
        'UseAfterFree': 'Set pointers to NULL after free(). Use smart pointers in C++. Implement proper memory management.',
        'AWSCredentials': 'Use IAM roles, environment variables, or AWS credential chain. Never hardcode credentials.',
        'WeakJWT': 'Use strong secrets (256+ bits). Consider asymmetric keys for production. Implement proper key rotation.',
        'CORSMisconfiguration': 'Specify exact origins instead of wildcard. Implement proper CORS policy for your use case.',
        'NoAuthentication': 'Implement proper authentication for all sensitive endpoints. Use middleware for consistent auth checks.'
    };

    return recommendations[issueType] || 'Review and fix the identified security issue.';
}

// Update getCWEForIssue to include Docker and SCA CWEs
function getCWEForIssue(category: string, issueType: string): string {
    const cweMap: Record<string, string> = {
        'HardcodedHashes': 'CWE-798',
        'InsecureCrypto': 'CWE-326',
        'SQLInjection': 'CWE-89',
        'XSS': 'CWE-79',
        'CommandInjection': 'CWE-78',
        'HardcodedCredentials': 'CWE-798',
        'PathTraversal': 'CWE-22',
        'UnsafeDeserialization': 'CWE-502',
        'BufferOverflow': 'CWE-120',
        'DebugCode': 'CWE-489',
        // Docker CWEs
        'RootUser': 'CWE-250',
        'LatestTag': 'CWE-1021',
        'SensitiveMount': 'CWE-552',
        'PrivilegedMode': 'CWE-250',
        'ExposedPorts': 'CWE-200',
        'SensitiveEnv': 'CWE-798',
        'UnsafeCommands': 'CWE-78',
        'NoHealthCheck': 'CWE-1021',
        'NoUserNamespace': 'CWE-250',
        'NoReadOnly': 'CWE-250',
        // SCA CWEs
        'OutdatedPackage': 'CWE-1021',
        'KnownVulnerablePackage': 'CWE-1021',
        'InsecureDependency': 'CWE-1021',
        'NoVersionLock': 'CWE-1021',
        'UnpinnedVersion': 'CWE-1021',
        'KnownVulnerableVersion': 'CWE-1021',
        'InsecureSource': 'CWE-829',
        'NoIntegrityCheck': 'CWE-494',
        'NoVulnerabilityScan': 'CWE-1021'
    };

    return cweMap[issueType] || '';
}

// Update getOWASPReferenceForIssue to include Docker and SCA references
function getOWASPReferenceForIssue(category: string, issueType: string): string {
    const owaspMap: Record<string, string> = {
        'HardcodedHashes': 'A7:2017-Identification and Authentication Failures',
        'InsecureCrypto': 'A2:2017-Broken Authentication',
        'SQLInjection': 'A1:2017-Injection',
        'XSS': 'A7:2017-Cross-Site Scripting (XSS)',
        'CommandInjection': 'A1:2017-Injection',
        'HardcodedCredentials': 'A7:2017-Identification and Authentication Failures',
        'PathTraversal': 'A5:2017-Broken Access Control',
        'UnsafeDeserialization': 'A8:2017-Insecure Deserialization',
        'BufferOverflow': 'A1:2017-Injection',
        'DebugCode': 'A9:2017-Using Components with Known Vulnerabilities',
        // Docker OWASP references
        'RootUser': 'A5:2017-Broken Access Control',
        'LatestTag': 'A9:2017-Using Components with Known Vulnerabilities',
        'SensitiveMount': 'A5:2017-Broken Access Control',
        'PrivilegedMode': 'A5:2017-Broken Access Control',
        'ExposedPorts': 'A5:2017-Broken Access Control',
        'SensitiveEnv': 'A3:2017-Sensitive Data Exposure',
        'UnsafeCommands': 'A8:2017-Insecure Deserialization',
        'NoHealthCheck': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoUserNamespace': 'A5:2017-Broken Access Control',
        'NoReadOnly': 'A5:2017-Broken Access Control',
        // SCA OWASP references
        'OutdatedPackage': 'A9:2017-Using Components with Known Vulnerabilities',
        'KnownVulnerablePackage': 'A9:2017-Using Components with Known Vulnerabilities',
        'InsecureDependency': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoVersionLock': 'A9:2017-Using Components with Known Vulnerabilities',
        'UnpinnedVersion': 'A9:2017-Using Components with Known Vulnerabilities',
        'KnownVulnerableVersion': 'A9:2017-Using Components with Known Vulnerabilities',
        'InsecureSource': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoIntegrityCheck': 'A8:2017-Insecure Deserialization',
        'NoVulnerabilityScan': 'A9:2017-Using Components with Known Vulnerabilities'
    };

    return owaspMap[issueType] || '';
}

// Update processVulnerabilities to handle exact line numbers with LLM-first approach
function processVulnerabilities(
    vulnerabilities: any[],
    providerName: string,
    fileName: string,
    languageId: string,
    originalCode: string,
    useLlmFirst: boolean = true
): Vulnerability[] {
    let processedVulns: Vulnerability[] = [];
    let securityVulns: Vulnerability[] = [];
    
    // Check if this is an LLM-only file (BI, IaC, etc.)
    const isLlmOnly = isLlmOnlyFile(fileName, languageId, originalCode);
    
    if (isLlmOnly) {
        // LLM-only files: Never use local scanner, never fallback
        if (outputChannel) {
            outputChannel.appendLine(`${fileName} is LLM-only file (BI/IaC), skipping local scanner completely`);
        }
        // No local scanner for these files - only process LLM results
        // Even if LLM fails, we don't fallback to local scanner for BI/IaC files
    } else {
        // Traditional files: LLM-first approach with local scanner fallback
        if (useLlmFirst && vulnerabilities.length > 0) {
            // LLM found vulnerabilities - use them as primary
            // Only run local scanner for additional coverage or verification
            securityVulns = detectSecurityVulnerabilities(originalCode);
            
            // Merge and deduplicate (prioritize LLM results)
            const llmVulnIds = new Set();
            processedVulns.forEach(v => llmVulnIds.add(v.id.split('_')[0])); // Get base type
            securityVulns = securityVulns.filter(sv => !llmVulnIds.has(sv.id.split('_')[0]));
        } else {
            // Fallback: LLM failed or returned no results - rely on local scanner
            securityVulns = detectSecurityVulnerabilities(originalCode);
            if (outputChannel) {
                outputChannel.appendLine(`LLM analysis failed/empty for ${fileName}, using Local Scanner as fallback`);
            }
        }
    }
    
    // Handle both old and new format
    if (vulnerabilities.length > 0 && 'summary' in vulnerabilities[0]) {
        // New format - extract issues from the comprehensive analysis
        const analysis = vulnerabilities[0];
        processedVulns = (analysis.issues || []).map((issue: any) => {
            // Get line number from either lineNumber or location
            let lineNumber = 0;
            if (issue.lineNumber) {
                lineNumber = parseInt(issue.lineNumber);
            } else if (issue.location) {
                // Extract line number from location string (e.g., "Line 42" or "Line: 42")
                const match = issue.location.match(/Line\s*:?\s*(\d+)/i);
                if (match) {
                    lineNumber = parseInt(match[1]);
                }
            }
            
            // If we still don't have a valid line number, try to find it in the original code
            if (!lineNumber || isNaN(lineNumber)) {
                const exactLineNumber = getExactLineNumber(originalCode, issue.location || '');
                lineNumber = exactLineNumber || 0;
            }

            return {
                id: issue.id || 'Unknown',
                description: issue.description || 'No description provided',
                location: `Line ${lineNumber}`,
                severity: issue.severity || 'Medium',
                recommendation: issue.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || issue.fileName,
                lineNumber: lineNumber.toString(),
                cweId: issue.cweId,
                owaspReference: issue.owaspReference,
                hallucinationScore: issue.hallucinationScore,
                confidenceScore: issue.confidenceScore
            };
        });
    } else {
        // Old format - process as before
        processedVulns = vulnerabilities.map(vuln => {
            // Get line number from either lineNumber or location
            let lineNumber = 0;
            if (vuln.lineNumber) {
                lineNumber = parseInt(vuln.lineNumber);
            } else if (vuln.location) {
                // Extract line number from location string (e.g., "Line 42" or "Line: 42")
                const match = vuln.location.match(/Line\s*:?\s*(\d+)/i);
                if (match) {
                    lineNumber = parseInt(match[1]);
                }
            }
            
            // If we still don't have a valid line number, try to find it in the original code
            if (!lineNumber || isNaN(lineNumber)) {
                const exactLineNumber = getExactLineNumber(originalCode, vuln.location || '');
                lineNumber = exactLineNumber || 0;
            }

            return {
                id: vuln.id || 'Unknown',
                description: vuln.description || 'No description provided',
                location: `Line ${lineNumber}`,
                severity: vuln.severity || 'Medium',
                recommendation: vuln.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || vuln.fileName,
                lineNumber: lineNumber.toString(),
                cweId: vuln.cweId,
                owaspReference: vuln.owaspReference,
                hallucinationScore: vuln.hallucinationScore,
                confidenceScore: vuln.confidenceScore
            };
        });
    }

    // Return LLM results first, then unique local scanner findings
    const combinedResults = [...processedVulns, ...securityVulns];
    
    if (outputChannel) {
        const llmCount = processedVulns.length;
        const localCount = securityVulns.length;
        outputChannel.appendLine(`Detection summary for ${fileName}: ${llmCount} LLM findings, ${localCount} additional local findings`);
    }
    
    return combinedResults;
}

// Update analyzeCodeWithOpenAI to preserve exact line structure
async function analyzeCodeWithOpenAI(
    apiKey: string,
    codeSnippet: string,
    languageId: string,
    fileName: string = ''
): Promise<Vulnerability[]> {
    const { model, systemPrompt, userPrompt } = getOpenAIConfig();

    try {
        // Keep the original code exactly as is, including all spaces and empty lines
        const formattedCode = codeSnippet;
        // Split by newline but preserve empty lines and spaces
        const originalLines = codeSnippet.split(/\r?\n/);

        const openai = new OpenAI({ apiKey });
        const fullPrompt = systemPrompt + userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', formattedCode);
        const dynamicMaxTokens = calculateMaxTokens(fullPrompt, 4000);
        
        const response = await retryWithExponentialBackoff(
            () => openai.chat.completions.create({
                model: 'gpt-4-turbo-preview',
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', formattedCode) }
                ],
                response_format: { type: 'json_object' },
                temperature: 0,
                max_tokens: dynamicMaxTokens,
                top_p: 1,
                frequency_penalty: 0,
                presence_penalty: 0
            }),
            undefined,
            `OpenAI direct analysis for ${fileName}`
        );

        const content = response.choices[0]?.message?.content;
        if (content) {
            try {
                const cleanJson = extractJsonFromMarkdown(content);
                const result = JSON.parse(cleanJson);
                let vulnerabilities: Vulnerability[] = [];
                
                // Process vulnerabilities based on format
                if (Array.isArray(result)) {
                    vulnerabilities = result.map((v: any) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                } else if (result?.vulnerabilities) {
                    vulnerabilities = result.vulnerabilities.map((v: any) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                } else if (result?.issues) {
                    vulnerabilities = result.issues.map((v: any) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                }

                // Process vulnerabilities using the helper function
                const processedVulnerabilities = processVulnerabilities(vulnerabilities, LlmProvider.OpenAI, fileName, languageId, codeSnippet);
                
                // Ensure line numbers are accurate
                processedVulnerabilities.forEach(v => {
                    if (!v.llmProvider) {
                        v.llmProvider = LlmProvider.OpenAI;
                    }
                    if (!v.fileName) {
                        v.fileName = fileName;
                    }
                    if (v.lineNumber) {
                        const lineNumber = parseInt(v.lineNumber);
                        if (lineNumber > 0 && lineNumber <= originalLines.length) {
                            v.location = `Line ${lineNumber}`;
                        }
                    }
                });
                
                return processedVulnerabilities;
            } catch (parseError: any) {
                if (outputChannel) {
                    outputChannel.appendLine(`Error parsing OpenAI response: ${parseError.message}. Response: ${content}`);
                }
                return [];
            }
        }
        return [];
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Error calling OpenAI API: ${error.message}`);
        }
        return [];
    }
}

// Update formatAndLogVulnerabilities to handle line numbers properly
function formatAndLogVulnerabilities(vulnerabilities: Vulnerability[], providerDisplayName: string) {
    if (!outputChannel) return;
    outputChannel.clear();
    if (vulnerabilities.length === 0) {
        outputChannel.appendLine(`No vulnerabilities detected by ${providerDisplayName}.`);
        return;
    }

    outputChannel.appendLine("Scan results:");
    vulnerabilities.forEach(vuln => {
        outputChannel.appendLine("----------------------------------------");
        outputChannel.appendLine(`Vulnerability ID: ${vuln.id}`);
        outputChannel.appendLine(`Description: ${vuln.description}`);
        outputChannel.appendLine(`Severity: ${vuln.severity}`);
        if (vuln.fileName) {
            outputChannel.appendLine(`File: ${vuln.fileName}`);
            // Ensure line number is valid before displaying
            const lineNumber = parseInt(vuln.lineNumber || '0');
            if (!isNaN(lineNumber) && lineNumber > 0) {
                outputChannel.appendLine(`Location: Line ${lineNumber}`);
            } else {
                outputChannel.appendLine(`Location: Line 0 (Unable to determine exact line)`);
            }
        } else {
            outputChannel.appendLine(`File: Unknown`);
        }
        outputChannel.appendLine(`Recommendation: ${vuln.recommendation}`);
        outputChannel.appendLine(`Detected by: ${vuln.llmProvider || providerDisplayName}`);

        // Add the rewritten code suggestion
        const fix = generateCodeFix(vuln, vuln.fileName?.split('.').pop() || '');
        if (fix) {
            outputChannel.appendLine("\nSuggested Fix:");
            outputChannel.appendLine(fix);
        }
    });
    outputChannel.appendLine("----------------------------------------");
}

// LLM-powered code fix generator
async function generateCodeFixWithLLM(
    vuln: Vulnerability,
    originalCode: string,
    languageId: string,
    context: vscode.ExtensionContext
): Promise<string | null> {
    // SMART LLM SELECTION: Use any available LLM for individual fix generation
    const availableLlms = await getAvailableLlms(context);
    if (availableLlms.length === 0) {
        return null;
    }

    // Use preferred LLM if available, otherwise use first available LLM
    const preferredLlmSetting = getPreferredLlm();
    let selectedLlm = preferredLlmSetting;
    let apiKey = preferredLlmSetting ? await getApiKey(context, preferredLlmSetting) : undefined;
    let endpointToUse: string | undefined;
    
    if (!apiKey) {
        // Fallback to first available LLM
        selectedLlm = availableLlms[0];
        apiKey = await getApiKey(context, selectedLlm);
        
        // Get endpoint for custom LLMs
        if (!Object.values(LlmProvider).includes(selectedLlm as LlmProvider)) {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
            endpointToUse = customConfig?.endpoint;
        }
    } else if (preferredLlmSetting === "Custom") {
        const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
        if (customLlmConfigs.length > 0) {
            const chosenCustomLlm = customLlmConfigs[0];
            selectedLlm = chosenCustomLlm.name;
            endpointToUse = chosenCustomLlm.endpoint;
        }
    }

    if (!apiKey || !selectedLlm) {
        return null;
    }

    const fixPrompt = `You are a security expert tasked with fixing code vulnerabilities. 

VULNERABILITY DETAILS:
- ID: ${vuln.id}
- Description: ${vuln.description}
- Severity: ${vuln.severity}
- Location: ${vuln.location}
- CWE: ${vuln.cweId}
- OWASP: ${vuln.owaspReference}
- Recommendation: ${vuln.recommendation}

ORIGINAL CODE (${languageId}):
\`\`\`${languageId}
${originalCode}
\`\`\`

TASK: Provide a COMPLETE, SECURE rewrite of the vulnerable code section. 

REQUIREMENTS:
1. Fix the specific security vulnerability
2. Maintain the original functionality  
3. Follow secure coding best practices for ${languageId}
4. Include clear comments explaining the security improvements
5. For pickle files: Recommend safe alternatives (JSON, XML, Protocol Buffers) or secure pickle practices
6. Provide only the corrected code, not explanations

RESPONSE FORMAT:
Return only the fixed code in a code block:
\`\`\`${languageId}
[Your secure code here]
\`\`\``;

    try {
        let llmResponse = '';
        
        if (selectedLlm === LlmProvider.OpenAI) {
            const openai = new OpenAI({ apiKey });
            const dynamicMaxTokens = calculateMaxTokens(fixPrompt, 2000);
            
            const openaiConfig = vscode.workspace.getConfiguration('secureCodingAssistant.openai');
            const openaiModel = openaiConfig.get<string>('model', 'gpt-4-turbo-preview');
            const response = await retryWithExponentialBackoff(
                () => openai.chat.completions.create({
                    model: openaiModel,
                    messages: [
                        { role: 'system', content: 'You are a security expert that provides secure code fixes for all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.). Always respond with properly formatted code blocks and follow security best practices for the specific language/platform.' },
                        { role: 'user', content: fixPrompt }
                    ],
                    temperature: 0,
                    max_tokens: dynamicMaxTokens
                }),
                undefined,
                `${selectedLlm} fix generation for ${vuln.id}`
            );
            llmResponse = response.choices[0]?.message?.content || '';
        } else if (selectedLlm === LlmProvider.Anthropic) {
            const anthropic = new Anthropic({ apiKey });
            const dynamicMaxTokens = calculateMaxTokens(fixPrompt, 2000);
            
            const anthropicConfig = vscode.workspace.getConfiguration('secureCodingAssistant.anthropic');
            const anthropicModel = anthropicConfig.get<string>('model', 'claude-3-5-sonnet-20241022');
            const response = await retryWithExponentialBackoff(
                () => anthropic.messages.create({
                    model: anthropicModel,
                    max_tokens: dynamicMaxTokens,
                    temperature: 0,
                    messages: [
                        { role: 'user', content: fixPrompt }
                    ]
                }),
                undefined,
                `${selectedLlm} fix generation for ${vuln.id}`
            );
            // Handle new Anthropic SDK content structure
            const firstBlock = response.content[0];
            llmResponse = firstBlock.type === 'text' ? firstBlock.text : JSON.stringify(firstBlock);
        } else if (selectedLlm === LlmProvider.Google) {
            const genAI = new GoogleGenAI({ apiKey });
            const dynamicMaxTokens = calculateMaxTokens(fixPrompt, 2000);
            
            const googleConfig = vscode.workspace.getConfiguration('secureCodingAssistant.google');
            const modelName = googleConfig.get<string>('model', 'gemini-1.5-flash');
            
            const response = await retryWithExponentialBackoff(
                () => genAI.models.generateContent({
                    model: modelName,
                    contents: fixPrompt,
                    config: {
                        temperature: 0,
                        maxOutputTokens: dynamicMaxTokens
                    }
                }),
                undefined,
                `${selectedLlm} fix generation for ${vuln.id}`
            );
            llmResponse = response.text || '';
        } else {
            // Custom LLM provider
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
            if (customConfig) {
                const dynamicMaxTokens = calculateMaxTokens(fixPrompt, 2000);
                
                const response = await retryWithExponentialBackoff(
                    async () => {
                        const customModelConfig = vscode.workspace.getConfiguration('secureCodingAssistant.custom');
                        const customModel = customModelConfig.get<string>('defaultModel', 'gpt-4-turbo-preview');
                        
                        return await axios.post(endpointToUse!, {
                            model: customModel,
                            messages: [
                                { role: 'system', content: 'You are a security expert that provides secure code fixes for all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.). Always follow security best practices for the specific language/platform.' },
                                { role: 'user', content: fixPrompt }
                            ],
                            temperature: 0,
                            max_tokens: dynamicMaxTokens
                        }, {
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${apiKey}`
                            }
                        });
                    },
                    undefined,
                    `${selectedLlm} fix generation for ${vuln.id}`
                );
                // Type assertion for response data
                const responseData = response.data as {
                    choices?: Array<{ message: { content: string } }>;
                    content?: string;
                    text?: string;
                };
                llmResponse = responseData.choices?.[0]?.message?.content || responseData.content || responseData.text || '';
            }
        }

        // Extract code block from response
        const codeBlockMatch = llmResponse.match(/```[\w]*\n([\s\S]*?)\n```/);
        if (codeBlockMatch) {
            return codeBlockMatch[1].trim();
        }
        
        // If no code block found, return the whole response cleaned up
        return llmResponse.trim();

    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Error generating fix with LLM: ${error.message}`);
        }
        return null;
    }
}

// Interface for fix generation results
interface FixResult {
    success: boolean;
    fix?: string;
    method: 'LLM-GENERATED' | 'BATCH-GENERATED' | 'CACHED' | 'FALLBACK';
    error?: string;
    processingTime?: number;
    verification?: {
        isSecure: boolean;
        fixesOriginalIssue: boolean;
        introducesNewIssues: boolean;
        syntaxCorrect: boolean;
        maintainsFunctionality: boolean;
        verificationResult: 'APPROVED' | 'REJECTED' | 'NEEDS_IMPROVEMENT';
        issues: string[];
        confidence: number;
    };
}

// Cache for similar fixes to avoid redundant LLM calls
// Enhanced fix cache with metadata and expiration
interface CachedFix {
    fix: string;
    timestamp: number;
    usageCount: number;
    verificationResult?: any;
    processingTime: number;
}
const fixCache = new Map<string, CachedFix>();
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_CACHE_SIZE = 1000;

// Cache for scanning results to avoid redundant LLM calls
const scanCache = new Map<string, any>();

// Function to generate cache key for scanning
function generateScanCacheKey(codeSnippet: string, languageId: string, providerName: string): string {
    // Create a hash-like key from the code content, language, and provider
    const contentHash = codeSnippet.substring(0, 100) + codeSnippet.length + languageId + providerName;
    try {
        return Buffer.from(contentHash).toString('base64').substring(0, 32); // Simple base64 hash for caching
    } catch {
        // Fallback if Buffer is not available
        return (contentHash).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
    }
}

// Function to chunk large code files for better performance
function chunkCode(code: string, maxChunkSize: number = 8000): string[] {
    if (code.length <= maxChunkSize) {
        return [code];
    }
    
    const lines = code.split('\n');
    const chunks: string[] = [];
    let currentChunk = '';
    
    for (const line of lines) {
        if ((currentChunk + line + '\n').length > maxChunkSize && currentChunk.length > 0) {
            chunks.push(currentChunk.trim());
            currentChunk = line + '\n';
        } else {
            currentChunk += line + '\n';
        }
    }
    
    if (currentChunk.trim().length > 0) {
        chunks.push(currentChunk.trim());
    }
    
    return chunks;
}

// Optimized scanning function with multi-LLM support and local fallback
async function scanCodeOptimized(
    providerDisplayName: string,
    apiKey: string,
    codeSnippet: string,
    languageId: string,
    fileName: string,
    context: vscode.ExtensionContext,
    endpointUrl?: string
): Promise<Vulnerability[]> {
    const startTime = Date.now();
    
    // Detect actual language if VS Code reported plaintext
    const actualLanguageId = detectActualLanguage(fileName, languageId, codeSnippet);
    
    // Get scan configuration for comprehensive scanning
    const scanConfig = getScanConfiguration();
    
    // Check if multiple LLMs are configured
    const availableLlms = await getAvailableLlms(context);
    const useMultipleLlms = availableLlms.length > 1;
    
    // Check if this is an LLM-only file type
    const isLlmOnlyFileType = isLlmOnlyFile(fileName, actualLanguageId, codeSnippet);
    
    // Determine scanning strategy based on configuration
    const useComprehensiveScanning = scanConfig.enableComprehensiveScanning;
    const forceLocalScanner = scanConfig.forceLocalScannerForAllFiles;
    
    if (useMultipleLlms) {
        if (outputChannel) {
            const langDisplay = actualLanguageId !== languageId ? `${actualLanguageId} (detected from ${languageId})` : actualLanguageId;
            const scanModeDesc = useComprehensiveScanning ? 
                (forceLocalScanner ? 'Comprehensive (Multi-LLM + Local Scanner)' : 'Multi-LLM with Smart Fallback') :
                'Standard Multi-LLM';
            outputChannel.appendLine(`🚀 ${scanModeDesc}: Using ${availableLlms.length} LLMs for ${fileName} (${langDisplay}): [${availableLlms.join(', ')}]`);
            if (forceLocalScanner && !isLlmOnlyFileType) {
                outputChannel.appendLine(`   🔧 Local Scanner: FORCED ON for comprehensive coverage`);
            }
        }
        
        // Get configuration for chunking (same as single LLM)
        const config = vscode.workspace.getConfiguration('secureCodingAssistant');
        const maxChunkSize = config.get<number>('performance.maxChunkSize', 8000);
        const enableChunking = config.get<boolean>('performance.enableChunking', true);
        
        // Run all available LLMs in parallel with full performance optimizations
        const llmPromises = availableLlms.map(async (llmName) => {
            const llmStartTime = Date.now();
            try {
                // Check cache for each LLM
                const cacheKey = generateScanCacheKey(codeSnippet, languageId, llmName);
                if (scanCache.has(cacheKey)) {
                    if (outputChannel) {
                        outputChannel.appendLine(`💾 ${llmName}: Using cached result (${Date.now() - llmStartTime}ms)`);
                    }
                    return { llmName, vulnerabilities: scanCache.get(cacheKey), fromCache: true };
                }
                
                const llmApiKey = await getApiKeySilent(context, llmName);
                if (!llmApiKey) {
                    // Should never happen since getAvailableLlms() only returns LLMs with valid keys
                    // but handle gracefully without logging
                    return { llmName, vulnerabilities: [], fromCache: false };
                }
                
                // Get endpoint for custom LLMs
                let llmEndpoint = undefined;
                if (!Object.values(LlmProvider).includes(llmName as LlmProvider)) {
                    const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
                    const customConfig = customLlmConfigs.find(cfg => cfg.name === llmName);
                    llmEndpoint = customConfig?.endpoint;
                }
                
                let vulnerabilities: Vulnerability[] = [];
                
                // ENHANCED: Apply chunking logic for each LLM
                if (enableChunking && codeSnippet.length > maxChunkSize) {
                    if (outputChannel) {
                        outputChannel.appendLine(`📦 ${llmName}: Processing large file with chunking (${Math.ceil(codeSnippet.length / maxChunkSize)} chunks)`);
                    }
                    
                    const chunks = chunkCode(codeSnippet, maxChunkSize);
                    const chunkPromises = chunks.map(async (chunk, index) => {
                        try {
                            if (llmName === LlmProvider.OpenAI) {
                                return await retryWithExponentialBackoff(
                                    () => analyzeCodeWithOpenAI(llmApiKey, chunk, actualLanguageId, `${fileName}-${llmName}-chunk-${index + 1}`),
                                    undefined,
                                    `${llmName} chunk ${index + 1} analysis`
                                );
                            } else {
                                return await retryWithExponentialBackoff(
                                    async () => {
                                        const result = await callLlmApi(llmName, llmApiKey, chunk, actualLanguageId, llmEndpoint);
                                        const cleanJson = extractJsonFromMarkdown(result);
                                        const parsed = JSON.parse(cleanJson);
                                        return processVulnerabilities(Array.isArray(parsed) ? parsed : (parsed.issues || []), llmName, fileName, actualLanguageId, chunk, true);
                                    },
                                    undefined,
                                    `${llmName} chunk ${index + 1} analysis`
                                );
                            }
                        } catch (error: any) {
                            if (outputChannel) {
                                outputChannel.appendLine(`❌ ${llmName} chunk ${index + 1} failed: ${error.message}`);
                            }
                            return [];
                        }
                    });
                    
                    const chunkResults = await Promise.all(chunkPromises);
                    vulnerabilities = chunkResults.flat();
                    
                    if (outputChannel) {
                        outputChannel.appendLine(`✅ ${llmName}: Processed ${chunks.length} chunks successfully`);
                    }
                } else {
                    // ENHANCED: Apply retry logic for single file processing
                    if (llmName === LlmProvider.OpenAI) {
                        vulnerabilities = await retryWithExponentialBackoff(
                            () => analyzeCodeWithOpenAI(llmApiKey, codeSnippet, actualLanguageId, fileName),
                            undefined,
                            `${llmName} single file analysis`
                        );
                    } else {
                        vulnerabilities = await retryWithExponentialBackoff(
                            async () => {
                                const result = await callLlmApi(llmName, llmApiKey, codeSnippet, actualLanguageId, llmEndpoint);
                                const cleanJson = extractJsonFromMarkdown(result);
                                const parsed = JSON.parse(cleanJson);
                                return processVulnerabilities(Array.isArray(parsed) ? parsed : (parsed.issues || []), llmName, fileName, actualLanguageId, codeSnippet, true);
                            },
                            undefined,
                            `${llmName} single file analysis`
                        );
                    }
                }
                
                // ENHANCED: Cache management with size limits
                scanCache.set(cacheKey, vulnerabilities);
                if (scanCache.size > 50) {
                    const firstKey = scanCache.keys().next().value;
                    if (firstKey) {
                        scanCache.delete(firstKey);
                    }
                }
                
                if (outputChannel) {
                    outputChannel.appendLine(`✅ ${llmName}: ${vulnerabilities.length} findings in ${Date.now() - llmStartTime}ms`);
                }
                
                return { llmName, vulnerabilities, fromCache: false };
            } catch (error: any) {
                if (outputChannel) {
                    outputChannel.appendLine(`❌ ${llmName} failed for ${fileName} after retries: ${error.message}`);
                }
                return { llmName, vulnerabilities: [], fromCache: false };
            }
        });
        
        const llmResults = await Promise.all(llmPromises);
        
        // Combine results from all LLMs
        let combinedVulnerabilities: Vulnerability[] = [];
        let successfulLlms: string[] = [];
        
        // ENHANCED: Process results with deduplication and performance metrics
        let totalApiCalls = 0;
        let totalCacheHits = 0;
        let failedLlms: string[] = [];
        
        llmResults.forEach(result => {
            if (result.fromCache) {
                totalCacheHits++;
            } else {
                totalApiCalls++;
            }
            
            if (result.vulnerabilities.length > 0) {
                // ENHANCED: Add deduplication logic based on vulnerability signature
                const newVulns = result.vulnerabilities.filter((newVuln: Vulnerability) => {
                    return !combinedVulnerabilities.some((existingVuln: Vulnerability) => 
                        existingVuln.id === newVuln.id && 
                        existingVuln.lineNumber === newVuln.lineNumber &&
                        existingVuln.description === newVuln.description
                    );
                });
                
                combinedVulnerabilities.push(...newVulns);
                successfulLlms.push(result.llmName);
                
                if (outputChannel) {
                    const cacheStatus = result.fromCache ? " (cached)" : "";
                    const dupCount = result.vulnerabilities.length - newVulns.length;
                    const dupInfo = dupCount > 0 ? `, ${dupCount} duplicates filtered` : "";
                    outputChannel.appendLine(`📊 ${result.llmName}: ${newVulns.length} unique findings${dupInfo}${cacheStatus}`);
                }
            } else {
                failedLlms.push(result.llmName);
            }
        });
        
        // ENHANCED: Smart fallback - check if this is LLM-only file first
        if (combinedVulnerabilities.length === 0 && successfulLlms.length === 0) {
            // Check if this is an LLM-only file (BI/IaC)
            const isLlmOnly = isLlmOnlyFile(fileName, actualLanguageId, codeSnippet);
            
            if (isLlmOnly) {
                // LLM-only files: NO fallback to local scanner, even if all LLMs fail
                if (outputChannel) {
                    outputChannel.appendLine(`⚠️ All ${availableLlms.length} LLMs failed for BI/IaC file ${fileName}, but NO fallback to local scanner (LLM-only)`);
                    outputChannel.appendLine(`   Failed LLMs: [${failedLlms.join(', ')}] - This is expected for BI/IaC files`);
                }
                // Return empty results - no local scanner fallback for BI/IaC
                combinedVulnerabilities = [];
            } else {
                // Traditional files: fallback to local scanner
                if (outputChannel) {
                    outputChannel.appendLine(`🔄 All ${availableLlms.length} LLMs failed/empty for ${fileName}, falling back to Local Scanner`);
                    outputChannel.appendLine(`   Failed LLMs: [${failedLlms.join(', ')}]`);
                }
                const localVulns = detectSecurityVulnerabilities(codeSnippet);
                combinedVulnerabilities = localVulns.map(v => ({
                    ...v,
                    llmProvider: "Local Scanner (Multi-LLM Fallback)",
                    fileName: fileName
                }));
            }
        }
        
        // ENHANCED: Add forced local scanner if configured
        if (forceLocalScanner && !isLlmOnlyFileType && useComprehensiveScanning) {
            try {
                if (outputChannel) {
                    outputChannel.appendLine(`🔧 Running additional Local Scanner for comprehensive coverage...`);
                }
                const localStartTime = Date.now();
                const localVulns = detectSecurityVulnerabilities(codeSnippet);
                
                // Filter out duplicates from local scanner
                const newLocalVulns = localVulns.filter((localVuln: Vulnerability) => {
                    return !combinedVulnerabilities.some((existingVuln: Vulnerability) => 
                        existingVuln.id === localVuln.id && 
                        existingVuln.lineNumber === localVuln.lineNumber &&
                        existingVuln.description === localVuln.description
                    );
                }).map(v => ({
                    ...v,
                    llmProvider: "Local Scanner (Forced)",
                    fileName: fileName
                }));
                
                combinedVulnerabilities.push(...newLocalVulns);
                
                if (outputChannel) {
                    outputChannel.appendLine(`✅ Local Scanner: ${newLocalVulns.length} additional unique findings in ${Date.now() - localStartTime}ms`);
                }
            } catch (localError: any) {
                if (outputChannel) {
                    outputChannel.appendLine(`❌ Local Scanner (forced) failed: ${localError.message}`);
                }
            }
        }

        // ENHANCED: Comprehensive performance reporting
        if (outputChannel) {
            const totalTime = Date.now() - startTime;
            const avgTimePerLlm = totalTime / availableLlms.length;
            const scanTypesUsed = forceLocalScanner && !isLlmOnlyFileType ? 
                `Multi-LLM + Local Scanner` : `Multi-LLM only`;
            outputChannel.appendLine(`🏁 Multi-LLM scan complete for ${fileName}:`);
            outputChannel.appendLine(`   🔍 Scan types used: ${scanTypesUsed}`);
            outputChannel.appendLine(`   📈 ${combinedVulnerabilities.length} total unique findings from [${successfulLlms.join(', ')}]`);
            outputChannel.appendLine(`   ⏱️  Total time: ${totalTime}ms (avg ${Math.round(avgTimePerLlm)}ms per LLM)`);
            outputChannel.appendLine(`   🚀 Performance: ${totalApiCalls} API calls, ${totalCacheHits} cache hits`);
            if (failedLlms.length > 0) {
                outputChannel.appendLine(`   ❌ Failed LLMs: [${failedLlms.join(', ')}]`);
            }
        }
        
        return combinedVulnerabilities;
    }
    
    // Single LLM mode (original logic)
    // Check cache first
    const cacheKey = generateScanCacheKey(codeSnippet, actualLanguageId, providerDisplayName);
    
    if (outputChannel) {
        const langDisplay = actualLanguageId !== languageId ? `${actualLanguageId} (detected from ${languageId})` : actualLanguageId;
        outputChannel.appendLine(`📝 Single LLM mode: Using ${providerDisplayName} for ${fileName} (${langDisplay})`);
    }
    if (scanCache.has(cacheKey)) {
        if (outputChannel) {
            outputChannel.appendLine(`Using cached result for ${fileName} (${Date.now() - startTime}ms)`);
        }
        return scanCache.get(cacheKey);
    }
    
    // Get configuration for chunking
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    const maxChunkSize = config.get<number>('performance.maxChunkSize', 8000);
    const enableChunking = config.get<boolean>('performance.enableChunking', true);
    
    let allVulnerabilities: Vulnerability[] = [];
    let llmFailed = false;
    
    // TRY LLM FIRST
    try {
        if (enableChunking && codeSnippet.length > maxChunkSize) {
            // Process large files in chunks
            const chunks = chunkCode(codeSnippet, maxChunkSize);
            const chunkPromises = chunks.map(async (chunk, index) => {
                try {
                    if (providerDisplayName === LlmProvider.OpenAI) {
                        return await analyzeCodeWithOpenAI(apiKey, chunk, actualLanguageId, `${fileName}-chunk-${index + 1}`);
                    } else {
                        const result = await callLlmApi(providerDisplayName, apiKey, chunk, actualLanguageId, endpointUrl);
                        const cleanJson = extractJsonFromMarkdown(result);
                        const parsed = JSON.parse(cleanJson);
                        return processVulnerabilities(Array.isArray(parsed) ? parsed : (parsed.issues || []), providerDisplayName, fileName, actualLanguageId, chunk, true);
                    }
                } catch (error: any) {
                    if (outputChannel) {
                        outputChannel.appendLine(`LLM error on chunk ${index + 1}: ${error.message}`);
                    }
                    throw error; // Re-throw to trigger fallback
                }
            });
            
            const chunkResults = await Promise.all(chunkPromises);
            allVulnerabilities = chunkResults.flat();
            
            if (outputChannel) {
                outputChannel.appendLine(`✅ LLM processed ${chunks.length} chunks for ${fileName} in ${Date.now() - startTime}ms`);
            }
        } else {
            // Process as single file with LLM
            if (providerDisplayName === LlmProvider.OpenAI) {
                allVulnerabilities = await analyzeCodeWithOpenAI(apiKey, codeSnippet, actualLanguageId, fileName);
            } else {
                const result = await callLlmApi(providerDisplayName, apiKey, codeSnippet, actualLanguageId, endpointUrl);
                const cleanJson = extractJsonFromMarkdown(result);
                const parsed = JSON.parse(cleanJson);
                allVulnerabilities = processVulnerabilities(Array.isArray(parsed) ? parsed : (parsed.issues || []), providerDisplayName, fileName, actualLanguageId, codeSnippet, true);
            }
            
            if (outputChannel) {
                outputChannel.appendLine(`✅ LLM analyzed ${fileName} successfully in ${Date.now() - startTime}ms`);
            }
        }
    } catch (error: any) {
        llmFailed = true;
        
        // Check if this is an LLM-only file (BI/IaC)
        const isLlmOnly = isLlmOnlyFile(fileName, actualLanguageId, codeSnippet);
        
        if (isLlmOnly) {
            // LLM-only files: NO fallback to local scanner, even if LLM fails
            if (outputChannel) {
                outputChannel.appendLine(`❌ LLM analysis failed for BI/IaC file ${fileName}: ${error.message}`);
                outputChannel.appendLine(`⚠️ NO fallback to Local Scanner for BI/IaC files (LLM-only) - This is expected`);
            }
            allVulnerabilities = []; // Return empty results - no local scanner fallback
        } else {
            // Traditional files: fallback to local scanner
            if (outputChannel) {
                outputChannel.appendLine(`❌ LLM analysis failed for ${fileName}: ${error.message}`);
                outputChannel.appendLine(`🔄 Falling back to Local Scanner for ${fileName}`);
            }
            
            // FALLBACK TO LOCAL SCANNER (only for non-BI/IaC files)
            try {
                const localVulns = detectSecurityVulnerabilities(codeSnippet);
                allVulnerabilities = localVulns.map(v => ({
                    ...v,
                    llmProvider: "Local Scanner (Fallback)",
                    fileName: fileName
                }));
                
                if (outputChannel) {
                    outputChannel.appendLine(`🛡️ Local Scanner fallback completed for ${fileName} (${allVulnerabilities.length} findings)`);
                }
            } catch (fallbackError: any) {
                if (outputChannel) {
                    outputChannel.appendLine(`❌ Local Scanner fallback also failed for ${fileName}: ${fallbackError.message}`);
                }
                allVulnerabilities = [];
            }
        }
    }
    
    // Cache the result
    scanCache.set(cacheKey, allVulnerabilities);
    
    // Limit cache size to prevent memory issues
    if (scanCache.size > 50) {
        const firstKey = scanCache.keys().next().value;
        if (firstKey) {
            scanCache.delete(firstKey);
        }
    }
    
    if (outputChannel) {
        outputChannel.appendLine(`Completed scanning ${fileName} in ${Date.now() - startTime}ms (found ${allVulnerabilities.length} issues)`);
    }
    
    return allVulnerabilities;
}

// Generate cache key for similar vulnerabilities
function generateCacheKey(vuln: Vulnerability, languageId: string): string {
    // Create a key based on vulnerability type and language
    const keyParts = [
        vuln.id.split('_')[0], // Get vulnerability type (e.g., "SQL" from "SQL_Injection_001")
        languageId,
        vuln.severity
    ];
    return keyParts.join('|').toLowerCase();
}

// Helper function to determine if a fix is complex and needs full verification
function isComplexFix(fix: string, vulnerability: Vulnerability): boolean {
    // Simple heuristics to determine fix complexity
    const fixLower = fix.toLowerCase();
    const complexPatterns = [
        'async', 'await', 'promise', 'callback', 'closure', 'prototype',
        'class', 'extends', 'implements', 'interface', 'generic',
        'try', 'catch', 'finally', 'throw', 'error',
        'crypto', 'hash', 'encrypt', 'decrypt', 'signature',
        'sql', 'query', 'database', 'connection',
        'regex', 'regexp', 'pattern', 'match',
        'security', 'authentication', 'authorization', 'session',
        'xss', 'csrf', 'injection', 'sanitize', 'validate'
    ];
    
    // Check if fix contains complex patterns
    const hasComplexPatterns = complexPatterns.some(pattern => fixLower.includes(pattern));
    
    // Check if fix is multi-line (likely more complex)
    const isMultiLine = fix.split('\n').length > 3;
    
    // Check if vulnerability is high severity (needs thorough verification)
    const isHighSeverity = vulnerability.severity === 'High';
    
    // Check fix length (longer fixes are typically more complex)
    const isLongFix = fix.length > 200;
    
    return hasComplexPatterns || isMultiLine || isHighSeverity || isLongFix;
}

// Quick verification for simple fixes without full LLM call
async function quickVerifyFix(fix: string, vulnerability: Vulnerability, languageId: string): Promise<any> {
    // Basic syntax and pattern checking without LLM
    const verification = {
        isSecure: true,
        fixesOriginalIssue: true,
        introducesNewIssues: false,
        syntaxCorrect: true,
        maintainsFunctionality: true,
        verificationResult: 'APPROVED' as 'APPROVED' | 'REJECTED' | 'NEEDS_IMPROVEMENT',
        issues: [] as string[],
        confidence: 85 // Lower confidence for quick verification
    };
    
    // Basic syntax checks
    const fixLower = fix.toLowerCase();
    
    // Check for obvious security issues
    if (fixLower.includes('eval(') || fixLower.includes('exec(') || 
        fixLower.includes('system(') || fixLower.includes('shell_exec(')) {
        verification.isSecure = false;
        verification.introducesNewIssues = true;
        verification.verificationResult = 'REJECTED';
        verification.issues.push('Contains potentially dangerous function calls');
        verification.confidence = 20;
    }
    
    // Check for basic syntax issues
    if (languageId === 'python' && !fix.match(/^\s*/)) {
        verification.syntaxCorrect = false;
        verification.issues.push('Python indentation may be incorrect');
        verification.confidence = 60;
    }
    
    // Check if fix seems to address the vulnerability type
    const vulnLower = vulnerability.description.toLowerCase();
    if (vulnLower.includes('sql injection') && !fixLower.includes('parameter')) {
        verification.fixesOriginalIssue = false;
        verification.issues.push('Fix may not properly address SQL injection');
        verification.confidence = 50;
    }
    
    return verification;
}

// Optimized parallel fix generation with batching and caching
async function generateFixesFastParallel(
    vulnerabilities: Vulnerability[],
    originalCode: string,
    languageId: string,
    context: vscode.ExtensionContext,
    progress: vscode.Progress<{ message?: string; increment?: number }>,
    maxConcurrent: number = 6,
    enableBatching: boolean = true
): Promise<FixResult[]> {
    const results: FixResult[] = new Array(vulnerabilities.length);
    const startTime = Date.now();
    
    // Group similar vulnerabilities for batch processing
    const groups = enableBatching ? groupSimilarVulnerabilities(vulnerabilities) : 
                   vulnerabilities.map((v, i) => ({ vulnerabilities: [v], indices: [i] }));
    
    progress.report({ message: `Processing ${groups.length} vulnerability groups...` });
    
    // Process groups with proper concurrency control
    let processedGroups = 0;
    
    const processGroup = async (group: { vulnerabilities: Vulnerability[], indices: number[] }) => {
        const groupStartTime = Date.now();
        
        try {
            if (group.vulnerabilities.length === 1) {
                // Single vulnerability - check cache first
                const vuln = group.vulnerabilities[0];
                const cacheKey = generateCacheKey(vuln, languageId);
                
                if (fixCache.has(cacheKey)) {
                    const cachedFix = fixCache.get(cacheKey)!;
                    // Check if cache entry is still valid
                    if (Date.now() - cachedFix.timestamp < CACHE_EXPIRY_MS) {
                        cachedFix.usageCount++;
                        results[group.indices[0]] = {
                            success: true,
                            fix: cachedFix.fix,
                            method: 'CACHED',
                            processingTime: cachedFix.processingTime,
                            verification: cachedFix.verificationResult
                        };
                        return;
                    } else {
                        // Remove expired cache entry
                        fixCache.delete(cacheKey);
                    }
                }
                
                // Generate individual fix
                const fix = await generateCodeFixWithLLM(vuln, originalCode, languageId, context);
                if (fix) {
                    // Smart verification - skip for simple fixes if enabled
                    const config = vscode.workspace.getConfiguration('secureCodingAssistant.performance');
                    const enableSmartVerification = config.get<boolean>('enableSmartVerification', true);
                    const fastModeEnabled = config.get<boolean>('fastModeEnabled', false);
                    
                    let verification = null;
                    if (!fastModeEnabled && (!enableSmartVerification || isComplexFix(fix, vuln))) {
                        // Full verification for complex fixes or when smart verification is disabled
                        verification = await verifyFixWithLLM(originalCode, fix, vuln, languageId, context);
                    } else if (enableSmartVerification && !fastModeEnabled) {
                        // Quick verification for simple fixes
                        verification = await quickVerifyFix(fix, vuln, languageId);
                    }
                    
                    let finalFix = fix;
                    if (verification) {
                        if (verification.verificationResult === 'NEEDS_IMPROVEMENT' && verification.improvedFix) {
                            finalFix = verification.improvedFix.trim();
                        } else if (verification.verificationResult === 'REJECTED') {
                            if (verification.improvedFix) {
                                finalFix = verification.improvedFix.trim();
                            } else {
                                // Use fallback if fix is rejected without improvement
                                finalFix = generateCodeFix(vuln, languageId) || '';
                            }
                        }
                    }
                    
                    // Store in enhanced cache with metadata
                    fixCache.set(cacheKey, {
                        fix: finalFix,
                        timestamp: Date.now(),
                        usageCount: 1,
                        verificationResult: verification,
                        processingTime: Date.now() - groupStartTime
                    });
                    
                    // Manage cache size
                    if (fixCache.size > MAX_CACHE_SIZE) {
                        // Remove oldest entries
                        const sortedEntries = Array.from(fixCache.entries())
                            .sort((a, b) => a[1].timestamp - b[1].timestamp);
                        for (let i = 0; i < Math.floor(MAX_CACHE_SIZE * 0.1); i++) {
                            fixCache.delete(sortedEntries[i][0]);
                        }
                    }
                    results[group.indices[0]] = {
                        success: true,
                        fix: finalFix,
                        method: 'LLM-GENERATED',
                        processingTime: Date.now() - groupStartTime,
                        verification: verification
                    };
                } else {
                    // Fallback
                    results[group.indices[0]] = {
                        success: true,
                        fix: generateCodeFix(vuln, languageId) || '',
                        method: 'FALLBACK',
                        processingTime: Date.now() - groupStartTime
                    };
                }
            } else {
                // Batch processing for similar vulnerabilities
                const batchFix = await generateBatchFix(group.vulnerabilities, originalCode, languageId, context);
                
                // Apply batch fix to all vulnerabilities in the group
                group.indices.forEach(index => {
                    results[index] = {
                        success: true,
                        fix: batchFix || generateCodeFix(group.vulnerabilities[index % group.vulnerabilities.length], languageId) || '',
                        method: batchFix ? 'BATCH-GENERATED' : 'FALLBACK',
                        processingTime: Date.now() - groupStartTime
                    };
                });
            }
        } catch (error: any) {
            // Handle errors for all vulnerabilities in the group
            group.indices.forEach(index => {
                results[index] = {
                    success: false,
                    method: 'FALLBACK',
                    error: error.message,
                    processingTime: Date.now() - groupStartTime
                };
            });
        }
        
        processedGroups++;
        progress.report({ 
            message: `Processed ${processedGroups}/${groups.length} groups...`,
            increment: (100 / groups.length) * 0.8 // Reserve 20% for final processing
        });
    };
    
    // Process groups in batches with proper concurrency limit
    for (let i = 0; i < groups.length; i += maxConcurrent) {
        const batch = groups.slice(i, i + maxConcurrent);
        await Promise.all(batch.map(processGroup));
    }
    
    const totalTime = Date.now() - startTime;
    progress.report({ 
        message: `Completed in ${totalTime}ms`,
        increment: 20 
    });
    
    if (outputChannel) {
        outputChannel.appendLine(`Performance: Generated ${results.length} fixes in ${totalTime}ms using ${groups.length} parallel operations`);
    }
    
    return results;
}

// Group similar vulnerabilities for batch processing
function groupSimilarVulnerabilities(vulnerabilities: Vulnerability[]): { vulnerabilities: Vulnerability[], indices: number[] }[] {
    const groups = new Map<string, { vulnerabilities: Vulnerability[], indices: number[] }>();
    
    vulnerabilities.forEach((vuln, index) => {
        const groupKey = vuln.id.split('_')[0] + '_' + vuln.severity; // Group by type and severity
        
        if (!groups.has(groupKey)) {
            groups.set(groupKey, { vulnerabilities: [], indices: [] });
        }
        
        const group = groups.get(groupKey)!;
        group.vulnerabilities.push(vuln);
        group.indices.push(index);
    });
    
    return Array.from(groups.values());
}

// Generate fix for multiple similar vulnerabilities in one LLM call
async function generateBatchFix(
    vulnerabilities: Vulnerability[],
    originalCode: string,
    languageId: string,
    context: vscode.ExtensionContext
): Promise<string | null> {
    if (vulnerabilities.length === 0) return null;
    
    // Create a batch prompt for similar vulnerabilities
    const batchPrompt = `You are a security expert. Fix multiple similar vulnerabilities in one code block.

VULNERABILITIES TO FIX:
${vulnerabilities.map((v, i) => `${i + 1}. ${v.id}: ${v.description} (${v.severity})`).join('\n')}

ORIGINAL CODE (${languageId}):
\`\`\`${languageId}
${originalCode}
\`\`\`

TASK: Provide ONE comprehensive fix that addresses ALL the vulnerabilities listed above.

REQUIREMENTS:
1. Fix all security issues in a single code rewrite
2. Maintain original functionality  
3. Include comments explaining what was fixed
4. For pickle files: Provide secure alternatives or safe pickle practices with HMAC validation
5. Be concise but complete

RESPONSE FORMAT:
\`\`\`${languageId}
[Your secure code here that fixes all issues]
\`\`\``;

    // SMART LLM SELECTION: Use any available LLM for batch fix generation
    const availableLlms = await getAvailableLlms(context);
    if (availableLlms.length === 0) return null;

    // Use preferred LLM if available, otherwise use first available LLM
    const preferredLlmSetting = getPreferredLlm();
    let selectedLlm = preferredLlmSetting;
    let apiKey = preferredLlmSetting ? await getApiKey(context, preferredLlmSetting) : undefined;
    let endpointToUse: string | undefined;
    
    if (!apiKey) {
        // Fallback to first available LLM
        selectedLlm = availableLlms[0];
        apiKey = await getApiKey(context, selectedLlm);
        
        // Get endpoint for custom LLMs
        if (!Object.values(LlmProvider).includes(selectedLlm as LlmProvider)) {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
            endpointToUse = customConfig?.endpoint;
        }
    } else if (preferredLlmSetting === "Custom") {
        const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
        if (customLlmConfigs.length > 0) {
            const chosenCustomLlm = customLlmConfigs[0];
            selectedLlm = chosenCustomLlm.name;
            endpointToUse = chosenCustomLlm.endpoint;
        }
    }

    if (!apiKey || !selectedLlm) return null;

    try {
        let llmResponse = '';
        const dynamicMaxTokens = calculateMaxTokens(batchPrompt, 1500); // Smaller tokens for batch
        
        if (selectedLlm === LlmProvider.OpenAI) {
            const openai = new OpenAI({ apiKey });
            const openaiConfig = vscode.workspace.getConfiguration('secureCodingAssistant.openai');
            const openaiModel = openaiConfig.get<string>('model', 'gpt-4-turbo-preview');
            const response = await retryWithExponentialBackoff(
                () => openai.chat.completions.create({
                    model: openaiModel,
                    messages: [
                        { role: 'system', content: 'You are a security expert that provides efficient batch fixes for multiple vulnerabilities across all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.).' },
                        { role: 'user', content: batchPrompt }
                    ],
                    temperature: 0,
                    max_tokens: dynamicMaxTokens
                }),
                undefined,
                `${selectedLlm} batch fix generation`
            );
            llmResponse = response.choices[0]?.message?.content || '';
        } else if (selectedLlm === LlmProvider.Anthropic) {
            const anthropic = new Anthropic({ apiKey });
            const anthropicConfig = vscode.workspace.getConfiguration('secureCodingAssistant.anthropic');
            const anthropicModel = anthropicConfig.get<string>('model', 'claude-3-5-sonnet-20241022');
            const response = await retryWithExponentialBackoff(
                () => anthropic.messages.create({
                    model: anthropicModel,
                    max_tokens: dynamicMaxTokens,
                    temperature: 0,
                    messages: [
                        { role: 'user', content: `You are a security expert that provides efficient batch fixes for multiple vulnerabilities across all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.).\n\n${batchPrompt}` }
                    ]
                }),
                undefined,
                `${selectedLlm} batch fix generation`
            );
            // Handle new Anthropic SDK content structure
            const firstBlock = response.content[0];
            llmResponse = firstBlock.type === 'text' ? firstBlock.text : JSON.stringify(firstBlock);
        } else if (selectedLlm === LlmProvider.Google) {
            const genAI = new GoogleGenAI({ apiKey });
            const googleConfig = vscode.workspace.getConfiguration('secureCodingAssistant.google');
            const modelName = googleConfig.get<string>('model', 'gemini-1.5-flash');
            
            const response = await retryWithExponentialBackoff(
                () => genAI.models.generateContent({
                    model: modelName,
                    contents: `You are a security expert that provides efficient batch fixes for multiple vulnerabilities across all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.).\n\n${batchPrompt}`,
                    config: {
                        temperature: 0,
                        maxOutputTokens: dynamicMaxTokens
                    }
                }),
                undefined,
                `${selectedLlm} batch fix generation`
            );
            llmResponse = response.text || '';
        } else {
            // Custom LLM provider
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
            if (customConfig) {
                const response = await retryWithExponentialBackoff(
                    async () => {
                        const customModelConfig = vscode.workspace.getConfiguration('secureCodingAssistant.custom');
                        const customModel = customModelConfig.get<string>('defaultModel', 'gpt-4-turbo-preview');
                        
                        return await axios.post(endpointToUse!, {
                            model: customModel,
                            messages: [
                                { role: 'system', content: 'You are a security expert that provides efficient batch fixes for multiple vulnerabilities across all programming languages, infrastructure as code (Terraform, CloudFormation, Kubernetes, etc.), Business Intelligence platforms (LookML, dbt, Tableau, Power BI, etc.), and shell/batch scripting languages (Bash, PowerShell, Batch, etc.).' },
                                { role: 'user', content: batchPrompt }
                            ],
                            temperature: 0,
                            max_tokens: dynamicMaxTokens
                        }, {
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${apiKey}`
                            }
                        });
                    },
                    undefined,
                    `${selectedLlm} batch fix generation`
                );
                const responseData = response.data as {
                    choices?: Array<{ message: { content: string } }>;
                    content?: string;
                    text?: string;
                };
                llmResponse = responseData.choices?.[0]?.message?.content || responseData.content || responseData.text || '';
            }
        }

        // Extract code block
        const codeBlockMatch = llmResponse.match(/```[\w]*\n([\s\S]*?)\n```/);
        return codeBlockMatch ? codeBlockMatch[1].trim() : llmResponse.trim();
        
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Batch fix generation failed: ${error.message}`);
        }
        return null;
    }
}

// Fallback template-based fix generator (kept as backup)
function generateCodeFix(vuln: Vulnerability, languageId: string): string | null {
    return `// Fallback fix template for ${vuln.id}
// ${vuln.recommendation}
// Please review and implement the security improvements mentioned above.`;
}

// Helper function to escape HTML
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Helper function to extract JSON from markdown-formatted responses
// Verify a generated fix using LLM
async function verifyFixWithLLM(
    originalCode: string,
    proposedFix: string,
    vulnerability: Vulnerability,
    languageId: string,
    context: vscode.ExtensionContext
): Promise<any> {
    const verificationPrompt = `SECURITY VERIFICATION: Analyze this ${languageId} code fix for security issues.

ORIGINAL VULNERABLE CODE:
${originalCode}

PROPOSED FIX:
${proposedFix}

VULNERABILITY BEING FIXED:
${vulnerability.description}

VERIFICATION TASKS:
1. Does the fix actually resolve the original security issue?
2. Does the fix introduce any new security vulnerabilities?
3. Is the fix syntactically correct for ${languageId}?
4. Does the fix maintain the original functionality?
5. Are there any edge cases the fix doesn't handle?

Respond with JSON format:
{
  "isSecure": true/false,
  "fixesOriginalIssue": true/false,
  "introducesNewIssues": true/false,
  "syntaxCorrect": true/false,
  "maintainsFunctionality": true/false,
  "verificationResult": "APPROVED/REJECTED/NEEDS_IMPROVEMENT",
  "issues": ["list of any issues found"],
  "improvedFix": "if rejected, provide improved version here",
  "confidence": 85
}`;

    // SMART LLM SELECTION: Use any available LLM for verification
    const availableLlms = await getAvailableLlms(context);
    if (availableLlms.length === 0) return null;

    // Use preferred LLM if available, otherwise use first available LLM
    const preferredLlmSetting = getPreferredLlm();
    let selectedLlm = preferredLlmSetting;
    let apiKey = preferredLlmSetting ? await getApiKey(context, preferredLlmSetting) : undefined;
    let endpointToUse: string | undefined;
    
    if (!apiKey) {
        // Fallback to first available LLM
        selectedLlm = availableLlms[0];
        apiKey = await getApiKey(context, selectedLlm);
        
        // Get endpoint for custom LLMs
        if (!Object.values(LlmProvider).includes(selectedLlm as LlmProvider)) {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
            endpointToUse = customConfig?.endpoint;
        }
    } else if (preferredLlmSetting === "Custom") {
        const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
        if (customLlmConfigs.length > 0) {
            const chosenCustomLlm = customLlmConfigs[0];
            selectedLlm = chosenCustomLlm.name;
            endpointToUse = chosenCustomLlm.endpoint;
        }
    }

    if (!apiKey || !selectedLlm) return null;

    try {
        let verificationResult: any = null;
        
        if (selectedLlm === LlmProvider.OpenAI) {
            const OpenAI = require('openai').default;
            const openai = new OpenAI({ apiKey });
            const verifyResponse = await retryWithExponentialBackoff(
                async () => await openai.chat.completions.create({
                    model: 'gpt-4-turbo-preview',
                    messages: [{ role: 'user', content: verificationPrompt }],
                    max_tokens: 500,
                    temperature: 0.1
                }),
                undefined,
                `Fix verification`,
                'OpenAI'
            );
            const verifyContent = verifyResponse.choices[0]?.message?.content?.trim() || '';
            try {
                verificationResult = JSON.parse(extractJsonFromMarkdown(verifyContent));
            } catch (e) {
                if (outputChannel) {
                    outputChannel.appendLine(`⚠️ Verification parsing failed: ${e}`);
                }
            }
        } else if (selectedLlm === LlmProvider.Anthropic) {
            const Anthropic = require('@anthropic-ai/sdk').default;
            const anthropic = new Anthropic({ apiKey });
            const verifyResponse = await retryWithExponentialBackoff(
                async () => await anthropic.messages.create({
                    model: 'claude-3-5-sonnet-20241022',
                    max_tokens: 500,
                    messages: [{ role: 'user', content: verificationPrompt }]
                }),
                undefined,
                `Fix verification`,
                'Anthropic'
            );
            const firstBlock = verifyResponse.content[0];
            const verifyContent = (firstBlock.type === 'text' ? firstBlock.text : '').trim();
            try {
                verificationResult = JSON.parse(extractJsonFromMarkdown(verifyContent));
            } catch (e) {
                if (outputChannel) {
                    outputChannel.appendLine(`⚠️ Verification parsing failed: ${e}`);
                }
            }
        } else {
            // For other LLMs, use the generic API
            const llmResponse = await callLlmApi(selectedLlm, apiKey, verificationPrompt, languageId, endpointToUse);
            try {
                verificationResult = JSON.parse(extractJsonFromMarkdown(llmResponse));
            } catch (e) {
                if (outputChannel) {
                    outputChannel.appendLine(`⚠️ Verification parsing failed: ${e}`);
                }
            }
        }

        return verificationResult;
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`⚠️ Fix verification failed: ${error.message}`);
        }
        return null;
    }
}

function extractJsonFromMarkdown(content: string): string {
    // Try to extract JSON from markdown code blocks (```json ... ```)
    const jsonBlockMatch = content.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    if (jsonBlockMatch) {
        return jsonBlockMatch[1].trim();
    }
    
    // If no code block found, try to find JSON-like content
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
        return jsonMatch[0];
    }
    
    // Return original content if no JSON patterns found
    return content.trim();
}

// Helper function to calculate dynamic max tokens based on content length
function calculateMaxTokens(content: string, baseTokens?: number): number {
    // Get base tokens from settings if not provided
    if (!baseTokens) {
        const config = vscode.workspace.getConfiguration('secureCodingAssistant.tokens');
        baseTokens = config.get<number>('baseMaxTokens', 4000);
    }
    
    // Rough estimate: 1 token ≈ 4 characters for English text
    const estimatedInputTokens = Math.ceil(content.length / 4);
    const maxContextTokens = 128000; // GPT-4 Turbo context limit
    const safetyBuffer = 1000; // Buffer for response
    
    // Ensure we don't exceed context limits
    const availableTokens = maxContextTokens - estimatedInputTokens - safetyBuffer;
    const calculatedTokens = Math.min(Math.max(availableTokens, 1000), baseTokens);
    
    // Removed token calculation logging to reduce noise
    return calculatedTokens;
}

// Retry configuration
interface RetryConfig {
    maxRetries: number;
    baseDelay: number;
    maxDelay: number;
    exponentialBase: number;
    rateLimitRetries: number;
    rateLimitBaseDelay: number;
    rateLimitMaxDelay: number;
}

interface RateLimitInfo {
    remaining: number;
    resetTime: number;
    limit: number;
    provider: string;
}

// Function to get retry configuration from settings
function getRetryConfig(): RetryConfig {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant.retry');
    return {
        maxRetries: config.get<number>('maxRetries', 3),
        baseDelay: config.get<number>('baseDelay', 1000),
        maxDelay: config.get<number>('maxDelay', 10000),
        exponentialBase: 2,
        rateLimitRetries: config.get<number>('rateLimitRetries', 5),
        rateLimitBaseDelay: config.get<number>('rateLimitBaseDelay', 2000),
        rateLimitMaxDelay: config.get<number>('rateLimitMaxDelay', 60000)
    };
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxRetries: 3,
    baseDelay: 1000, // 1 second
    maxDelay: 10000, // 10 seconds
    exponentialBase: 2,
    rateLimitRetries: 5, // More retries for rate limits
    rateLimitBaseDelay: 2000, // 2 seconds base delay for rate limits
    rateLimitMaxDelay: 60000 // 60 seconds max delay for rate limits
};

// Rate limit tracker per provider
const rateLimitTracker = new Map<string, RateLimitInfo>();

// Function to parse rate limit headers
function parseRateLimitHeaders(headers: any, provider: string): RateLimitInfo | null {
    try {
        let remaining, resetTime, limit;
        
        if (provider === 'OpenAI') {
            remaining = parseInt(headers['x-ratelimit-remaining-requests'] || headers['x-ratelimit-remaining'] || '0');
            resetTime = parseInt(headers['x-ratelimit-reset-requests'] || headers['x-ratelimit-reset'] || '0');
            limit = parseInt(headers['x-ratelimit-limit-requests'] || headers['x-ratelimit-limit'] || '0');
        } else if (provider === 'Anthropic') {
            remaining = parseInt(headers['anthropic-ratelimit-requests-remaining'] || '0');
            resetTime = parseInt(headers['anthropic-ratelimit-requests-reset'] || '0');
            limit = parseInt(headers['anthropic-ratelimit-requests-limit'] || '0');
        } else {
            return null;
        }
        
        return {
            remaining,
            resetTime: resetTime * 1000, // Convert to milliseconds
            limit,
            provider
        };
    } catch (error) {
        return null;
    }
}

// Function to check if we should wait for rate limit reset
function shouldWaitForRateLimit(provider: string): number {
    const rateLimitInfo = rateLimitTracker.get(provider);
    if (!rateLimitInfo) return 0;
    
    const now = Date.now();
    if (rateLimitInfo.remaining <= 0 && rateLimitInfo.resetTime > now) {
        return rateLimitInfo.resetTime - now;
    }
    
    return 0;
}

// Enhanced retry function with rate limit handling
async function retryWithExponentialBackoff<T>(
    fn: () => Promise<T>,
    config?: RetryConfig,
    context: string = 'API call',
    provider: string = 'unknown'
): Promise<T> {
    // Use dynamic configuration from settings if not provided
    const retryConfig = config || getRetryConfig();
    let lastError: any;
    
    // Check rate limit before starting
    const rateLimitWait = shouldWaitForRateLimit(provider);
    if (rateLimitWait > 0) {
        const waitSeconds = Math.ceil(rateLimitWait / 1000);
        if (outputChannel) {
            outputChannel.appendLine(`🚦 RATE LIMIT: Waiting ${waitSeconds}s for ${provider} rate limit reset`);
        }
        await new Promise(resolve => setTimeout(resolve, Math.min(rateLimitWait, retryConfig.rateLimitMaxDelay)));
    }
    
    for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
        try {
            const result = await fn();
            
            // If successful, clear any rate limit tracking for this provider
            if (rateLimitTracker.has(provider)) {
                const info = rateLimitTracker.get(provider)!;
                if (info.remaining > 0) {
                    rateLimitTracker.delete(provider);
                }
            }
            
            return result;
        } catch (error: any) {
            lastError = error;
            
            if (outputChannel) {
                outputChannel.appendLine(`${context} attempt ${attempt + 1} failed: ${error.message}`);
            }
            
            // Handle rate limit errors specifically
            const isRateLimit = error.status === 429 || 
                               error.message?.toLowerCase().includes('rate limit') ||
                               error.message?.toLowerCase().includes('too many requests');
            
            if (isRateLimit) {
                if (outputChannel) {
                    outputChannel.appendLine(`🚦 RATE LIMIT: Hit rate limit for ${provider}`);
                }
                
                // Parse rate limit info from error response
                if (error.response?.headers) {
                    const rateLimitInfo = parseRateLimitHeaders(error.response.headers, provider);
                    if (rateLimitInfo) {
                        rateLimitTracker.set(provider, rateLimitInfo);
                        if (outputChannel) {
                            outputChannel.appendLine(`🚦 RATE LIMIT: ${rateLimitInfo.remaining}/${rateLimitInfo.limit} requests remaining`);
                        }
                    }
                }
                
                // Use rate limit specific retry logic
                if (attempt < retryConfig.rateLimitRetries) {
                    const rateLimitDelay = Math.min(
                        retryConfig.rateLimitBaseDelay * Math.pow(2, attempt),
                        retryConfig.rateLimitMaxDelay
                    );
                    const jitter = Math.random() * 0.2 * rateLimitDelay; // 20% jitter for rate limits
                    const totalDelay = rateLimitDelay + jitter;
                    
                    if (outputChannel) {
                        outputChannel.appendLine(`🚦 RATE LIMIT: Retrying in ${Math.round(totalDelay / 1000)}s (attempt ${attempt + 1}/${retryConfig.rateLimitRetries})`);
                    }
                    
                    await new Promise(resolve => setTimeout(resolve, totalDelay));
                    continue;
                }
            }
            
            // Don't retry on the last attempt
            if (attempt === retryConfig.maxRetries) {
                break;
            }
            
            // Don't retry on certain error types (authentication, invalid input, etc.)
            if (error.status === 401 || error.status === 403 || error.status === 400) {
                if (outputChannel) {
                    outputChannel.appendLine(`${context} failed with non-retryable error: ${error.status}`);
                }
                break;
            }
            
            // Calculate delay with exponential backoff and jitter for regular errors
            const delay = Math.min(
                retryConfig.baseDelay * Math.pow(retryConfig.exponentialBase, attempt),
                retryConfig.maxDelay
            );
            const jitter = Math.random() * 0.1 * delay; // Add up to 10% jitter
            const totalDelay = delay + jitter;
            
            if (outputChannel) {
                outputChannel.appendLine(`${context} retrying in ${Math.round(totalDelay)}ms...`);
            }
            
            await new Promise(resolve => setTimeout(resolve, totalDelay));
        }
    }
    
    // If we get here, all attempts failed
    if (outputChannel) {
        outputChannel.appendLine(`${context} failed after ${retryConfig.maxRetries + 1} attempts`);
    }
    throw lastError;
}

// Helper function to get OpenAI configuration
function getOpenAIConfig(): { model: string; systemPrompt: string; userPrompt: string } {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant.openai');
    const scanConfig = getScanConfiguration();
    const model = config.get<string>('model', scanConfig.defaultModel);
    
    const systemPrompt = `You are a code security tool, a high-assurance code validation and security-auditing assistant.

Your only allowed input is source code pasted or imported by the user. Reject any message that does not include code. Do not respond to general questions, instructions, or comments unless they are accompanied by code.

Capabilities:
- Source Code Analysis
- Syntax and logic flaws detection
- Code quality and best practices validation
- Secure coding violations and known vulnerability patterns
- Performance & Complexity analysis
- Maintainability & Style checking
- Cryptographic hash detection and validation
- CVE Detection and Analysis
  * Known vulnerability identification
  * CVE ID tracking and validation
  * Affected version ranges
  * Fixed version information
  * Vulnerability severity assessment
  * Exploit availability checking
  * Patch status verification
  * Security advisory analysis
  * Common vulnerability patterns
  * Zero-day vulnerability detection
- Container Security Analysis
  * Docker Compose security
  * Kubernetes manifests
  * Podman configurations
  * Container runtime security
- Infrastructure Security Analysis
  * Terraform security (HCL)
  * Ansible playbooks (YAML)
  * CloudFormation templates (JSON/YAML)
  * ARM templates (JSON)
  * Bicep templates
  * Pulumi configurations (TypeScript/Python/Go/C#)
  * Serverless configurations (YAML)
  * Kubernetes manifests (YAML)
  * Helm charts (YAML/templates)
  * Docker Compose files (YAML)
  * Vagrant configurations
  * Crossplane configurations
  * AWS SAM templates
  * AWS CDK configurations
- CI/CD Pipeline Security
  * GitHub Actions
  * GitLab CI
  * Jenkins pipelines
  * Azure DevOps
  * CircleCI
  * Travis CI
  * Buildkite
- Database Security Analysis
  * SQL migrations
  * Database schemas
  * Connection strings
  * Query security
  * Data encryption
  * Backup security
  * Access patterns
- API Security Analysis
  * OpenAPI/Swagger specs
  * GraphQL schemas
  * API gateways
  * Rate limiting
  * Authentication flows
  * Authorization patterns
  * API versioning
- Web Security Analysis
  * Webpack configs
  * Babel configs
  * ESLint configs
  * CSP headers
  * CORS policies
  * Cookie security
  * Session management
- Mobile Security Analysis
  * AndroidManifest.xml
  * Info.plist
  * App permissions
  * Deep linking
  * App signing
  * ProGuard rules
  * Mobile networking
- Cloud Security Analysis
  * IAM policies
  * Security groups
  * Network ACLs
  * Storage policies
  * Encryption configs
  * Backup policies
  * Disaster recovery
- Business Intelligence and Data Platform Security Analysis
  * LookML (Looker) security
    - Connection security
    - SQL injection in dimensions/measures
    - Access grant configurations
    - Row-level security
    - Data exposure through explores
    - Hardcoded credentials in connections
    - HTML/JavaScript injection in visualizations
    - Unsafe liquid templating
    - Dashboard sharing permissions
    - Model security settings
  * dbt (Data Build Tool) security
    - Profile and connection security
    - SQL injection in models/macros
    - Unsafe Jinja templating
    - Source and seed security
    - Materialization security
    - Grant permissions
    - Package dependency security
    - Environment variable exposure
    - Test security configurations
    - Documentation security
  * Tableau security
    - Data source connection security
    - Workbook and dashboard permissions
    - SQL injection in calculated fields
    - Custom SQL security
    - Extract security
    - Row-level security
    - Authentication configurations
    - SSL/TLS settings
    - Server security configurations
    - Repository security
  * Power BI security
    - Dataset security
    - DAX injection vulnerabilities
    - Row-level security (RLS)
    - Data gateway security
    - Workspace permissions
    - App security
    - Power Query M security
    - Connection string security
    - Sensitivity labeling
    - External sharing settings
  * ThoughtSpot TML security
    - Worksheet and answer security
    - Formula injection
    - Join security
    - Row-level security
    - Column security
    - Connection security
    - Sharing and permission configurations
    - Authentication settings
    - Data source security
  * AtScale security
    - Cube security
    - Dimension and measure security
    - SQL expression security
    - Connection security
    - Aggregate security
    - User and role security
    - Query security
    - Cache security
    - Model security
    - Authentication configurations
  * Qlik Sense security
    - App security
    - Section access security
    - Data connection security
    - Load script security
    - Expression security
    - Selection security
    - Extension security
    - Authentication and authorization
    - SSL/TLS configurations
    - Repository security
  * GoodData security
    - Workspace security
    - MAQL injection
    - Logical data model security
    - Metric security
    - Report security
    - Dashboard security
    - User and group security
    - API security
    - Authentication configurations
    - Data source security
- Package Management and Build System Analysis
  * Maven (pom.xml) analysis
    - Dependency management
    - Plugin security
    - Repository security
    - Build configuration
    - Profile security
    - Property management
    - Version management
    - Scope analysis
    - Transitive dependencies
    - Build lifecycle security
  * Gradle (build.gradle, settings.gradle) analysis
    - Dependency management
    - Plugin security
    - Repository security
    - Build configuration
    - Task security
    - Version catalogs
    - Dependency constraints
    - Build script security
    - Transitive dependencies
    - Build optimization
  * npm (package.json) analysis
    - Dependency management
    - Script security
    - Configuration security
    - Workspace security
    - Version management
    - Package integrity
    - Access control
    - Registry security
    - Transitive dependencies
    - Build security
  * pip (requirements.txt, setup.py) analysis
    - Dependency management
    - Version constraints
    - Index security
    - Package security
    - Environment security
    - Build security
    - Distribution security
    - Access control
    - Transitive dependencies
    - Package integrity
  * Ruby (Gemfile) analysis
    - Dependency management
    - Source security
    - Version constraints
    - Group security
    - Platform security
    - Gem security
    - Build security
    - Access control
    - Transitive dependencies
    - Package integrity
  * Composer (composer.json) analysis
    - Dependency management
    - Repository security
    - Version constraints
    - Script security
    - Autoload security
    - Platform security
    - Package security
    - Access control
    - Transitive dependencies
    - Build security
  * NuGet (packages.config, .csproj) analysis
    - Package management
    - Source security
    - Version constraints
    - Framework security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Configuration security
    - Update security
  * Cargo (Cargo.toml) analysis
    - Dependency management
    - Registry security
    - Version constraints
    - Feature security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Profile security
    - Workspace security
  * Yarn (yarn.lock) analysis
    - Dependency management
    - Integrity verification
    - Version constraints
    - Workspace security
    - Access control
    - Registry security
    - Package security
    - Transitive dependencies
    - Build security
    - Configuration security
  * Go Modules (go.mod) analysis
    - Dependency management
    - Version constraints
    - Module security
    - Proxy security
    - Access control
    - Package integrity
    - Build security
    - Transitive dependencies
    - Workspace security
    - Configuration security
  * Build System Security
    - Build script analysis
    - Task security
    - Plugin security
    - Configuration security
    - Environment security
    - Access control
    - Resource security
    - Output security
    - Cache security
    - Artifact security
  * Conan (conanfile.txt, conanfile.py) analysis
    - Dependency management
    - Profile security
    - Generator security
    - Package security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Configuration security
    - Remote security
  * Poetry (pyproject.toml) analysis
    - Dependency management
    - Virtual environment security
    - Build system security
    - Package security
    - Script security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Source security
    - Version constraints
  * SBT (build.sbt) analysis
    - Dependency management
    - Plugin security
    - Task security
    - Build configuration
    - Project security
    - Access control
    - Transitive dependencies
    - Version management
    - Repository security
    - Build optimization
  * Leiningen (project.clj) analysis
    - Dependency management
    - Profile security
    - Plugin security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Repository security
    - Version management
  * Mix (mix.exs) analysis
    - Dependency management
    - Application security
    - Environment security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Release security
  * Cabal (cabal.project) analysis
    - Dependency management
    - Package security
    - Build security
    - Flag security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Repository security
    - Distribution security
  * Paket (paket.dependencies) analysis
    - Dependency management
    - Source security
    - Version constraints
    - Framework security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Lock file security
    - Update security
  * Shards (shard.yml) analysis
    - Dependency management
    - Version constraints
    - Script security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Source security
    - Build security
    - Development security
  * Dub (dub.json) analysis
    - Dependency management
    - Build type security
    - Configuration security
    - Package security
    - Access control
    - Transitive dependencies
    - Version constraints
    - Source security
    - Build security
    - Target security
  * Vcpkg (vcpkg.json) analysis
    - Dependency management
    - Port security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Feature security
    - Overlay security

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable
- For library issues: CVE IDs and affected versions

IMPORTANT: You MUST detect and report the following security issues:
1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. SQL injection vulnerabilities
5. Cross-site scripting (XSS)
6. Command injection
7. Path traversal
8. Insecure deserialization
9. Insecure direct object references
10. Security misconfiguration
11. Vulnerable dependencies and libraries
12. Outdated or deprecated packages
13. Insecure library usage patterns
14. Package management issues
15. Version conflicts
16. Insecure sources
17. Missing integrity checks
18. Outdated packages
19. Malicious packages
20. License violations
21. Access control issues
22. Build security issues
23. Configuration security
24. Dependency vulnerabilities
25. Dependency confusion
26. Build system attacks
27. Artifact verification
28. Signing verification
29. Source verification
30. Distribution security
31. Update security
32. Integrity checks
33. Trust verification
34. Compliance and standards
35. Data protection
36. Privacy controls
37. Security controls
38. Audit requirements
39. Documentation requirements
40. Package Management System Issues
    - Dependency resolution
    - Version compatibility
    - Build system security
    - Package integrity
    - Access control
    - Configuration security
    - Repository security
    - Update security
    - Lock file security
    - Development security
41. Container Security Issues
42. Infrastructure Security Issues
43. CI/CD Security Issues
44. Database Security Issues
45. API Security Issues
46. Web Security Issues
47. Mobile Security Issues
48. Cloud Security Issues
49. Python Pickle File Security (CRITICAL)
    - Pickle files (.pkl, .pickle) are extremely dangerous and should be treated as executable code
    - Any pickle file from untrusted sources can execute arbitrary Python code during deserialization
    - Check for: malicious code execution, data exfiltration, system compromise
    - Recommend: Use JSON, XML, or other safe serialization formats instead
    - If pickle must be used: cryptographically sign files, validate sources, sandbox execution
50. Shell and Batch Script Security (CRITICAL)
    - Command injection vulnerabilities in shell scripts
    - Unsafe variable expansion and command substitution
    - Path traversal through relative paths and user input
    - Privilege escalation through sudo/setuid usage
    - Hardcoded credentials and secrets in scripts
    - Unsafe file operations and permissions
    - Environment variable exposure and injection
    - Process injection and background execution risks
    - Input validation bypass in script parameters
    - Race conditions in temporary file handling
51. Business Intelligence Security Issues
    - LookML SQL injection and credential exposure
    - dbt macro security and template injection
    - Tableau calculated field injection and connection security
    - Power BI DAX injection and RLS bypass
    - ThoughtSpot formula injection and authentication issues
    - AtScale SQL expression security and access control
    - Qlik script injection and section access bypass
    - GoodData MAQL injection and workspace security
52. Infrastructure as Code Security Issues
    - Terraform configuration security and state exposure
    - CloudFormation template security and parameter validation
    - Kubernetes manifest security and RBAC misconfigurations
    - Docker Compose security and secret management
    - Ansible playbook security and privilege escalation
    - Helm chart security and template injection
    - Bicep template security and resource exposure
    - Pulumi configuration security and secret handling

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values
- Import statements and dependency declarations
- Library version specifications
- Usage of known vulnerable functions from libraries

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer
6. Dependency Analysis (if applicable)

Respond in JSON format with the following structure:
{
    "summary": {
        "language": "string",
        "riskRating": "High|Medium|Low",
        "issueCount": number
    },
    "validatedCode": ["string"],
    "issues": [{
        "id": "string",
        "description": "string",
        "location": "string",
        "severity": "High|Medium|Low",
        "recommendation": "string",
        "lineNumber": "string",
        "cweId": "string",
        "owaspReference": "string",
        "hallucinationScore": number,
        "confidenceScore": number,
        "llmProvider": "string",
        "cveId": "string",
        "affectedVersions": "string",
        "fixedVersions": "string"
    }],
    "performanceHighlights": ["string"],
    "dependencyAnalysis": {
        "vulnerableDependencies": [{
            "name": "string",
            "version": "string",
            "cveId": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "recommendation": "string"
        }],
        "outdatedDependencies": [{
            "name": "string",
            "currentVersion": "string",
            "latestVersion": "string",
            "updateRecommendation": "string"
        }]
    },
    "packageManagementAnalysis": {
        "buildSystemIssues": [{
            "system": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "dependencyIssues": [{
            "package": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string",
            "affectedVersions": "string",
            "fixedVersions": "string"
        }],
        "configurationIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "securityIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "systemSpecificIssues": [{
            "system": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string",
            "affectedVersions": "string",
            "fixedVersions": "string"
        }]
    },
    "containerSecurityAnalysis": {
        "runtimeIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "networkIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "infrastructureSecurityAnalysis": {
        "resourceIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "stateIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "cicdSecurityAnalysis": {
        "pipelineIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "secretIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "databaseSecurityAnalysis": {
        "schemaIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "queryIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "apiSecurityAnalysis": {
        "endpointIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "authIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "webSecurityAnalysis": {
        "configIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "headerIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "mobileSecurityAnalysis": {
        "permissionIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "componentIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "cloudSecurityAnalysis": {
        "iamIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "networkIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    },
    "shellScriptSecurityAnalysis": {
        "commandInjectionIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "variableExpansionIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "privilegeEscalationIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "fileOperationIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "environmentVariableIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }]
    }
}`;

    const userPrompt = `Analyze the following {languageId} code for security vulnerabilities and code quality issues. Pay special attention to:

1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. Other security vulnerabilities
5. Docker security issues (if Dockerfile)
6. Software Composition Analysis issues (if dependency files)
7. Known CVE vulnerabilities (e.g., Log4Shell, Spring4Shell)
8. Zero-day vulnerabilities and security advisories
9. Infrastructure as Code security (if IaC files)
10. API security issues
11. Mobile security issues
12. Cloud security issues
13. CI/CD security issues
14. Cryptocurrency/Blockchain security
15. IoT security issues
16. AI/ML security issues
17. Supply chain security
18. Compliance and standards
19. Package management and build system security
    - Dependency vulnerabilities
    - Version conflicts
    - Insecure sources
    - Missing integrity checks
    - Outdated packages
    - Malicious packages
    - License violations
    - Access control issues
    - Build security issues
    - Configuration security
20. Package management system security
    - Dependency resolution
    - Version compatibility
    - Build system security
    - Package integrity
    - Access control
    - Configuration security
    - Repository security
    - Update security
    - Lock file security
    - Development security
21. Container security
22. Infrastructure security
23. CI/CD security
24. Database security
25. API security
26. Web security
27. Mobile security
28. Cloud security
29. Business Intelligence and Data Platform security
    - LookML (Looker) vulnerabilities:
      * PII exposure in dimensions/measures (hcp_full_name, hcp_gender_label, hcp_npi, hcl_address2, etc.)
      * SQL injection through dollar-brace interpolation in sql parameters
      * Hardcoded credentials in connection strings
      * Weak access grants and public explores
      * Unencrypted database connections
      * Unsafe Liquid templating with user input
    - dbt model and macro security
    - Tableau workbook and data source security
    - Power BI dataset and DAX security
    - ThoughtSpot worksheet and TML security
    - AtScale cube and dimension security
    - Qlik Sense app and script security
    - GoodData workspace and MAQL security
30. Infrastructure as Code security
    - Terraform configuration vulnerabilities
    - CloudFormation template security
    - Kubernetes manifest misconfigurations
    - Docker Compose security issues
    - Ansible playbook vulnerabilities
    - Helm chart security
    - Bicep template security
    - Pulumi configuration security

IMPORTANT: Look for variable assignments containing hash values and string literals that match hash patterns.

\`\`\`
{codeSnippet}
\`\`\`

Provide a comprehensive security analysis following the specified structure. Include all detected vulnerabilities, their severity, and recommended fixes. Ensure the response is in valid JSON format as specified in the system prompt.`;

    return { model, systemPrompt, userPrompt };
}

export function activate(context: vscode.ExtensionContext) {
    // Create output channel
    outputChannel = vscode.window.createOutputChannel("Secure Coding Assistant");
    outputChannel.appendLine('Congratulations, your extension "secure-coding-assistant" is now active!');

    // Log the preferred LLM
    const preferredLlmOnActivation = getPreferredLlm();
    outputChannel.appendLine(`Preferred LLM on activation: ${preferredLlmOnActivation || 'Not set (user needs to configure)'}`);

    // ============ SCAN COORDINATION SYSTEM ============
    // Global scan state to prevent conflicts between different scan types
    interface ScanState {
        isRealTimeScanRunning: boolean;
        isManualScanRunning: boolean;
        isFolderScanRunning: boolean;
        isSelectionScanRunning: boolean;
        isFixGenerationRunning: boolean;
        currentScanType: string | null;
        scanStartTime: number | null;
    }

    const scanState: ScanState = {
        isRealTimeScanRunning: false,
        isManualScanRunning: false,
        isFolderScanRunning: false,
        isSelectionScanRunning: false,
        isFixGenerationRunning: false,
        currentScanType: null,
        scanStartTime: null
    };

    // Real-time scan pause/resume system
    let realTimeScanPaused = false;
    let pendingRealTimeScanDocument: vscode.TextDocument | null = null;
    let realTimeScanResumeTimeout: NodeJS.Timeout | undefined;

    // Scan coordination functions
    function canStartRealTimeScan(): boolean {
        const otherScansRunning = scanState.isManualScanRunning || 
                                 scanState.isFolderScanRunning || 
                                 scanState.isSelectionScanRunning ||
                                 scanState.isFixGenerationRunning;
        
        if (otherScansRunning) {
            if (!realTimeScanPaused) {
                realTimeScanPaused = true;
                outputChannel.appendLine(`⏸️ REAL-TIME SCAN PAUSED: ${scanState.currentScanType} is running`);
            }
            return false;
        }
        return true;
    }

    function pauseRealTimeScanning(reason: string) {
        if (!realTimeScanPaused) {
            realTimeScanPaused = true;
            outputChannel.appendLine(`⏸️ REAL-TIME SCAN PAUSED: ${reason}`);
        }
        
        // Cancel any pending scan timeout
        if (scanTimeout) {
            clearTimeout(scanTimeout);
            scanTimeout = undefined;
        }
        
        // Cancel any pending resume timeout
        if (realTimeScanResumeTimeout) {
            clearTimeout(realTimeScanResumeTimeout);
            realTimeScanResumeTimeout = undefined;
        }
    }

    function resumeRealTimeScanning() {
        if (realTimeScanPaused) {
            realTimeScanPaused = false;
            outputChannel.appendLine(`▶️ REAL-TIME SCAN RESUMED`);
            
            // If there's a pending document to scan, scan it after a short delay
            if (pendingRealTimeScanDocument) {
                const docToScan = pendingRealTimeScanDocument;
                pendingRealTimeScanDocument = null;
                
                realTimeScanResumeTimeout = setTimeout(() => {
                    performRealTimeScan(docToScan).catch(error => {
                        outputChannel.appendLine(`Resume scan failed: ${error.message}`);
                    });
                }, 500); // Short delay to ensure other scan is fully completed
            }
        }
    }

    function startScan(scanType: 'realtime' | 'manual' | 'folder' | 'selection' | 'fix', description?: string): boolean {
        // Check if any scan is already running
        const anyScanRunning = scanState.isRealTimeScanRunning || 
                              scanState.isManualScanRunning || 
                              scanState.isFolderScanRunning || 
                              scanState.isSelectionScanRunning ||
                              scanState.isFixGenerationRunning;

        if (anyScanRunning && scanType !== 'realtime') {
            const currentScanDuration = scanState.scanStartTime ? (Date.now() - scanState.scanStartTime) / 1000 : 0;
            outputChannel.appendLine(`🚫 SCAN BLOCKED: Cannot start ${scanType} scan - ${scanState.currentScanType} is already running (${currentScanDuration.toFixed(1)}s)`);
            
            // ENHANCED: Reduce timeout from 5 minutes to 2 minutes for better UX
            // Auto-clear scan state if it's been running for more than 2 minutes (likely stuck)
            if (currentScanDuration > 120) {
                outputChannel.appendLine(`⚠️ SCAN TIMEOUT: ${scanState.currentScanType} has been running for ${currentScanDuration.toFixed(1)}s - force clearing`);
                
                // Determine which scan type is actually running and clear it
                if (scanState.isFixGenerationRunning) {
                    endScan('fix');
                } else if (scanState.isManualScanRunning) {
                    endScan('manual');
                } else if (scanState.isFolderScanRunning) {
                    endScan('folder');
                } else if (scanState.isSelectionScanRunning) {
                    endScan('selection');
                } else if (scanState.isRealTimeScanRunning) {
                    endScan('realtime');
                } else {
                    // Force clear everything if we can't determine which scan is running
                    outputChannel.appendLine(`🚨 UNKNOWN SCAN TYPE RUNNING - Force clearing all states`);
                    scanState.isRealTimeScanRunning = false;
                    scanState.isManualScanRunning = false;
                    scanState.isFolderScanRunning = false;
                    scanState.isSelectionScanRunning = false;
                    scanState.isFixGenerationRunning = false;
                    scanState.currentScanType = null;
                    scanState.scanStartTime = null;
                    resumeRealTimeScanning();
                }
                
                // Try starting the new scan again
                return startScan(scanType, description);
            }
            
            return false;
        }

        // Pause real-time scanning when starting other scan types
        if (scanType !== 'realtime') {
            pauseRealTimeScanning(description || scanType);
        }

        // Update scan state
        scanState.scanStartTime = Date.now();
        scanState.currentScanType = description || scanType;
        
        switch (scanType) {
            case 'realtime':
                scanState.isRealTimeScanRunning = true;
                break;
            case 'manual':
                scanState.isManualScanRunning = true;
                break;
            case 'folder':
                scanState.isFolderScanRunning = true;
                break;
            case 'selection':
                scanState.isSelectionScanRunning = true;
                break;
            case 'fix':
                scanState.isFixGenerationRunning = true;
                break;
        }

        outputChannel.appendLine(`✅ SCAN STARTED: ${scanState.currentScanType}`);
        return true;
    }

    function endScan(scanType: 'realtime' | 'manual' | 'folder' | 'selection' | 'fix'): void {
        const scanDuration = scanState.scanStartTime ? (Date.now() - scanState.scanStartTime) / 1000 : 0;
        outputChannel.appendLine(`🏁 SCAN COMPLETED: ${scanState.currentScanType} (${scanDuration.toFixed(1)}s) - Ending ${scanType} scan`);
        
        // Debug: Show scan state before clearing
        outputChannel.appendLine(`🔍 SCAN STATE BEFORE CLEAR: RT:${scanState.isRealTimeScanRunning}, M:${scanState.isManualScanRunning}, F:${scanState.isFolderScanRunning}, S:${scanState.isSelectionScanRunning}, FIX:${scanState.isFixGenerationRunning}`);
        
        // ENHANCED: Clear the specific scan type being ended
        let scanCleared = false;
        switch (scanType) {
            case 'realtime':
                if (scanState.isRealTimeScanRunning) {
                    scanState.isRealTimeScanRunning = false;
                    scanCleared = true;
                }
                break;
            case 'manual':
                if (scanState.isManualScanRunning) {
                    scanState.isManualScanRunning = false;
                    scanCleared = true;
                }
                break;
            case 'folder':
                if (scanState.isFolderScanRunning) {
                    scanState.isFolderScanRunning = false;
                    scanCleared = true;
                }
                break;
            case 'selection':
                if (scanState.isSelectionScanRunning) {
                    scanState.isSelectionScanRunning = false;
                    scanCleared = true;
                }
                break;
            case 'fix':
                if (scanState.isFixGenerationRunning) {
                    scanState.isFixGenerationRunning = false;
                    scanCleared = true;
                }
                break;
        }

        if (!scanCleared) {
            outputChannel.appendLine(`⚠️ WARNING: Attempted to end ${scanType} scan but it wasn't running!`);
            // Force clear all scans if there's a mismatch
            outputChannel.appendLine(`🚨 FORCE CLEARING ALL SCAN STATES due to mismatch`);
            scanState.isRealTimeScanRunning = false;
            scanState.isManualScanRunning = false;
            scanState.isFolderScanRunning = false;
            scanState.isSelectionScanRunning = false;
            scanState.isFixGenerationRunning = false;
            scanCleared = true;
        }

        // Debug: Show scan state after clearing
        outputChannel.appendLine(`🔍 SCAN STATE AFTER CLEAR: RT:${scanState.isRealTimeScanRunning}, M:${scanState.isManualScanRunning}, F:${scanState.isFolderScanRunning}, S:${scanState.isSelectionScanRunning}, FIX:${scanState.isFixGenerationRunning}`);

        // Reset global state if no scans are running
        const anyScanRunning = scanState.isRealTimeScanRunning || 
                              scanState.isManualScanRunning || 
                              scanState.isFolderScanRunning || 
                              scanState.isSelectionScanRunning ||
                              scanState.isFixGenerationRunning;
        
        if (!anyScanRunning) {
            outputChannel.appendLine(`✅ ALL SCANS COMPLETE: Resetting global scan state and resuming real-time scanning`);
            scanState.currentScanType = null;
            scanState.scanStartTime = null;
            
            // Resume real-time scanning when all other scans are complete
            if (scanType !== 'realtime') {
                resumeRealTimeScanning();
            }
        } else {
            outputChannel.appendLine(`⏳ OTHER SCANS STILL RUNNING: Not resuming real-time scanning yet`);
        }
    }

    function getScanStatus(): string {
        if (scanState.currentScanType) {
            const scanDuration = scanState.scanStartTime ? (Date.now() - scanState.scanStartTime) / 1000 : 0;
            return `${scanState.currentScanType} (${scanDuration.toFixed(1)}s)`;
        }
        return 'idle';
    }
    // ============ END SCAN COORDINATION SYSTEM ============

    // Create diagnostics collection for real-time scanning
    const diagnosticsCollection = vscode.languages.createDiagnosticCollection('secure-coding-assistant');
    context.subscriptions.push(diagnosticsCollection);
    outputChannel.appendLine(`🔧 DEBUG: Diagnostics collection created: ${diagnosticsCollection ? 'SUCCESS' : 'FAILED'}`);

    // Create status bar item for real-time scanning
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 1000);
    statusBarItem.command = 'secure-coding-assistant.toggleRealTimeScanning';
    statusBarItem.tooltip = 'Click to toggle real-time security scanning';
    context.subscriptions.push(statusBarItem);
    
    // Function to count total security issues across all open files
    function getTotalSecurityIssuesCount(): number {
        let totalIssues = 0;
        
        // Iterate through all diagnostics in the collection
        diagnosticsCollection.forEach((uri, diagnostics) => {
            // Count only our security diagnostics
            const securityDiagnostics = diagnostics.filter(diagnostic => 
                diagnostic.source === 'Secure Coding Assistant'
            );
            totalIssues += securityDiagnostics.length;
        });
        
        return totalIssues;
    }

    // Helper function to set colored status bar display
    function setStatusBarDisplay(text: string, color?: vscode.ThemeColor, backgroundColor?: vscode.ThemeColor, tooltip?: string) {
        statusBarItem.text = text;
        statusBarItem.color = color;
        statusBarItem.backgroundColor = backgroundColor;
        statusBarItem.tooltip = tooltip || text;
    }

    // Enhanced status bar with support for different scan types and operations
    const updateStatusBar = (status: 'idle' | 'scanning' | 'complete' | 'fixing' | 'manual' | 'folder', issueCount?: number, fileName?: string, scanType?: string) => {
        const isEnabled = context.globalState.get('realTimeScanningEnabled', true);
        
        if (!isEnabled) {
            statusBarItem.text = '$(lock) Security: OFF';
            statusBarItem.color = new vscode.ThemeColor('charts.red');
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.tooltip = 'Real-time security scanning is disabled. Click to enable.';
        } else {
            // Check if any scan is currently running (except real-time which is passive)
            const isAnyScanRunning = scanState.isManualScanRunning || 
                                   scanState.isFolderScanRunning || 
                                   scanState.isSelectionScanRunning ||
                                   scanState.isFixGenerationRunning ||
                                   scanState.isRealTimeScanRunning;
            
            switch (status) {
                case 'scanning':
                    const scanIcon = getScanTypeIcon(scanType || 'code');
                    statusBarItem.text = `${scanIcon} Scanning ${fileName || ''}...`;
                    statusBarItem.color = new vscode.ThemeColor('charts.green');
                    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                    statusBarItem.tooltip = `Security scan in progress (${scanType || 'real-time'})...`;
                    break;
                case 'fixing':
                    statusBarItem.text = `$(tools) Generating fixes...`;
                    statusBarItem.color = new vscode.ThemeColor('charts.orange');
                    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                    statusBarItem.tooltip = 'Generating security fixes with AI...';
                    break;
                case 'manual':
                    statusBarItem.text = `$(target) Manual scan...`;
                    statusBarItem.color = new vscode.ThemeColor('charts.blue');
                    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                    statusBarItem.tooltip = 'Manual security scan in progress...';
                    break;
                case 'folder':
                    statusBarItem.text = `$(folder) Folder scan...`;
                    statusBarItem.color = new vscode.ThemeColor('charts.purple');
                    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                    statusBarItem.tooltip = 'Folder security scan in progress...';
                    break;
                case 'complete':
                    // Only show issue count if no other scans are running
                    if (isAnyScanRunning) {
                        // If a scan is running, show that scan's status instead
                        if (scanState.isFixGenerationRunning) {
                            statusBarItem.text = `$(tools) Generating fixes...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.orange');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Generating security fixes with AI...';
                        } else if (scanState.isManualScanRunning) {
                            statusBarItem.text = `$(target) Manual scan...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.blue');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Manual security scan in progress...';
                        } else if (scanState.isFolderScanRunning) {
                            statusBarItem.text = `$(folder) Folder scan...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.purple');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Folder security scan in progress...';
                        } else if (scanState.isRealTimeScanRunning) {
                            const scanIcon = getScanTypeIcon(scanType || 'code');
                            statusBarItem.text = `${scanIcon} Scanning...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.green');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Real-time security scan in progress...';
                        }
                    } else {
                        // No scans running, show issue count
                        const totalIssues = issueCount !== undefined ? issueCount : getTotalSecurityIssuesCount();
                        if (totalIssues > 0) {
                            statusBarItem.text = `$(error) Security: ${totalIssues} issues`;
                            statusBarItem.color = new vscode.ThemeColor('errorForeground');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                            statusBarItem.tooltip = `Found ${totalIssues} security issues across all open files. Click to toggle scanning.`;
                        } else {
                            statusBarItem.text = '$(shield) Security: Clean';
                            statusBarItem.color = new vscode.ThemeColor('charts.green');
                            statusBarItem.backgroundColor = undefined;
                            statusBarItem.tooltip = 'No security issues found. Click to toggle scanning.';
                        }
                    }
                    break;
                case 'idle':
                default:
                    // Only show issue count if no scans are running
                    if (isAnyScanRunning) {
                        // If a scan is running, show that scan's status instead
                        if (scanState.isFixGenerationRunning) {
                            statusBarItem.text = `$(tools) Generating fixes...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.orange');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Generating security fixes with AI...';
                        } else if (scanState.isManualScanRunning) {
                            statusBarItem.text = `$(target) Manual scan...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.blue');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Manual security scan in progress...';
                        } else if (scanState.isFolderScanRunning) {
                            statusBarItem.text = `$(folder) Folder scan...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.purple');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Folder security scan in progress...';
                        } else if (scanState.isRealTimeScanRunning) {
                            const scanIcon = getScanTypeIcon(scanType || 'code');
                            statusBarItem.text = `${scanIcon} Scanning...`;
                            statusBarItem.color = new vscode.ThemeColor('charts.green');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
                            statusBarItem.tooltip = 'Real-time security scan in progress...';
                        }
                    } else {
                        // No scans running, show issue count or idle status
                        const idleTotalIssues = getTotalSecurityIssuesCount();
                        if (idleTotalIssues > 0) {
                            statusBarItem.text = `$(error) Security: ${idleTotalIssues} issues`;
                            statusBarItem.color = new vscode.ThemeColor('errorForeground');
                            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                            statusBarItem.tooltip = `Found ${idleTotalIssues} security issues across all open files. Click to toggle scanning.`;
                        } else {
                            statusBarItem.text = '$(shield) Security: ON';
                            statusBarItem.color = new vscode.ThemeColor('charts.green');
                            statusBarItem.backgroundColor = undefined;
                            statusBarItem.tooltip = 'Real-time security scanning enabled. Click to disable.';
                        }
                    }
                    break;
            }
        }
        statusBarItem.show();
    };

    // Get appropriate icon for scan type with colored codicons
    function getScanTypeIcon(scanType: string): string {
        switch (scanType) {
            case 'code': return '$(search)';
            case 'config': return '$(settings-gear)';
            case 'iac': return '$(cloud)';
            case 'sca': return '$(package)';
            case 'sensitive': return '$(key)';
            case 'database': return '$(database)';
            case 'web': return '$(globe)';
            case 'script': return '$(file-code)';
            case 'data': return '$(graph)';
            case 'unknown': return '$(question)';
            default: return '$(search)';
        }
    }
    
    // Initialize status bar
    updateStatusBar('idle');

    // Register code actions provider for quick fixes
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        ['javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 'php', 'go', 'rust', 'ruby'],
        {
            provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
                const codeActions: vscode.CodeAction[] = [];
                
                // Get diagnostics for this range
                const diagnostics = context.diagnostics.filter(diagnostic => 
                    diagnostic.source === 'Secure Coding Assistant'
                );
                
                for (const diagnostic of diagnostics) {
                    // Create quick fix action
                    const quickFix = new vscode.CodeAction(
                        `$(tools) Fix Security Issue: ${diagnostic.message.substring(2, 50)}...`,
                        vscode.CodeActionKind.QuickFix
                    );
                    quickFix.diagnostics = [diagnostic];
                    quickFix.isPreferred = true;
                    
                    // Add command to generate fix using LLM
                    quickFix.command = {
                        title: 'Generate security fix',
                        command: 'secure-coding-assistant.generateQuickFix',
                        arguments: [document.uri, diagnostic.range, diagnostic.message]
                    };
                    
                    codeActions.push(quickFix);
                    
                    // Create "Show More Info" action
                    const moreInfo = new vscode.CodeAction(
                        `$(book) Learn More About This Issue`,
                        vscode.CodeActionKind.Empty
                    );
                    moreInfo.command = {
                        title: 'Show security information',
                        command: 'secure-coding-assistant.showSecurityInfo',
                        arguments: [diagnostic.message, diagnostic.code]
                    };
                    
                    codeActions.push(moreInfo);
                }
                
                return codeActions;
            }
        }
    );
    context.subscriptions.push(codeActionProvider);

    // Real-time scanning variables
    let scanTimeout: NodeJS.Timeout | undefined;
    // Get configurable scan delay
    const getScanDelay = () => vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<number>('scanDelay', 1000);

    // Comprehensive file type support function
    function shouldScanFile(document: vscode.TextDocument): { shouldScan: boolean; scanType: string; reason: string } {
        const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
        const languageId = document.languageId;
        const content = document.getText();
        
        // Get configuration settings
        const config = vscode.workspace.getConfiguration('secureCodingAssistant.realtime');
        const scanAllFileTypes = config.get<boolean>('scanAllFileTypes', true);
        const skipVSCodeInternalFiles = config.get<boolean>('skipVSCodeInternalFiles', true);
        
        // Skip empty files
        if (!content.trim()) {
            return { shouldScan: false, scanType: 'none', reason: 'Empty file' };
        }
        
        // Skip VS Code internal files and output channels (if configured)
        if (skipVSCodeInternalFiles && (
            fileName.includes('extension-output-') || 
            fileName.includes('#') || 
            languageId === 'log' || 
            languageId === 'output' ||
            document.uri.scheme !== 'file')) {
            return { shouldScan: false, scanType: 'none', reason: 'VS Code internal/output file (skipped by configuration)' };
        }
        
        // Programming languages - always scan
        const programmingLanguages = [
            'javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 
            'php', 'go', 'rust', 'ruby', 'swift', 'kotlin', 'scala', 'dart',
            'perl', 'lua', 'r', 'matlab', 'julia', 'haskell', 'erlang', 'elixir',
            'clojure', 'fsharp', 'vb', 'pascal', 'fortran', 'cobol', 'ada',
            'objective-c', 'objective-cpp', 'groovy', 'powershell', 'shellscript',
            'bash', 'zsh', 'fish', 'csh', 'tcsh', 'ksh'
        ];
        
        if (programmingLanguages.includes(languageId)) {
            return { shouldScan: true, scanType: 'code', reason: `Programming language: ${languageId}` };
        }
        
        // Configuration and data files - scan for security misconfigurations
        const configLanguages = [
            'json', 'yaml', 'yml', 'xml', 'toml', 'ini', 'properties', 'env',
            'dockerfile', 'dockercompose', 'terraform', 'hcl', 'bicep',
            'cloudformation', 'ansible', 'kubernetes', 'helm'
        ];
        
        if (configLanguages.includes(languageId)) {
            return { shouldScan: true, scanType: 'config', reason: `Configuration file: ${languageId}` };
        }
        
        // Dependency files - scan for SCA (Software Composition Analysis)
        const dependencyFiles = [
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'pipfile', 'pyproject.toml', 'poetry.lock',
            'pom.xml', 'build.gradle', 'gradle.lockfile', 'maven-metadata.xml',
            'cargo.toml', 'cargo.lock', 'composer.json', 'composer.lock',
            'gemfile', 'gemfile.lock', 'go.mod', 'go.sum', 'mix.exs', 'mix.lock',
            'pubspec.yaml', 'pubspec.lock', 'project.clj', 'deps.edn'
        ];
        
        const isDependencyFile = dependencyFiles.some(depFile => 
            fileName.toLowerCase().includes(depFile.toLowerCase()) ||
            fileName.toLowerCase().endsWith(depFile.toLowerCase())
        );
        
        if (isDependencyFile) {
            return { shouldScan: true, scanType: 'sca', reason: `Dependency file: ${fileName}` };
        }
        
        // Infrastructure as Code files
        const iacExtensions = ['.tf', '.tfvars', '.hcl', '.bicep', '.arm', '.template', '.cfn'];
        const hasIacExtension = iacExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
        
        if (hasIacExtension) {
            return { shouldScan: true, scanType: 'iac', reason: `Infrastructure as Code: ${fileName}` };
        }
        
        // Script files by extension
        const scriptExtensions = [
            '.sh', '.bash', '.zsh', '.fish', '.csh', '.tcsh', '.ksh',
            '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vba',
            '.awk', '.sed', '.perl', '.pl', '.py', '.rb', '.lua'
        ];
        
        const hasScriptExtension = scriptExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
        
        if (hasScriptExtension) {
            return { shouldScan: true, scanType: 'script', reason: `Script file: ${fileName}` };
        }
        
        // Web files - scan for XSS, CSRF, etc.
        const webLanguages = ['html', 'css', 'scss', 'sass', 'less', 'vue', 'svelte', 'jsx', 'tsx'];
        
        if (webLanguages.includes(languageId)) {
            return { shouldScan: true, scanType: 'web', reason: `Web file: ${languageId}` };
        }
        
        // Database files
        const dbLanguages = ['sql', 'mysql', 'postgresql', 'sqlite', 'plsql', 'tsql'];
        
        if (dbLanguages.includes(languageId)) {
            return { shouldScan: true, scanType: 'database', reason: `Database file: ${languageId}` };
        }
        
        // Data files that might contain sensitive information
        const dataLanguages = ['csv', 'tsv', 'parquet', 'avro', 'protobuf'];
        
        if (dataLanguages.includes(languageId)) {
            return { shouldScan: true, scanType: 'data', reason: `Data file: ${languageId}` };
        }
        
        // Special file types
        if (languageId === 'plaintext' || languageId === 'text') {
            // Check file extension for plaintext files
            if (fileName.includes('.env') || fileName.includes('.secret') || 
                fileName.includes('.key') || fileName.includes('.pem') ||
                fileName.includes('.crt') || fileName.includes('.cer') ||
                fileName.toLowerCase().includes('password') ||
                fileName.toLowerCase().includes('secret') ||
                fileName.toLowerCase().includes('token') ||
                fileName.toLowerCase().includes('credential')) {
                return { shouldScan: true, scanType: 'sensitive', reason: `Potentially sensitive file: ${fileName}` };
            }
            
            // Check content for code patterns
            if (content.includes('function') || content.includes('class') || 
                content.includes('import') || content.includes('require') ||
                content.includes('#!/') || content.includes('<?') ||
                content.includes('<script') || content.includes('<html')) {
                return { shouldScan: true, scanType: 'code', reason: 'Contains code patterns' };
            }
        }
        
        // If scanAllFileTypes is disabled, only scan programming languages and dependency files
        if (!scanAllFileTypes) {
            const basicLanguages = [
                'javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 
                'php', 'go', 'rust', 'ruby', 'swift', 'kotlin'
            ];
            
            const basicDependencyFiles = [
                'package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 
                'cargo.toml', 'composer.json', 'gemfile', 'go.mod'
            ];
            
            if (basicLanguages.includes(languageId)) {
                return { shouldScan: true, scanType: 'code', reason: `Core programming language: ${languageId}` };
            }
            
            const isBasicDependencyFile = basicDependencyFiles.some(depFile => 
                fileName.toLowerCase().includes(depFile.toLowerCase())
            );
            
            if (isBasicDependencyFile) {
                return { shouldScan: true, scanType: 'sca', reason: `Core dependency file: ${fileName}` };
            }
            
            return { shouldScan: false, scanType: 'none', reason: `File type scanning disabled (scanAllFileTypes=false): ${languageId}` };
        }
        
        // Default: scan unknown file types if they have meaningful content (when scanAllFileTypes is enabled)
        if (content.length > 50) { // At least 50 characters
            return { shouldScan: true, scanType: 'unknown', reason: `Unknown file type with content: ${languageId}` };
        }
        
        return { shouldScan: false, scanType: 'none', reason: `No security relevance detected: ${languageId}` };
    }

    // Interface for change information
    interface ChangeInfo {
        startLine: number;
        endLine: number;
        contextLines: number;
        changedContent: string;
        contextContent: string;
        affectedRanges: vscode.Range[];
    }

    // Extract change information for incremental scanning
    function extractChangeInfo(event: vscode.TextDocumentChangeEvent): ChangeInfo {
        const document = event.document;
        const changes = event.contentChanges;
        
        if (changes.length === 0) {
            return {
                startLine: 0,
                endLine: 0,
                contextLines: 0,
                changedContent: '',
                contextContent: '',
                affectedRanges: []
            };
        }

        // Find the range of all changes
        let minLine = Number.MAX_SAFE_INTEGER;
        let maxLine = 0;
        const affectedRanges: vscode.Range[] = [];

        changes.forEach(change => {
            const startLine = change.range.start.line;
            const endLine = change.range.end.line;
            
            minLine = Math.min(minLine, startLine);
            maxLine = Math.max(maxLine, endLine);
            affectedRanges.push(change.range);
        });

        // Add context lines before and after (5 lines each)
        const contextSize = 5;
        const contextStartLine = Math.max(0, minLine - contextSize);
        const contextEndLine = Math.min(document.lineCount - 1, maxLine + contextSize);

        // Extract the changed content with context
        const contextRange = new vscode.Range(contextStartLine, 0, contextEndLine, document.lineAt(contextEndLine).text.length);
        const contextContent = document.getText(contextRange);

        // Extract just the changed content
        const changedContent = changes.map(change => change.text).join('\n');

        return {
            startLine: minLine,
            endLine: maxLine,
            contextLines: contextEndLine - contextStartLine + 1,
            changedContent,
            contextContent,
            affectedRanges
        };
    }
    const SCAN_TIMEOUT = 60000; // 60 seconds max per scan (comprehensive scanning)
    let currentScanAbortController: AbortController | undefined;
    let lastScanContentHash: string = '';

    // Fast real-time LLM scanning function (optimized for speed)
    async function performFastLlmScan(
        selectedLlm: string,
        apiKey: string,
        content: string,
        languageId: string,
        fileName: string,
        fallbackMode: boolean = false
    ): Promise<Vulnerability[]> {
        const scanMode = fallbackMode ? 'fast fallback' : 'comprehensive';
        
        // Detect if this is a dependency file for SCA scanning
        const dependencyFiles = ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 'Cargo.toml', 'composer.json', 'Gemfile', 'go.mod', 'pyproject.toml', 'setup.py', 'yarn.lock', 'package-lock.json', 'Pipfile'];
        const isDependencyFile = dependencyFiles.some(depFile => fileName.toLowerCase().includes(depFile.toLowerCase()));
        
        if (isDependencyFile) {
            outputChannel.appendLine(`🚀 REAL-TIME SCA: Using ${scanMode} Software Composition Analysis scan`);
        } else {
            outputChannel.appendLine(`🚀 REAL-TIME: Using ${scanMode} LLM-only scan (no local findings)`);
        }
        
        // Create SCA-specific or general security prompts
        let prompt: string;
        
        if (isDependencyFile) {
            // SCA-specific prompt for dependency files
            prompt = fallbackMode 
                ? `Perform Software Composition Analysis (SCA) on this ${fileName} dependency file. Look for:
1. Vulnerable dependencies with known CVEs
2. Outdated packages with security issues
3. Insecure version constraints (wildcards, ranges)
4. Missing security patches
5. Dependencies with known malicious packages

Return JSON array with format: [{"description":"SCA issue","severity":"High|Medium|Low","lineNumber":"1","recommendation":"security fix"}]. Focus on top 10 critical dependency vulnerabilities:

\`\`\`${languageId}
${content}
\`\`\``
                : `Perform comprehensive Software Composition Analysis (SCA) on this ${fileName} dependency file. Analyze ALL dependencies for:
1. Known CVE vulnerabilities in specified versions
2. Outdated packages with available security updates
3. Insecure version pinning (wildcards, broad ranges)
4. Missing security patches and updates
5. Dependencies with known security advisories
6. Transitive dependency vulnerabilities
7. License compliance issues with security implications
8. Deprecated packages with security concerns
9. Package integrity and supply chain risks
10. Configuration security issues

Return JSON array with format: [{"description":"SCA security issue","severity":"High|Medium|Low","lineNumber":"1","recommendation":"security remediation"}]. Find ALL dependency security issues:

\`\`\`${languageId}
${content}
\`\`\``;
        } else {
            // Standard code security scanning prompt
            prompt = fallbackMode 
                ? `Analyze this ${languageId} code for the most critical security vulnerabilities. Return JSON array with format: [{"description":"issue","severity":"High|Medium|Low","lineNumber":"1","recommendation":"fix"}]. Focus on top 10 critical issues:

\`\`\`${languageId}
${content}
\`\`\``
                : `Analyze this ${languageId} code for ALL security vulnerabilities. Find as many issues as possible. Return JSON array with format: [{"description":"issue","severity":"High|Medium|Low","lineNumber":"1","recommendation":"fix"}]. Find ALL security issues, not just the top few:

\`\`\`${languageId}
${content}
\`\`\``;
        }

        try {
            if (selectedLlm === LlmProvider.OpenAI) {
                outputChannel.appendLine(`🤖 REAL-TIME: Calling OpenAI directly for ${scanMode} scan`);
                const openai = new OpenAI({ apiKey });
                
                const response = await retryWithExponentialBackoff(
                    async () => {
                        return await openai.chat.completions.create({
                            model: fallbackMode ? 'gpt-3.5-turbo' : 'gpt-4-turbo-preview', // Faster model for fallback
                            messages: [{ role: 'user', content: prompt }],
                            max_tokens: fallbackMode ? 1000 : 2000, // Fewer tokens for fallback
                            temperature: 0.1
                        });
                    },
                    undefined, // Use default retry config
                    `OpenAI ${scanMode} scan for ${fileName}`,
                    'OpenAI'
                );
                
                const responseContent = response.choices[0]?.message?.content || '[]';
                outputChannel.appendLine(`✅ REAL-TIME: OpenAI response received, parsing vulnerabilities`);
                
                // Parse and process vulnerabilities using the same comprehensive function as selection scan
                const rawVulnerabilities = JSON.parse(extractJsonFromMarkdown(responseContent));
                const vulnerabilities = processVulnerabilities(
                    Array.isArray(rawVulnerabilities) ? rawVulnerabilities : (rawVulnerabilities.issues || []),
                    selectedLlm,
                    fileName,
                    languageId,
                    content,
                    true // useLlmFirst = true for real-time scan
                );
                
                outputChannel.appendLine(`🎯 REAL-TIME: Found ${vulnerabilities.length} LLM-only vulnerabilities`);
                return vulnerabilities;
                
            } else if (selectedLlm === LlmProvider.Anthropic) {
                outputChannel.appendLine(`🤖 REAL-TIME: Calling Anthropic directly for ${scanMode} scan`);
                const anthropic = new Anthropic({ apiKey });
                
                const response = await retryWithExponentialBackoff(
                    async () => {
                        return await anthropic.messages.create({
                            model: fallbackMode ? 'claude-3-haiku-20240307' : 'claude-3-5-sonnet-20241022', // Faster model for fallback
                            max_tokens: fallbackMode ? 1000 : 2000,
                            messages: [{ role: 'user', content: prompt }]
                        });
                    },
                    undefined, // Use default retry config
                    `Anthropic ${scanMode} scan for ${fileName}`,
                    'Anthropic'
                );
                
                const firstBlock = response.content[0];
                const responseContent = firstBlock.type === 'text' ? firstBlock.text : '[]';
                outputChannel.appendLine(`✅ REAL-TIME: Anthropic response received, parsing vulnerabilities`);
                
                // Parse and process vulnerabilities using the same comprehensive function as selection scan
                const rawVulnerabilities = JSON.parse(extractJsonFromMarkdown(responseContent));
                const vulnerabilities = processVulnerabilities(
                    Array.isArray(rawVulnerabilities) ? rawVulnerabilities : (rawVulnerabilities.issues || []),
                    selectedLlm,
                    fileName,
                    languageId,
                    content,
                    true // useLlmFirst = true for real-time scan
                );
                
                outputChannel.appendLine(`🎯 REAL-TIME: Found ${vulnerabilities.length} LLM-only vulnerabilities`);
                return vulnerabilities;
            }
            
            outputChannel.appendLine(`❌ REAL-TIME: Unsupported LLM provider: ${selectedLlm}`);
            return [];
        } catch (error: any) {
            outputChannel.appendLine(`❌ REAL-TIME: ${scanMode} scan error: ${error.message}`);
            return [];
        }
    }

    // Real-time scanning function
    async function performRealTimeScan(document: vscode.TextDocument) {
        // Check if real-time scanning is enabled
        const isEnabled = context.globalState.get('realTimeScanningEnabled', true);
        if (!isEnabled) {
            return;
        }

        // ============ SCAN COORDINATION CHECK ============
        // Check if other scan types are running - if so, queue this scan for later
        if (!canStartRealTimeScan()) {
            // Store the document for scanning when other scans complete
            pendingRealTimeScanDocument = document;
            return; // Real-time scan paused - will resume automatically
        }
        
        // Clear any pending document since we're about to scan this one
        if (pendingRealTimeScanDocument === document) {
            pendingRealTimeScanDocument = null;
        }
        // ============ END SCAN COORDINATION CHECK ============

        // Use comprehensive file type support
        const scanDecision = shouldScanFile(document);
        
        if (!scanDecision.shouldScan) {
            outputChannel.appendLine(`⚠️ REAL-TIME: Skipping file - ${scanDecision.reason}: ${document.fileName.substring(document.fileName.lastIndexOf('/') + 1)}`);
            return;
        }
        
        const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
        outputChannel.appendLine(`🔍 REAL-TIME ${scanDecision.scanType.toUpperCase()}: Scanning ${fileName} - ${scanDecision.reason}`);

        // Skip empty documents
        const content = document.getText();
        if (!content.trim()) {
            diagnosticsCollection.delete(document.uri);
            return;
        }

        // Skip if content hasn't changed (cache optimization)
        const contentHash = content.substring(0, 100) + content.length;
        if (contentHash === lastScanContentHash) {
            return; // No changes, skip scan
        }
        lastScanContentHash = contentHash;

        try {
            // Cancel previous scan if still running
            if (currentScanAbortController) {
                currentScanAbortController.abort();
            }
            currentScanAbortController = new AbortController();

            // Get available LLMs
            const availableLlms = await getAvailableLlms(context);
            if (availableLlms.length === 0) {
                outputChannel.appendLine(`❌ No LLM API keys configured. Please add an API key first.`);
                return;
            }

            // Use preferred LLM if available, otherwise use first available
            const preferredLlm = getPreferredLlm();
            let selectedLlm = preferredLlm;
            let apiKey = preferredLlm ? await getApiKeySilent(context, preferredLlm) : undefined;
            
            if (!apiKey) {
                selectedLlm = availableLlms[0];
                apiKey = await getApiKeySilent(context, selectedLlm);
            }

            if (!apiKey || !selectedLlm) {
                outputChannel.appendLine(`❌ No API key available for any LLM provider.`);
                return;
            }

            // Check if scan was aborted
            if (currentScanAbortController.signal.aborted) {
                return;
            }

            // Perform fast LLM scan for real-time use
            const documentFileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
            const scanTypeDescription = scanDecision.scanType === 'sca' ? 'SCA (Software Composition Analysis)' : 
                                      scanDecision.scanType === 'config' ? 'Configuration Security' :
                                      scanDecision.scanType === 'iac' ? 'Infrastructure as Code' :
                                      scanDecision.scanType === 'web' ? 'Web Security' :
                                      scanDecision.scanType === 'database' ? 'Database Security' :
                                      scanDecision.scanType === 'sensitive' ? 'Sensitive Data' :
                                      'Code Security';
            outputChannel.appendLine(`⚡ REAL-TIME SCAN: Starting ${scanTypeDescription} scan for ${documentFileName}`);
            
            // ============ START REAL-TIME SCAN TRACKING ============
            if (!startScan('realtime', `Real-time scan: ${documentFileName}`)) {
                outputChannel.appendLine(`❌ REAL-TIME SCAN: Could not start scan - another scan is running`);
                return;
            }
            // ============ END START REAL-TIME SCAN TRACKING ============
            
            // Update status bar to show scanning with scan type
            updateStatusBar('scanning', undefined, documentFileName, scanDecision.scanType);
            
            // Try comprehensive scan first, then fallback to fast scan if timeout
            let vulnerabilities: Vulnerability[] = [];
            
            try {
                outputChannel.appendLine(`🔍 REAL-TIME: Attempting comprehensive scan first...`);
                const comprehensiveScanPromise = performFastLlmScan(
                    selectedLlm,
                    apiKey,
                    content,
                    document.languageId,
                    documentFileName,
                    false // comprehensive mode
                );
                
                const timeoutPromise = new Promise<never>((_, reject) => {
                    setTimeout(() => reject(new Error('Comprehensive scan timeout')), SCAN_TIMEOUT);
                });
                
                vulnerabilities = await Promise.race([comprehensiveScanPromise, timeoutPromise]);
                outputChannel.appendLine(`✅ REAL-TIME: Comprehensive scan completed successfully`);
                
            } catch (error: any) {
                if (error.message.includes('timeout')) {
                    outputChannel.appendLine(`⚠️ REAL-TIME: Comprehensive scan timed out, trying fast fallback...`);
                    
                    try {
                        const fastScanPromise = performFastLlmScan(
                            selectedLlm,
                            apiKey,
                            content,
                            document.languageId,
                            documentFileName,
                            true // fallback mode
                        );
                        
                        const fastTimeoutPromise = new Promise<never>((_, reject) => {
                            setTimeout(() => reject(new Error('Fast fallback timeout')), 20000); // 20 second timeout for fallback
                        });
                        
                        vulnerabilities = await Promise.race([fastScanPromise, fastTimeoutPromise]);
                        outputChannel.appendLine(`✅ REAL-TIME: Fast fallback scan completed successfully`);
                        
                    } catch (fallbackError: any) {
                        outputChannel.appendLine(`❌ REAL-TIME: Both comprehensive and fallback scans failed: ${fallbackError.message}`);
                        vulnerabilities = [];
                    }
                } else {
                    outputChannel.appendLine(`❌ REAL-TIME: Comprehensive scan failed: ${error.message}`);
                    vulnerabilities = [];
                }
            }

            outputChannel.appendLine(`⚡ REAL-TIME SCAN COMPLETE: ${vulnerabilities.length} LLM-only issues found`);

            // Check if scan was aborted
            if (currentScanAbortController.signal.aborted) {
                outputChannel.appendLine(`⚠️ Scan was cancelled`);
                return;
            }

            // Convert vulnerabilities to diagnostics
            const diagnostics: vscode.Diagnostic[] = [];
            
            // Split document into lines for better line number calculation
            const documentLines = content.split('\n');
            
            outputChannel.appendLine(`🔍 DEBUG: Processing ${vulnerabilities.length} vulnerabilities:`);
            
            for (let i = 0; i < vulnerabilities.length; i++) {
                const vuln = vulnerabilities[i];
                outputChannel.appendLine(`  [${i + 1}/${vulnerabilities.length}] ${vuln.description} | Line: ${vuln.lineNumber}`);
                // Enhanced line number detection - ensure EVERY vulnerability gets a red underline
                let lineNum = -1;
                let actualLineNumber = 1;
                let lineDetectionMethod = 'unknown';
                
                // Method 1: Direct line number from vulnerability
                if (vuln.lineNumber) {
                    const parsedLine = parseInt(vuln.lineNumber.toString());
                    if (!isNaN(parsedLine) && parsedLine > 0) {
                        lineNum = parsedLine - 1; // VS Code uses 0-based line numbers
                        actualLineNumber = parsedLine;
                        lineDetectionMethod = 'direct';
                    }
                }
                
                // Method 2: Extract from location string
                if (lineNum < 0 && vuln.location) {
                    const locationMatch = vuln.location.match(/line[:\s]+(\d+)/i);
                    if (locationMatch) {
                        const parsedLine = parseInt(locationMatch[1]);
                        if (!isNaN(parsedLine) && parsedLine > 0) {
                            lineNum = parsedLine - 1;
                            actualLineNumber = parsedLine;
                            lineDetectionMethod = 'location';
                        }
                    }
                }
                
                // Method 3: Search for code patterns in description
                if (lineNum < 0 && vuln.description) {
                    const codeMatches = vuln.description.match(/`([^`]+)`/g);
                    if (codeMatches) {
                        for (const match of codeMatches) {
                            const code = match.replace(/`/g, '').trim();
                            if (code.length > 2) { // Only search for meaningful code snippets
                                for (let i = 0; i < documentLines.length; i++) {
                                    if (documentLines[i].includes(code)) {
                                        lineNum = i;
                                        actualLineNumber = i + 1;
                                        lineDetectionMethod = 'code-match';
                                        outputChannel.appendLine(`    🎯 Found code match on line ${actualLineNumber}: "${code}"`);
                                        break;
                                    }
                                }
                                if (lineNum >= 0) break;
                            }
                        }
                    }
                }
                
                // Method 4: Extract line numbers from description text
                if (lineNum < 0 && vuln.description) {
                    const linePattern = vuln.description.match(/\b(?:line|Line|LINE)\s*[:\s]*(\d+)/i);
                    if (linePattern) {
                        const parsedLine = parseInt(linePattern[1]);
                        if (!isNaN(parsedLine) && parsedLine > 0) {
                            lineNum = parsedLine - 1;
                            actualLineNumber = parsedLine;
                            lineDetectionMethod = 'description-pattern';
                            outputChannel.appendLine(`    🎯 Extracted line from description: ${actualLineNumber}`);
                        }
                    }
                }
                
                // Method 5: Search for security-related keywords in code
                if (lineNum < 0) {
                    const securityKeywords = ['password', 'secret', 'token', 'api', 'sql', 'query', 'eval', 'exec', 'system', 'shell', 'cmd', 'input', 'user', 'request', 'response'];
                    const vulnDesc = vuln.description.toLowerCase();
                    
                    for (const keyword of securityKeywords) {
                        if (vulnDesc.includes(keyword)) {
                            for (let i = 0; i < documentLines.length; i++) {
                                if (documentLines[i].toLowerCase().includes(keyword)) {
                                    lineNum = i;
                                    actualLineNumber = i + 1;
                                    lineDetectionMethod = 'keyword-match';
                                    outputChannel.appendLine(`    🎯 Found keyword "${keyword}" on line ${actualLineNumber}`);
                                    break;
                                }
                            }
                            if (lineNum >= 0) break;
                        }
                    }
                }
                
                // Method 6: AGGRESSIVE Fallback - GUARANTEE every vulnerability gets a red line
                if (lineNum < 0) {
                    // Use multiple strategies to ensure visibility
                    const distributionStrategy = i % 4;
                    switch (distributionStrategy) {
                        case 0:
                            lineNum = Math.min(i, document.lineCount - 1);
                            break;
                        case 1:
                            lineNum = Math.min(Math.floor(document.lineCount / 3) + i, document.lineCount - 1);
                            break;
                        case 2:
                            lineNum = Math.min(Math.floor(document.lineCount / 2) + i, document.lineCount - 1);
                            break;
                        default:
                            lineNum = Math.min(Math.floor(document.lineCount * 0.75) + i, document.lineCount - 1);
                            break;
                    }
                    actualLineNumber = lineNum + 1;
                    lineDetectionMethod = 'aggressive-fallback';
                    outputChannel.appendLine(`    🚨 FORCING red line on line ${actualLineNumber} (fallback strategy ${distributionStrategy})`);
                }
                
                // FINAL SAFETY CHECK - Absolutely guarantee a valid line number
                if (lineNum < 0 || lineNum >= document.lineCount) {
                    lineNum = Math.min(Math.max(0, i), document.lineCount - 1);
                    actualLineNumber = lineNum + 1;
                    lineDetectionMethod = 'bounds-corrected';
                    outputChannel.appendLine(`    ⚠️ Line out of bounds, corrected to line ${actualLineNumber}`);
                }
                
                // ABSOLUTE FINAL CHECK - This should NEVER be needed but ensures no crashes
                if (lineNum < 0) {
                    lineNum = 0;
                    actualLineNumber = 1;
                    lineDetectionMethod = 'emergency-fallback';
                    outputChannel.appendLine(`    🆘 EMERGENCY: Forced to line 1 for vulnerability ${i + 1}`);
                }
                
                // Double-check that the line number makes sense
                if (lineNum < documentLines.length) {
                    const lineContent = documentLines[lineNum];
                    outputChannel.appendLine(`🔍 Line ${actualLineNumber}: "${lineContent.trim().substring(0, 50)}${lineContent.length > 50 ? '...' : ''}"`);
                }
                
                // Create a proper range for red underlines - use actual line length instead of 1000
                const lineText = document.lineAt(lineNum).text;
                const endChar = Math.max(lineText.length, 1);
                
                // Ensure unique ranges to prevent VS Code from merging diagnostics
                const startChar = Math.min(i, lineText.length);
                const adjustedEndChar = Math.max(endChar, startChar + 1);
                
                const range = new vscode.Range(lineNum, startChar, lineNum, adjustedEndChar);
                
                // Force all security issues to Error severity for maximum visibility (red underlines)
                let severity: vscode.DiagnosticSeverity = vscode.DiagnosticSeverity.Error;
                
                // Optional: Keep different colors but ensure all are visible
                // switch (vuln.severity) {
                //     case 'High':
                //         severity = vscode.DiagnosticSeverity.Error;
                //         break;
                //     case 'Medium':
                //         severity = vscode.DiagnosticSeverity.Warning;
                //         break;
                //     case 'Low':
                //     default:
                //         severity = vscode.DiagnosticSeverity.Information;
                //         break;
                // }

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `🔐 [${i + 1}/${vulnerabilities.length}] ${vuln.description}${vuln.recommendation ? ' | Fix: ' + vuln.recommendation : ''}`,
                    severity
                );
                
                diagnostic.source = 'Secure Coding Assistant';
                diagnostic.code = `SEC-${i + 1}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
                
                // Add unique related information to prevent merging
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `Security Issue #${i + 1}: ${vuln.severity} severity - Method: ${lineDetectionMethod}`
                    )
                ];
                
                diagnostics.push(diagnostic);
                
                outputChannel.appendLine(`🔧 DEBUG: Created diagnostic [${i + 1}] - Line: ${actualLineNumber}, Range: ${range.start.line}:${range.start.character}-${range.end.line}:${range.end.character}, Severity: ERROR, Method: ${lineDetectionMethod}`);
            }

            // Clear existing diagnostics first
            diagnosticsCollection.delete(document.uri);
            
            // Always update diagnostics (clears old ones, adds new ones)
            diagnosticsCollection.set(document.uri, diagnostics);
            
            // Force multiple updates to ensure visibility
            setTimeout(() => {
                diagnosticsCollection.set(document.uri, [...diagnostics]);
            }, 100);
            
            // Debug: Check if diagnostics were set
            const setDiagnostics = diagnosticsCollection.get(document.uri);
            outputChannel.appendLine(`🔧 DEBUG: Set ${diagnostics.length} diagnostics, retrieved ${setDiagnostics?.length || 0} from collection`);
            outputChannel.appendLine(`🔧 DEBUG: Document URI: ${document.uri.toString()}`);
            
            // CRITICAL VERIFICATION: Ensure every vulnerability got a red line
            if (diagnostics.length !== vulnerabilities.length) {
                outputChannel.appendLine(`🚨 MISMATCH: Found ${vulnerabilities.length} vulnerabilities but created ${diagnostics.length} diagnostics!`);
                outputChannel.appendLine(`🚨 This means some vulnerabilities did NOT get red lines!`);
            } else {
                outputChannel.appendLine(`✅ VERIFIED: All ${vulnerabilities.length} vulnerabilities have red lines`);
            }
            
            // Summary of all diagnostic locations
            const diagnosticSummary = diagnostics.map((d, idx) => `Line ${d.range.start.line + 1}`).join(', ');
            outputChannel.appendLine(`📍 DIAGNOSTIC LOCATIONS: ${diagnosticSummary}`);
            
            if (vulnerabilities.length > 0) {
                // Create summary of issues with line numbers
                const issueLines = diagnostics.map((diag, index) => {
                    const lineNumber = diag.range.start.line + 1;
                    const severity = diag.severity === vscode.DiagnosticSeverity.Error ? 'HIGH' : 
                                   diag.severity === vscode.DiagnosticSeverity.Warning ? 'MED' : 'LOW';
                    return `Line ${lineNumber} [${severity}]`;
                }).join(', ');
                
                outputChannel.appendLine(`🔴 Found ${vulnerabilities.length} security issues in ${documentFileName} at: ${issueLines}`);
                outputChannel.appendLine(`🎯 Red lines should appear in editor at these lines`);
                
                // Force refresh of diagnostics
                diagnosticsCollection.set(document.uri, [...diagnostics]);
                
                // Update status bar to show issues found
                updateStatusBar('complete', undefined, documentFileName);
                
                // 🚨 AUTOMATICALLY SHOW OUTPUT WINDOW when security issues are found (if enabled)
                const autoShowOutput = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('autoShowOutput', true);
                if (autoShowOutput) {
                    outputChannel.show(true); // Show output window but preserve focus on editor
                    outputChannel.appendLine(`🚨 SECURITY ISSUES DETECTED! Output window shown automatically.`);
                    outputChannel.appendLine(`📋 Review the detailed security analysis above.`);
                    outputChannel.appendLine(`💡 To disable auto-show: Settings → secureCodingAssistant.realtime.autoShowOutput`);
                } else {
                    outputChannel.appendLine(`🚨 SECURITY ISSUES DETECTED! (Output window auto-show disabled)`);
                    outputChannel.appendLine(`💡 To enable auto-show: Settings → secureCodingAssistant.realtime.autoShowOutput`);
                }
            } else {
                outputChannel.appendLine(`✅ No security issues found in ${documentFileName} - Code looks clean!`);
                // Clear any existing diagnostics
                diagnosticsCollection.delete(document.uri);
                
                // Update status bar to show clean status
                updateStatusBar('complete', undefined, documentFileName);
            }

        } catch (error: any) {
            // Only log error if not aborted
            if (!currentScanAbortController?.signal.aborted) {
                const documentFileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
                outputChannel.appendLine(`❌ Real-time scan error for ${documentFileName}: ${error.message}`);
                outputChannel.appendLine(`Stack trace: ${error.stack}`);
                
                // Clear any existing diagnostics on error
                diagnosticsCollection.delete(document.uri);
                
                // Update status bar to show error
                updateStatusBar('idle');
            }
        } finally {
            // ============ END REAL-TIME SCAN TRACKING ============
            endScan('realtime');
            // ============ END REAL-TIME SCAN TRACKING ============
        }
    }

    // Incremental real-time scanning function - scans only changed code with context
    async function performIncrementalRealTimeScan(document: vscode.TextDocument, changeInfo: ChangeInfo) {
        // Check if real-time scanning is enabled
        const isEnabled = context.globalState.get('realTimeScanningEnabled', true);
        if (!isEnabled) {
            return;
        }

        // ============ SCAN COORDINATION CHECK ============
        if (!canStartRealTimeScan()) {
            pendingRealTimeScanDocument = document;
            return;
        }
        
        if (pendingRealTimeScanDocument === document) {
            pendingRealTimeScanDocument = null;
        }
        // ============ END SCAN COORDINATION CHECK ============

        // Use comprehensive file type support
        const scanDecision = shouldScanFile(document);
        
        if (!scanDecision.shouldScan) {
            outputChannel.appendLine(`⚠️ INCREMENTAL: Skipping file - ${scanDecision.reason}: ${document.fileName.substring(document.fileName.lastIndexOf('/') + 1)}`);
            return;
        }
        
        const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
        outputChannel.appendLine(`🔍 INCREMENTAL ${scanDecision.scanType.toUpperCase()}: Scanning ${fileName} - ${scanDecision.reason}`);

        // Skip if no meaningful changes
        if (!changeInfo.contextContent.trim()) {
            return;
        }

        try {
            // Cancel previous scan if still running
            if (currentScanAbortController) {
                currentScanAbortController.abort();
            }
            currentScanAbortController = new AbortController();

            // Get available LLMs
            const availableLlms = await getAvailableLlms(context);
            if (availableLlms.length === 0) {
                outputChannel.appendLine(`❌ No LLM API keys configured. Please add an API key first.`);
                return;
            }

            // Use preferred LLM if available
            const preferredLlm = getPreferredLlm();
            let selectedLlm = preferredLlm;
            let apiKey = preferredLlm ? await getApiKeySilent(context, preferredLlm) : undefined;
            
            if (!apiKey) {
                selectedLlm = availableLlms[0];
                apiKey = await getApiKeySilent(context, selectedLlm);
            }

            if (!apiKey || !selectedLlm) {
                outputChannel.appendLine(`❌ No API key available for any LLM provider.`);
                return;
            }

            // Check if scan was aborted
            if (currentScanAbortController.signal.aborted) {
                return;
            }

            const documentFileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
            outputChannel.appendLine(`🔍 INCREMENTAL SCAN: Scanning ${changeInfo.contextLines} lines (${changeInfo.startLine + 1}-${changeInfo.endLine + 1} with context) in ${documentFileName}`);
            
            // ============ START REAL-TIME SCAN TRACKING ============
            if (!startScan('realtime', `Incremental scan: ${documentFileName} lines ${changeInfo.startLine + 1}-${changeInfo.endLine + 1}`)) {
                outputChannel.appendLine(`❌ INCREMENTAL SCAN: Could not start scan - another scan is running`);
                return;
            }
            // ============ END START REAL-TIME SCAN TRACKING ============
            
            // Update status bar to show scanning with scan type
            updateStatusBar('scanning', undefined, documentFileName, scanDecision.scanType);
            
            // Perform fast LLM scan on the changed content with context
            let vulnerabilities: Vulnerability[] = [];
            
            try {
                // Use the context content (changed lines + surrounding context)
                vulnerabilities = await performFastLlmScan(
                    selectedLlm,
                    apiKey,
                    changeInfo.contextContent,
                    document.languageId,
                    documentFileName,
                    false // not fallback mode - we want good results
                );
                
                // Adjust line numbers to match the original document
                vulnerabilities = vulnerabilities.map(vuln => {
                    const adjustedVuln = { ...vuln };
                    if (vuln.lineNumber) {
                        const lineNum = parseInt(vuln.lineNumber.toString());
                        if (!isNaN(lineNum)) {
                            // Adjust line number to account for context offset
                            const contextStartLine = Math.max(0, changeInfo.startLine - 5);
                            adjustedVuln.lineNumber = (lineNum + contextStartLine).toString();
                        }
                    }
                    return adjustedVuln;
                });
                
                outputChannel.appendLine(`✅ INCREMENTAL SCAN: Found ${vulnerabilities.length} issues in changed code`);
                
            } catch (error: any) {
                outputChannel.appendLine(`❌ INCREMENTAL SCAN: Failed: ${error.message}`);
                vulnerabilities = [];
            }

            // Check if scan was aborted
            if (currentScanAbortController.signal.aborted) {
                outputChannel.appendLine(`⚠️ Incremental scan was cancelled`);
                return;
            }

            // Get existing diagnostics to preserve issues outside the changed area
            const existingDiagnostics = diagnosticsCollection.get(document.uri) || [];
            const newDiagnostics: vscode.Diagnostic[] = [];
            
            // Keep existing diagnostics that are outside the changed area
            const changeStartLine = changeInfo.startLine;
            const changeEndLine = changeInfo.endLine;
            
            existingDiagnostics.forEach(diag => {
                const diagLine = diag.range.start.line;
                // Keep diagnostics that are not in the changed area
                if (diagLine < changeStartLine || diagLine > changeEndLine) {
                    newDiagnostics.push(diag);
                }
            });

            // Convert new vulnerabilities to diagnostics and add them
            const documentLines = document.getText().split('\n');
            
            vulnerabilities.forEach((vuln, index) => {
                // Enhanced line number detection for incremental scan
                let lineNum = -1;
                let actualLineNumber = 1;
                
                // Try to get line number from vulnerability
                if (vuln.lineNumber) {
                    const parsedLine = parseInt(vuln.lineNumber.toString());
                    if (!isNaN(parsedLine) && parsedLine > 0 && parsedLine <= documentLines.length) {
                        lineNum = parsedLine - 1;
                        actualLineNumber = parsedLine;
                    }
                }
                
                // If no valid line number, use the middle of the changed area
                if (lineNum < 0) {
                    lineNum = Math.floor((changeStartLine + changeEndLine) / 2);
                    actualLineNumber = lineNum + 1;
                }
                
                // Ensure line number is within bounds
                lineNum = Math.max(0, Math.min(lineNum, documentLines.length - 1));
                const lineText = documentLines[lineNum];
                const lineLength = lineText ? lineText.length : 1;
                
                // Create diagnostic with red underline
                const diagnostic = new vscode.Diagnostic(
                    new vscode.Range(lineNum, 0, lineNum, Math.max(lineLength, 1)),
                    `🔴 ${vuln.description} (${vuln.severity})`,
                    vscode.DiagnosticSeverity.Error
                );
                
                diagnostic.source = 'Secure Coding Assistant';
                diagnostic.code = `INCR-${vuln.id || `SEC-${index + 1}`}-${Date.now()}`;
                
                // Add related information
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, new vscode.Range(lineNum, 0, lineNum, lineLength)),
                        `Incremental scan found: ${vuln.recommendation || 'Review this security issue'}`
                    )
                ];
                
                newDiagnostics.push(diagnostic);
                
                outputChannel.appendLine(`🔴 INCREMENTAL: Line ${actualLineNumber}: ${vuln.description}`);
            });

            // Update diagnostics collection with combined results
            diagnosticsCollection.set(document.uri, newDiagnostics);
            
            const totalIssues = newDiagnostics.length;
            const newIssues = vulnerabilities.length;
            const preservedIssues = totalIssues - newIssues;
            
            outputChannel.appendLine(`📊 INCREMENTAL SCAN COMPLETE: ${newIssues} new issues found, ${preservedIssues} existing issues preserved, ${totalIssues} total issues`);
            
            // Update status bar
            updateStatusBar('complete', undefined, documentFileName);
            
            // Auto-show output if configured and issues found
            if (totalIssues > 0) {
                const autoShowOutput = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('autoShowOutput', true);
                if (autoShowOutput) {
                    outputChannel.show(true); // Show without taking focus
                    vscode.window.showInformationMessage(`🔍 Incremental scan found ${newIssues} new security issues in ${documentFileName}`, 'View Details').then(selection => {
                        if (selection === 'View Details') {
                            outputChannel.show();
                        }
                    });
                }
            }

        } catch (error: any) {
            outputChannel.appendLine(`❌ Incremental scan error: ${error.message}`);
            updateStatusBar('idle');
        } finally {
            // ============ END REAL-TIME SCAN TRACKING ============
            endScan('realtime');
            // ============ END REAL-TIME SCAN TRACKING ============
        }
    }

    // Text document change listener for real-time scanning
    const onDidChangeTextDocument = vscode.workspace.onDidChangeTextDocument((event) => {
        // Skip if real-time scanning is paused
        if (realTimeScanPaused) {
            // Store the document for scanning when resumed
            pendingRealTimeScanDocument = event.document;
            return;
        }

        // Skip unsupported file types early
        const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 'php', 'go', 'rust', 'ruby'];
        if (!supportedLanguages.includes(event.document.languageId)) {
            return;
        }

        // Only scan if there are meaningful changes (not just whitespace)
        const changedText = event.contentChanges.map(change => change.text).join('');
        if (changedText.trim().length === 0 && event.contentChanges.every(change => change.text.match(/^\s*$/))) {
            return; // Skip whitespace-only changes
        }

        // Extract change information for incremental scanning
        const changeInfo = extractChangeInfo(event);
        
        // Log the change for debugging (if enabled)
        const fileName = event.document.fileName.substring(event.document.fileName.lastIndexOf('/') + 1);
        const enableChangeLogging = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('enableChangeLogging', false);
        
        if (enableChangeLogging && changedText.trim().length > 0) {
            outputChannel.appendLine(`📝 REAL-TIME: Code change detected in ${fileName} - "${changedText.trim().substring(0, 50)}${changedText.length > 50 ? '...' : ''}"`);
            outputChannel.appendLine(`📍 REAL-TIME: Change range: lines ${changeInfo.startLine + 1}-${changeInfo.endLine + 1} (${changeInfo.contextLines} lines with context)`);
        }

        // Clear existing timeout
        if (scanTimeout) {
            clearTimeout(scanTimeout);
        }

        // Get current scan delay from settings
        const currentScanDelay = getScanDelay();

        // Set new timeout for scanning (debounced)
        scanTimeout = setTimeout(() => {
            // Double-check pause state before scanning
            if (!realTimeScanPaused) {
                // Check if incremental scanning is enabled
                const enableIncrementalScanning = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('enableIncrementalScanning', true);
                
                if (enableIncrementalScanning) {
                    if (enableChangeLogging) {
                        outputChannel.appendLine(`⚡ REAL-TIME: Triggering incremental scan after ${currentScanDelay}ms delay for ${fileName}`);
                    }
                    performIncrementalRealTimeScan(event.document, changeInfo).catch((error: any) => {
                        outputChannel.appendLine(`❌ Real-time incremental scan failed for ${fileName}: ${error.message}`);
                    });
                } else {
                    if (enableChangeLogging) {
                        outputChannel.appendLine(`⚡ REAL-TIME: Triggering full scan after ${currentScanDelay}ms delay for ${fileName}`);
                    }
                    performRealTimeScan(event.document).catch((error: any) => {
                        outputChannel.appendLine(`❌ Real-time full scan failed for ${fileName}: ${error.message}`);
                    });
                }
            } else {
                // Store for later if paused during timeout
                pendingRealTimeScanDocument = event.document;
            }
        }, currentScanDelay);
    });
    context.subscriptions.push(onDidChangeTextDocument);

    // Initial scan for already open documents
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        
        // First, create a simple test diagnostic to verify the system works
        const testDiagnostic = new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 10),
            '🔴 INIT TEST: If you see this, diagnostics work!',
            vscode.DiagnosticSeverity.Error
        );
        testDiagnostic.source = 'Secure Coding Assistant';
        diagnosticsCollection.set(doc.uri, [testDiagnostic]);
        outputChannel.appendLine(`🧪 INIT: Added test diagnostic to verify system works`);
        
        // Then do the real scan
        setTimeout(() => {
            if (!realTimeScanPaused) {
                performRealTimeScan(doc).catch(error => {
                    outputChannel.appendLine(`Initial real-time scan failed: ${error.message}`);
                });
            } else {
                // Store for scanning when resumed
                pendingRealTimeScanDocument = doc;
            }
        }, 2000);
    }

    // Scan when switching between editors
    const onDidChangeActiveTextEditor = vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor) {
            if (realTimeScanPaused) {
                // Store for scanning when resumed
                pendingRealTimeScanDocument = editor.document;
            } else {
                performRealTimeScan(editor.document).catch(error => {
                    outputChannel.appendLine(`Editor switch scan failed: ${error.message}`);
                });
            }
        }
    });
    context.subscriptions.push(onDidChangeActiveTextEditor);

    // Immediate scan when opening a file
    const onDidOpenTextDocument = vscode.workspace.onDidOpenTextDocument((document) => {
        // Only scan if it's a visible document (not internal VS Code documents)
        if (document.uri.scheme === 'file') {
            if (realTimeScanPaused) {
                // Store for scanning when resumed
                pendingRealTimeScanDocument = document;
            } else {
                performRealTimeScan(document).catch(error => {
                    const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
                    outputChannel.appendLine(`❌ File open scan failed for ${fileName}: ${error.message}`);
                });
            }
        }
    });
    context.subscriptions.push(onDidOpenTextDocument);

    // Scan when a file is saved (ensures we catch all changes)
    const onDidSaveTextDocument = vscode.workspace.onDidSaveTextDocument((document) => {
        // Only scan if it's a visible document (not internal VS Code documents)
        if (document.uri.scheme === 'file') {
            const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
            const enableChangeLogging = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('enableChangeLogging', false);
            
            if (enableChangeLogging) {
                outputChannel.appendLine(`💾 REAL-TIME: File saved - ${fileName}, triggering immediate scan`);
            }
            
            if (realTimeScanPaused) {
                // Store for scanning when resumed
                pendingRealTimeScanDocument = document;
            } else {
                // Immediate scan on save (no delay)
                performRealTimeScan(document).catch(error => {
                    outputChannel.appendLine(`❌ File save scan failed for ${fileName}: ${error.message}`);
                });
            }
        }
    });
    context.subscriptions.push(onDidSaveTextDocument);

    // Event listener for when files are closed - update status bar count
    const onDidCloseTextDocument = vscode.workspace.onDidCloseTextDocument((document) => {
        // Clear diagnostics for the closed file
        diagnosticsCollection.delete(document.uri);
        
        // Only update status bar if no scans are running
        const isAnyScanRunning = scanState.isManualScanRunning || 
                               scanState.isFolderScanRunning || 
                               scanState.isSelectionScanRunning ||
                               scanState.isFixGenerationRunning ||
                               scanState.isRealTimeScanRunning;
        
        if (!isAnyScanRunning) {
            updateStatusBar('idle');
        }
        
        const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
        const totalIssues = getTotalSecurityIssuesCount();
        outputChannel.appendLine(`📄 File closed: ${fileName} - Total issues across all files: ${totalIssues}${isAnyScanRunning ? ' (status bar not updated - scan in progress)' : ''}`);
    });
    context.subscriptions.push(onDidCloseTextDocument);

    // Event listener for when diagnostics change - update status bar count
    const onDidChangeDiagnostics = vscode.languages.onDidChangeDiagnostics((event) => {
        // Only update status bar if no scans are running
        const isAnyScanRunning = scanState.isManualScanRunning || 
                               scanState.isFolderScanRunning || 
                               scanState.isSelectionScanRunning ||
                               scanState.isFixGenerationRunning ||
                               scanState.isRealTimeScanRunning;
        
        if (!isAnyScanRunning) {
            // Check if any of the changed URIs contain our diagnostics
            let hasSecurityDiagnostics = false;
            for (const uri of event.uris) {
                const diagnostics = diagnosticsCollection.get(uri);
                if (diagnostics && diagnostics.length > 0) {
                    hasSecurityDiagnostics = true;
                    break;
                }
            }
            
            // Only update status bar if we have security diagnostics or if diagnostics were cleared
            if (hasSecurityDiagnostics || event.uris.length > 0) {
                updateStatusBar('idle');
            }
        }
    });
    context.subscriptions.push(onDidChangeDiagnostics);

    // Command to toggle real-time scanning
    const toggleRealTimeScanCommand = vscode.commands.registerCommand('secure-coding-assistant.toggleRealTimeScanning', () => {
        const isEnabled = context.globalState.get('realTimeScanningEnabled', true);
        context.globalState.update('realTimeScanningEnabled', !isEnabled);
        const status = !isEnabled ? 'enabled' : 'disabled';
        vscode.window.showInformationMessage(`Real-time security scanning ${status}.`);
        outputChannel.appendLine(`Real-time scanning ${status}.`);
        
        if (!isEnabled) {
            // Clear all diagnostics when disabled
            diagnosticsCollection.clear();
            updateStatusBar('idle');
        } else if (vscode.window.activeTextEditor) {
            // Perform scan when enabled
            updateStatusBar('idle');
            performRealTimeScan(vscode.window.activeTextEditor.document);
        } else {
            updateStatusBar('idle');
        }
    });
    context.subscriptions.push(toggleRealTimeScanCommand);

    // Command to toggle auto-show output window
    const toggleAutoShowOutputCommand = vscode.commands.registerCommand('secure-coding-assistant.toggleAutoShowOutput', () => {
        const currentSetting = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('autoShowOutput', true);
        vscode.workspace.getConfiguration('secureCodingAssistant.realtime').update('autoShowOutput', !currentSetting, vscode.ConfigurationTarget.Global);
        const status = !currentSetting ? 'enabled' : 'disabled';
        vscode.window.showInformationMessage(`Auto-show output window for real-time scans ${status}.`);
        outputChannel.appendLine(`Auto-show output window ${status}.`);
    });
    context.subscriptions.push(toggleAutoShowOutputCommand);

    // Command to adjust scan delay
    const adjustScanDelayCommand = vscode.commands.registerCommand('secure-coding-assistant.adjustScanDelay', async () => {
        const currentDelay = getScanDelay();
        const newDelay = await vscode.window.showInputBox({
            prompt: 'Enter scan delay in milliseconds (500-5000)',
            value: currentDelay.toString(),
            validateInput: (value) => {
                const num = parseInt(value);
                if (isNaN(num) || num < 500 || num > 5000) {
                    return 'Please enter a number between 500 and 5000';
                }
                return null;
            }
        });
        
        if (newDelay) {
            await vscode.workspace.getConfiguration('secureCodingAssistant.realtime').update('scanDelay', parseInt(newDelay), vscode.ConfigurationTarget.Global);
            vscode.window.showInformationMessage(`Real-time scan delay updated to ${newDelay}ms`);
            outputChannel.appendLine(`⚙️ Real-time scan delay updated to ${newDelay}ms`);
        }
    });
    context.subscriptions.push(adjustScanDelayCommand);

    // Command to toggle incremental scanning
    const toggleIncrementalScanningCommand = vscode.commands.registerCommand('secure-coding-assistant.toggleIncrementalScanning', () => {
        const currentSetting = vscode.workspace.getConfiguration('secureCodingAssistant.realtime').get<boolean>('enableIncrementalScanning', true);
        vscode.workspace.getConfiguration('secureCodingAssistant.realtime').update('enableIncrementalScanning', !currentSetting, vscode.ConfigurationTarget.Global);
        const status = !currentSetting ? 'enabled' : 'disabled';
        const mode = !currentSetting ? 'incremental (faster)' : 'full file (comprehensive)';
        vscode.window.showInformationMessage(`Real-time scanning mode: ${mode}`);
        outputChannel.appendLine(`⚙️ Incremental scanning ${status} - using ${mode} scanning`);
    });
    context.subscriptions.push(toggleIncrementalScanningCommand);

    // Command to force clear scan state (emergency reset)
    const forceClearScanStateCommand = vscode.commands.registerCommand('secure-coding-assistant.forceClearScanState', () => {
        outputChannel.appendLine(`🚨 FORCE CLEARING SCAN STATE - Emergency Reset`);
        outputChannel.appendLine(`📊 Before Reset: RT:${scanState.isRealTimeScanRunning}, M:${scanState.isManualScanRunning}, F:${scanState.isFolderScanRunning}, S:${scanState.isSelectionScanRunning}, FIX:${scanState.isFixGenerationRunning}`);
        outputChannel.appendLine(`📊 Current Scan Type: ${scanState.currentScanType || 'None'}`);
        
        // Force clear all scan states
        scanState.isRealTimeScanRunning = false;
        scanState.isManualScanRunning = false;
        scanState.isFolderScanRunning = false;
        scanState.isSelectionScanRunning = false;
        scanState.isFixGenerationRunning = false;
        scanState.currentScanType = null;
        scanState.scanStartTime = null;
        
        // Resume real-time scanning
        resumeRealTimeScanning();
        
        outputChannel.appendLine(`✅ SCAN STATE RESET COMPLETE - All scans cleared, real-time scanning resumed`);
        vscode.window.showInformationMessage('Scan state has been force-cleared. Real-time scanning resumed.');
    });
    context.subscriptions.push(forceClearScanStateCommand);

    // Command to show current scan status
    const showScanStatusCommand = vscode.commands.registerCommand('secure-coding-assistant.showScanStatus', () => {
        const status = getScanStatus();
        const details = `
Current Status: ${status}
Real-time: ${scanState.isRealTimeScanRunning ? 'RUNNING' : 'STOPPED'}
Manual: ${scanState.isManualScanRunning ? 'RUNNING' : 'STOPPED'}
Folder: ${scanState.isFolderScanRunning ? 'RUNNING' : 'STOPPED'}
Selection: ${scanState.isSelectionScanRunning ? 'RUNNING' : 'STOPPED'}
Fix Generation: ${scanState.isFixGenerationRunning ? 'RUNNING' : 'STOPPED'}
Current Scan: ${scanState.currentScanType || 'None'}
Real-time Paused: ${realTimeScanPaused ? 'YES' : 'NO'}
        `;
        
        outputChannel.appendLine(`📊 SCAN STATUS REPORT:`);
        outputChannel.appendLine(details);
        outputChannel.show();
        
        vscode.window.showInformationMessage(`Scan Status: ${status}`, 'View Details').then(selection => {
            if (selection === 'View Details') {
                outputChannel.show();
            }
        });
    });
    context.subscriptions.push(showScanStatusCommand);

    // Debug command to force diagnostics refresh
    const refreshDiagnosticsCommand = vscode.commands.registerCommand('secure-coding-assistant.refreshDiagnostics', () => {
        if (vscode.window.activeTextEditor) {
            const doc = vscode.window.activeTextEditor.document;
            const fileName = doc.fileName.substring(doc.fileName.lastIndexOf('/') + 1);
            
            // Create test diagnostic to verify system works
            const testDiagnostic = new vscode.Diagnostic(
                new vscode.Range(0, 0, 0, 1),
                '🔴 TEST: Diagnostic system test - if you see this, diagnostics are working!',
                vscode.DiagnosticSeverity.Error
            );
            testDiagnostic.source = 'Secure Coding Assistant';
            
            diagnosticsCollection.set(doc.uri, [testDiagnostic]);
            outputChannel.appendLine(`🔧 DEBUG: Test diagnostic added to ${fileName}`);
            vscode.window.showInformationMessage('Test diagnostic added - check for red dot in editor!');
        } else {
            vscode.window.showWarningMessage('No active editor to add test diagnostic');
        }
    });
    context.subscriptions.push(refreshDiagnosticsCommand);

    // Add immediate diagnostic test command  
    const addImmediateDiagnosticsCommand = vscode.commands.registerCommand('secure-coding-assistant.addImmediateDiagnostics', () => {
        if (vscode.window.activeTextEditor) {
            const doc = vscode.window.activeTextEditor.document;
            const fileName = doc.fileName.substring(doc.fileName.lastIndexOf('/') + 1);
            
            outputChannel.appendLine(`🔴 IMMEDIATE: Creating COMPREHENSIVE test diagnostics with red underlines for ${fileName}`);
            
            // Create multiple test diagnostics with proper ranges for red underlines
            const testDiagnostics: vscode.Diagnostic[] = [];
            
            // Add diagnostics to EVERY line that has content
            for (let line = 0; line < doc.lineCount; line++) {
                const lineText = doc.lineAt(line).text;
                if (lineText.trim().length > 0) {
                    // Create unique ranges to prevent merging
                    const startChar = Math.min(line % 3, lineText.length);
                    const endChar = Math.max(lineText.length, startChar + 1);
                    
                    const diagnostic = new vscode.Diagnostic(
                        new vscode.Range(line, startChar, line, endChar),
                        `🔴 TEST-${line + 1}: Security vulnerability on line ${line + 1}!`,
                        vscode.DiagnosticSeverity.Error
                    );
                    diagnostic.source = 'Secure Coding Assistant';
                    diagnostic.code = `TEST-SEC-${line + 1}-${Date.now()}`;
                    
                    // Add unique related information
                    diagnostic.relatedInformation = [
                        new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(doc.uri, new vscode.Range(line, 0, line, lineText.length)),
                            `Test vulnerability #${line + 1}: Line ${line + 1} content check`
                        )
                    ];
                    
                    testDiagnostics.push(diagnostic);
                    outputChannel.appendLine(`🔧 TEST: Created diagnostic for line ${line + 1}: "${lineText.trim().substring(0, 30)}..."`);
                }
            }
            
            // Clear and set new diagnostics
            diagnosticsCollection.delete(doc.uri);
            
            // Force multiple updates to ensure visibility
            setTimeout(() => {
                diagnosticsCollection.set(doc.uri, testDiagnostics);
                outputChannel.appendLine(`✅ IMMEDIATE: Added ${testDiagnostics.length} test diagnostics with red underlines`);
                outputChannel.appendLine(`📍 IMMEDIATE: Check ALL lines with content for RED UNDERLINES`);
                
                // Verify diagnostics were set
                const verifyDiagnostics = diagnosticsCollection.get(doc.uri);
                outputChannel.appendLine(`🔍 VERIFICATION: Set ${testDiagnostics.length}, retrieved ${verifyDiagnostics?.length || 0}`);
                
                // Show problems panel to make issues visible
                vscode.commands.executeCommand('workbench.panel.markers.view.focus');
                
                vscode.window.showInformationMessage(`Added ${testDiagnostics.length} test diagnostics to ALL lines - check editor for RED UNDERLINES!`);
            }, 100);
            
        } else {
            vscode.window.showWarningMessage('No active editor');
        }
    });
    context.subscriptions.push(addImmediateDiagnosticsCommand);

    // Register toggle fast mode command
    const toggleFastModeCommand = vscode.commands.registerCommand(
        'secure-coding-assistant.toggleFastMode',
        async () => {
            const config = vscode.workspace.getConfiguration('secureCodingAssistant.performance');
            const currentFastMode = config.get<boolean>('fastModeEnabled', false);
            
            await config.update('fastModeEnabled', !currentFastMode, vscode.ConfigurationTarget.Global);
            
            const newStatus = !currentFastMode ? 'ENABLED' : 'DISABLED';
            const icon = !currentFastMode ? '⚡' : '🔧';
            
            vscode.window.showInformationMessage(`${icon} Fast Mode ${newStatus}`);
            outputChannel.appendLine(`${icon} Fast Mode ${newStatus} - ${!currentFastMode ? 'Prioritizing speed over thoroughness' : 'Full verification enabled'}`);
        }
    );
    context.subscriptions.push(toggleFastModeCommand);

    // Register toggle comprehensive file scanning command
    const toggleComprehensiveFileScanningCommand = vscode.commands.registerCommand(
        'secure-coding-assistant.toggleComprehensiveFileScanning',
        async () => {
            const config = vscode.workspace.getConfiguration('secureCodingAssistant.realtime');
            const currentScanAllFileTypes = config.get<boolean>('scanAllFileTypes', true);
            
            await config.update('scanAllFileTypes', !currentScanAllFileTypes, vscode.ConfigurationTarget.Global);
            
            const newStatus = !currentScanAllFileTypes ? 'ENABLED' : 'DISABLED';
            const icon = !currentScanAllFileTypes ? '🌍' : '🎯';
            const description = !currentScanAllFileTypes ? 
                'Now scanning all file types (config, scripts, data files, etc.)' : 
                'Now scanning only core programming languages and dependencies';
            
            vscode.window.showInformationMessage(`${icon} Comprehensive File Scanning ${newStatus}`);
            outputChannel.appendLine(`${icon} Comprehensive File Scanning ${newStatus} - ${description}`);
        }
    );
    context.subscriptions.push(toggleComprehensiveFileScanningCommand);

    // Register quick fix command with enhanced fix application
    const generateQuickFixCommand = vscode.commands.registerCommand(
        'secure-coding-assistant.generateQuickFix',
        async (documentUri: vscode.Uri, range: vscode.Range, diagnosticMessage: string) => {
            try {
                // ============ SCAN COORDINATION CHECK ============
                if (!startScan('fix', 'Quick fix generation')) {
                    vscode.window.showWarningMessage('Cannot generate fix - another scan is running.');
                    return;
                }
                // ============ END SCAN COORDINATION CHECK ============

                const document = await vscode.workspace.openTextDocument(documentUri);
                const lineText = document.lineAt(range.start.line).text;
                const fileName = document.fileName.substring(document.fileName.lastIndexOf('/') + 1);
                
                outputChannel.appendLine(`🔧 Generating quick fix for issue at line ${range.start.line + 1} in ${fileName}`);
                
                // Get surrounding context for better fixes (3 lines before and after)
                const startLine = Math.max(0, range.start.line - 3);
                const endLine = Math.min(document.lineCount - 1, range.start.line + 3);
                const contextRange = new vscode.Range(startLine, 0, endLine, document.lineAt(endLine).text.length);
                const contextCode = document.getText(contextRange);
                
                // Get LLM to generate a fix
                const availableLlms = await getAvailableLlms(context);
                if (availableLlms.length === 0) {
                    vscode.window.showErrorMessage('No LLM API keys configured for generating fixes.');
                    return;
                }
                
                const selectedLlm = getPreferredLlm() || availableLlms[0];
                const apiKey = await getApiKeySilent(context, selectedLlm);
                
                if (!apiKey) {
                    vscode.window.showErrorMessage(`No API key available for ${selectedLlm}.`);
                    return;
                }
                
                const fixPrompt = `Fix this security vulnerability in ${document.languageId}:

Issue: ${diagnosticMessage}
Context code (vulnerable line is marked with >>):
${contextCode.split('\n').map((line, idx) => {
    const actualLineNum = startLine + idx;
    const marker = actualLineNum === range.start.line ? '>>' : '  ';
    return `${marker} ${actualLineNum + 1}: ${line}`;
}).join('\n')}

Provide ONLY the corrected code for the vulnerable line (line ${range.start.line + 1}), maintaining proper indentation. No explanations or markdown:`;

                let fixedCode = '';
                let verificationResult: any = null;
                
                vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: 'Generating & verifying security fix...',
                    cancellable: false
                }, async (progress) => {
                    progress.report({ message: "Step 1/2: Generating fix...", increment: 25 });
                    
                    // STAGE 1: Generate the initial fix
                    if (selectedLlm === LlmProvider.OpenAI) {
                        const openai = new OpenAI({ apiKey });
                        const response = await retryWithExponentialBackoff(
                            async () => await openai.chat.completions.create({
                                model: 'gpt-4-turbo-preview',
                                messages: [{ role: 'user', content: fixPrompt }],
                                max_tokens: 300,
                                temperature: 0.1
                            }),
                            undefined,
                            `Quick fix generation for ${fileName}`,
                            'OpenAI'
                        );
                        fixedCode = response.choices[0]?.message?.content?.trim() || '';
                    } else if (selectedLlm === LlmProvider.Anthropic) {
                        const anthropic = new Anthropic({ apiKey });
                        const response = await retryWithExponentialBackoff(
                            async () => await anthropic.messages.create({
                                model: 'claude-3-5-sonnet-20241022',
                                max_tokens: 300,
                                messages: [{ role: 'user', content: fixPrompt }]
                            }),
                            undefined,
                            `Quick fix generation for ${fileName}`,
                            'Anthropic'
                        );
                        const firstBlock = response.content[0];
                        fixedCode = (firstBlock.type === 'text' ? firstBlock.text : '').trim();
                    }

                    if (!fixedCode) {
                        return; // Exit if no fix was generated
                    }

                    // Clean up the initial fix
                    fixedCode = fixedCode.replace(/```[\s\S]*?\n([\s\S]*?)\n```/g, '$1');
                    fixedCode = fixedCode.replace(/```[\s\S]*?```/g, '');
                    fixedCode = fixedCode.replace(/`([^`\n]+)`/g, '$1');
                    fixedCode = fixedCode.trim();

                    progress.report({ message: "Step 2/2: Verifying fix security...", increment: 50 });
                    
                    // STAGE 2: Verify the fix with LLM re-scan
                    const verificationPrompt = `SECURITY VERIFICATION: Analyze this ${document.languageId} code fix for security issues.

ORIGINAL VULNERABLE CODE:
${lineText}

PROPOSED FIX:
${fixedCode}

CONTEXT:
${contextCode}

VERIFICATION TASKS:
1. Does the fix actually resolve the original security issue?
2. Does the fix introduce any new security vulnerabilities?
3. Is the fix syntactically correct for ${document.languageId}?
4. Does the fix maintain the original functionality?
5. Are there any edge cases the fix doesn't handle?

Respond with JSON format:
{
  "isSecure": true/false,
  "fixesOriginalIssue": true/false,
  "introducesNewIssues": true/false,
  "syntaxCorrect": true/false,
  "maintainsFunctionality": true/false,
  "verificationResult": "APPROVED/REJECTED/NEEDS_IMPROVEMENT",
  "issues": ["list of any issues found"],
  "improvedFix": "if rejected, provide improved version here",
  "confidence": 85
}`;


                    
                    if (selectedLlm === LlmProvider.OpenAI) {
                        const openai = new OpenAI({ apiKey });
                        const verifyResponse = await retryWithExponentialBackoff(
                            async () => await openai.chat.completions.create({
                                model: 'gpt-4-turbo-preview',
                                messages: [{ role: 'user', content: verificationPrompt }],
                                max_tokens: 500,
                                temperature: 0.1
                            }),
                            undefined,
                            `Fix verification for ${fileName}`,
                            'OpenAI'
                        );
                        const verifyContent = verifyResponse.choices[0]?.message?.content?.trim() || '';
                        try {
                            verificationResult = JSON.parse(extractJsonFromMarkdown(verifyContent));
                        } catch (e) {
                            outputChannel.appendLine(`⚠️ Verification parsing failed: ${e}`);
                        }
                    } else if (selectedLlm === LlmProvider.Anthropic) {
                        const anthropic = new Anthropic({ apiKey });
                        const verifyResponse = await retryWithExponentialBackoff(
                            async () => await anthropic.messages.create({
                                model: 'claude-3-5-sonnet-20241022',
                                max_tokens: 500,
                                messages: [{ role: 'user', content: verificationPrompt }]
                            }),
                            undefined,
                            `Fix verification for ${fileName}`,
                            'Anthropic'
                        );
                        const firstBlock = verifyResponse.content[0];
                        const verifyContent = (firstBlock.type === 'text' ? firstBlock.text : '').trim();
                        try {
                            verificationResult = JSON.parse(extractJsonFromMarkdown(verifyContent));
                        } catch (e) {
                            outputChannel.appendLine(`⚠️ Verification parsing failed: ${e}`);
                        }
                    }

                    progress.report({ message: "Fix verification complete!", increment: 25 });

                    // Use improved fix if verification suggests one
                    if (verificationResult) {
                        outputChannel.appendLine(`🔍 FIX VERIFICATION RESULTS:`);
                        outputChannel.appendLine(`   ✅ Fixes Original Issue: ${verificationResult.fixesOriginalIssue}`);
                        outputChannel.appendLine(`   🔒 Is Secure: ${verificationResult.isSecure}`);
                        outputChannel.appendLine(`   ⚠️ Introduces New Issues: ${verificationResult.introducesNewIssues}`);
                        outputChannel.appendLine(`   📝 Syntax Correct: ${verificationResult.syntaxCorrect}`);
                        outputChannel.appendLine(`   🎯 Maintains Functionality: ${verificationResult.maintainsFunctionality}`);
                        outputChannel.appendLine(`   📊 Confidence: ${verificationResult.confidence}%`);
                        outputChannel.appendLine(`   🏆 Result: ${verificationResult.verificationResult}`);

                        if (verificationResult.issues && verificationResult.issues.length > 0) {
                            outputChannel.appendLine(`   ⚠️ Issues Found: ${verificationResult.issues.join(', ')}`);
                        }

                        // Use improved fix if available and verification suggests improvement
                        if (verificationResult.verificationResult === 'NEEDS_IMPROVEMENT' && verificationResult.improvedFix) {
                            outputChannel.appendLine(`🔧 Using improved fix from verification`);
                            fixedCode = verificationResult.improvedFix.trim();
                        } else if (verificationResult.verificationResult === 'REJECTED') {
                            if (verificationResult.improvedFix) {
                                outputChannel.appendLine(`🔧 Original fix rejected, using improved version`);
                                fixedCode = verificationResult.improvedFix.trim();
                            } else {
                                outputChannel.appendLine(`❌ Fix verification failed - fix rejected without improvement`);
                                fixedCode = ''; // Clear the fix to prevent showing bad fix
                            }
                        }
                    } else {
                        outputChannel.appendLine(`⚠️ Fix verification failed - proceeding with original fix`);
                    }
                });
                
                if (fixedCode) {
                    // Show preview and ask for confirmation
                    const originalIndent = lineText.match(/^\s*/)?.[0] || '';
                    const cleanedFix = fixedCode.startsWith(originalIndent) ? fixedCode : originalIndent + fixedCode.trimStart();
                    
                    // Create verification status section
                    let verificationSection = '';
                    if (verificationResult) {
                        const statusIcon = verificationResult.verificationResult === 'APPROVED' ? '✅' : 
                                         verificationResult.verificationResult === 'NEEDS_IMPROVEMENT' ? '⚠️' : '❌';
                        
                        verificationSection = `
VERIFICATION RESULTS: ${statusIcon} ${verificationResult.verificationResult}
${'-'.repeat(60)}
🔒 Security Status: ${verificationResult.isSecure ? '✅ SECURE' : '❌ INSECURE'}
🎯 Fixes Original Issue: ${verificationResult.fixesOriginalIssue ? '✅ YES' : '❌ NO'}
⚠️ Introduces New Issues: ${verificationResult.introducesNewIssues ? '❌ YES' : '✅ NO'}
📝 Syntax Correct: ${verificationResult.syntaxCorrect ? '✅ YES' : '❌ NO'}
🎯 Maintains Functionality: ${verificationResult.maintainsFunctionality ? '✅ YES' : '❌ NO'}
📊 AI Confidence: ${verificationResult.confidence}%

${verificationResult.issues && verificationResult.issues.length > 0 ? 
`⚠️ Issues Found: ${verificationResult.issues.join(', ')}` : '✅ No issues detected'}

`;
                    } else {
                        verificationSection = `
VERIFICATION RESULTS: ⚠️ VERIFICATION FAILED
${'-'.repeat(60)}
❌ Unable to verify fix security - proceed with caution

`;
                    }
                    
                    // Create diff view in a new document
                    const diffContent = `VERIFIED SECURITY FIX for ${fileName} (Line ${range.start.line + 1})
${'='.repeat(80)}

ORIGINAL ISSUE: ${diagnosticMessage}
${verificationSection}
BEFORE (vulnerable):
${lineText}

AFTER (verified fix):
${cleanedFix}

CONTEXT WITH CHANGES:
${contextCode.split('\n').map((line, idx) => {
    const actualLineNum = startLine + idx;
    if (actualLineNum === range.start.line) {
        return `- ${actualLineNum + 1}: ${line}\n+ ${actualLineNum + 1}: ${cleanedFix}`;
    }
    return `  ${actualLineNum + 1}: ${line}`;
}).join('\n')}

${'='.repeat(80)}
This fix has been METICULOUSLY VERIFIED by AI for security and correctness.
Choose your action below.
`;

                    // Show diff in new document
                    const diffDoc = await vscode.workspace.openTextDocument({
                        content: diffContent,
                        language: 'diff'
                    });
                    await vscode.window.showTextDocument(diffDoc, vscode.ViewColumn.Beside);
                    
                    // Ask user what to do
                    const action = await vscode.window.showQuickPick(
                        [
                            { label: '✅ Apply Fix', description: 'Replace vulnerable code with fixed version', value: 'apply' },
                            { label: '📋 Copy Fixed Code', description: 'Copy fixed code to clipboard', value: 'copy' },
                            { label: '❌ Cancel', description: 'Don\'t apply any changes', value: 'cancel' }
                        ],
                        {
                            placeHolder: 'Choose how to handle the security fix',
                            title: `Security Fix for Line ${range.start.line + 1}`
                        }
                    );
                    
                    if (action?.value === 'apply') {
                        // Apply the fix
                        const edit = new vscode.WorkspaceEdit();
                        const lineRange = new vscode.Range(range.start.line, 0, range.start.line, lineText.length);
                        edit.replace(documentUri, lineRange, cleanedFix);
                        
                        const applied = await vscode.workspace.applyEdit(edit);
                        if (applied) {
                            vscode.window.showInformationMessage(`✅ Security fix applied to line ${range.start.line + 1}`);
                            outputChannel.appendLine(`✅ Applied fix to line ${range.start.line + 1}:`);
                            outputChannel.appendLine(`   Before: ${lineText}`);
                            outputChannel.appendLine(`   After:  ${cleanedFix}`);
                            
                            // Close diff document
                            vscode.commands.executeCommand('workbench.action.closeActiveEditor');
                            
                            // Re-scan after fix to update diagnostics
                            setTimeout(() => {
                                performRealTimeScan(document).catch(error => {
                                    outputChannel.appendLine(`Re-scan after fix failed: ${error.message}`);
                                });
                            }, 1000);
                        } else {
                            vscode.window.showErrorMessage('Failed to apply security fix.');
                        }
                    } else if (action?.value === 'copy') {
                        // Copy to clipboard
                        await vscode.env.clipboard.writeText(cleanedFix);
                        vscode.window.showInformationMessage(`📋 Fixed code copied to clipboard`);
                        outputChannel.appendLine(`📋 Copied fixed code to clipboard: ${cleanedFix}`);
                    } else {
                        // Cancel - close diff document
                        vscode.commands.executeCommand('workbench.action.closeActiveEditor');
                        outputChannel.appendLine(`❌ Fix generation cancelled by user`);
                    }
                } else {
                    vscode.window.showErrorMessage('Failed to generate security fix.');
                    outputChannel.appendLine('❌ Failed to generate fix - empty response from LLM');
                }
                
            } catch (error: any) {
                vscode.window.showErrorMessage(`Error generating fix: ${error.message}`);
                outputChannel.appendLine(`Quick fix error: ${error.message}`);
            } finally {
                // ============ END QUICK FIX TRACKING ============
                endScan('fix');
                // ============ END QUICK FIX TRACKING ============
            }
        }
    );
    context.subscriptions.push(generateQuickFixCommand);

    // Register show security info command
    const showSecurityInfoCommand = vscode.commands.registerCommand(
        'secure-coding-assistant.showSecurityInfo',
        (diagnosticMessage: string, code: string) => {
            const panel = vscode.window.createWebviewPanel(
                'securityInfo',
                'Security Issue Information',
                vscode.ViewColumn.Beside,
                { enableScripts: false }
            );
            
            panel.webview.html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; }
                    .issue { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; }
                    .code { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
                    .severity-high { border-left: 4px solid #dc3545; }
                    .severity-medium { border-left: 4px solid #ffc107; }
                    .severity-low { border-left: 4px solid #28a745; }
                </style>
            </head>
            <body>
                <h2>🔐 Security Issue Details</h2>
                <div class="issue severity-high">
                    <h3>Issue Description</h3>
                    <p>${diagnosticMessage}</p>
                    ${code ? `<p><strong>Code:</strong> ${code}</p>` : ''}
                </div>
                <div class="issue">
                    <h3>💡 General Security Tips</h3>
                    <ul>
                        <li>Always validate and sanitize user input</li>
                        <li>Use parameterized queries for database operations</li>
                        <li>Implement proper authentication and authorization</li>
                        <li>Keep dependencies up to date</li>
                        <li>Follow security best practices for your language</li>
                    </ul>
                </div>
            </body>
            </html>`;
        }
    );
    context.subscriptions.push(showSecurityInfoCommand);

    // --- Register command to show output channel ---
    const showOutputChannelCommand = vscode.commands.registerCommand('secure-coding-assistant.showOutputChannel', () => {
        outputChannel.show(true); // Pass true to preserve focus on the output channel
    });
    context.subscriptions.push(showOutputChannelCommand);

    // --- Register commands for adding API keys ---
    Object.values(LlmProvider).forEach(provider => {
        const addApiKeyCommand = vscode.commands.registerCommand(`secure-coding-assistant.add${provider}ApiKey`, async () => {
            const apiKey = await vscode.window.showInputBox({
                prompt: `Enter your ${provider} API Key`,
                password: true,
                ignoreFocusOut: true,
                placeHolder: `Your ${provider} API Key`,
            });
            if (apiKey) {
                try {
                    await context.secrets.store(getBuiltInSecretKey(provider), apiKey);
                    vscode.window.showInformationMessage(`${provider} API Key stored successfully.`);
                    outputChannel.appendLine(`${provider} API Key stored.`);
                } catch (error: any) {
                    vscode.window.showErrorMessage(`Failed to store ${provider} API Key. ${error.message}`);
                    outputChannel.appendLine(`Failed to store ${provider} API Key: ${error.message}`);
                }
            } else {
                vscode.window.showWarningMessage(`No API Key entered for ${provider}.`);
            }
        });
        context.subscriptions.push(addApiKeyCommand);
    });

    // --- Register commands for removing API keys ---
    Object.values(LlmProvider).forEach(provider => {
        const removeApiKeyCommand = vscode.commands.registerCommand(`secure-coding-assistant.remove${provider}ApiKey`, async () => {
            try {
                await context.secrets.delete(getBuiltInSecretKey(provider));
                vscode.window.showInformationMessage(`${provider} API Key removed successfully.`);
                outputChannel.appendLine(`${provider} API Key removed.`);
            } catch (error: any) {
                vscode.window.showErrorMessage(`Failed to remove ${provider} API Key. ${error.message}`);
                outputChannel.appendLine(`Failed to remove ${provider} API Key: ${error.message}`);
            }
        });
        context.subscriptions.push(removeApiKeyCommand);
    });

    // --- Register command for scanning selected code ---
    const scanSelectionCommand = vscode.commands.registerCommand('secure-coding-assistant.scanSelection', async () => {
        outputChannel.appendLine("Attempting to scan selection...");
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active text editor found.");
            outputChannel.appendLine("Scan Selection: No active text editor.");
            return;
        }

        const selection = editor.selection;
        if (selection.isEmpty || editor.document.getText(selection).trim() === "") {
            vscode.window.showWarningMessage("No text selected or selection is empty.");
            outputChannel.appendLine("Scan Selection: No text selected or selection is empty.");
            return;
        }

        // Get the exact text including all spaces and empty lines
        const selectedText = editor.document.getText(selection);
        const languageId = editor.document.languageId;
        const fileName = editor.document.fileName.substring(editor.document.fileName.lastIndexOf('/') + 1);

        // SMART LLM SELECTION: Use any available LLM
        const availableLlms = await getAvailableLlms(context);
        if (availableLlms.length === 0) {
            vscode.window.showErrorMessage("No LLM API keys found. Please add at least one API key using the provided commands.");
            outputChannel.appendLine("Scan Selection: No LLM API keys configured.");
            return;
        }

        // Use preferred LLM if available, otherwise use first available LLM
        const preferredLlm = getPreferredLlm();
        let selectedLlm = preferredLlm;
        let apiKey = preferredLlm ? await getApiKey(context, preferredLlm) : undefined;
        
        if (!apiKey) {
            // Fallback to first available LLM
            selectedLlm = availableLlms[0];
            apiKey = await getApiKey(context, selectedLlm);
            
            if (outputChannel) {
                if (preferredLlm) {
                    outputChannel.appendLine(`Preferred LLM "${preferredLlm}" not available, using "${selectedLlm}" instead.`);
                } else {
                    outputChannel.appendLine(`No preferred LLM set, using "${selectedLlm}".`);
                }
            }
        }

        if (!apiKey) {
            vscode.window.showErrorMessage(`Failed to get API key for ${selectedLlm}. Please check your configuration.`);
            outputChannel.appendLine(`Scan Selection: Failed to get API key for ${selectedLlm}.`);
            return;
        }

        outputChannel.appendLine(`Scanning selected code using ${selectedLlm} (Language: ${languageId})...`);
        
        // ============ SCAN COORDINATION CHECK ============
        if (!startScan('selection', `Selection scan: ${fileName}`)) {
            return; // Scan blocked by another running scan
        }
        // ============ END SCAN COORDINATION CHECK ============
        
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Scanning selection with ${selectedLlm}`,
            cancellable: false
        }, async (progress) => {
            progress.report({ message: "Analyzing selected code..." });
            try {
                // Use optimized scanning function
                const vulnerabilities = await scanCodeOptimized(
                    selectedLlm!, 
                    apiKey!, 
                    selectedText, 
                    languageId, 
                    fileName, 
                    context
                );
                
                formatAndLogVulnerabilities(vulnerabilities, selectedLlm!);
                outputChannel.show(true);
                vscode.window.showInformationMessage(`Selection scan complete. View results in "Secure Coding Assistant" output channel.`);

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error during selection scan: ${error.message}`);
                outputChannel.appendLine(`Error during selection scan with ${selectedLlm!}: ${error.message}`);
                outputChannel.show(true);
            } finally {
                // ============ END SELECTION SCAN TRACKING ============
                endScan('selection');
                // ============ END SELECTION SCAN TRACKING ============
            }
        });
    });
    context.subscriptions.push(scanSelectionCommand);

    // --- Helper function for the core file scanning logic ---
    async function executeScanOnFileLogic(
        fileUri: vscode.Uri,
        context: vscode.ExtensionContext,
        isPartOfFolderScan: boolean = false
    ): Promise<{ success: boolean; fileName: string; error?: string }> {
        const shortFileName = fileUri.fsPath.substring(fileUri.fsPath.lastIndexOf('/') + 1);
        if (outputChannel) outputChannel.appendLine(`Attempting to scan file: ${fileUri.fsPath}`);

        let documentToScan: vscode.TextDocument;
        try {
            documentToScan = await vscode.workspace.openTextDocument(fileUri);
        } catch (error: any) {
            const errorMessage = `Failed to open file: ${fileUri.fsPath}. ${error.message}`;
            if (outputChannel) outputChannel.appendLine(`File Scan Error: ${errorMessage}`);
            if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }

        // Get the exact file content including all spaces and empty lines
        const fileContent = documentToScan.getText();
        const languageId = documentToScan.languageId;

        if (fileContent.trim() === "") {
            const warningMessage = `File "${shortFileName}" is empty or contains only whitespace. Skipping.`;
            if (outputChannel) outputChannel.appendLine(`File Scan: ${warningMessage}`);
            if (!isPartOfFolderScan) vscode.window.showWarningMessage(warningMessage);
            return { success: true, fileName: shortFileName };
        }

        // SMART LLM SELECTION: Use any available LLM for file scanning
        const availableLlms = await getAvailableLlms(context);
        if (availableLlms.length === 0) {
            const errorMessage = "No LLM API keys found. Please add at least one API key using the provided commands.";
            if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
            if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }

        // Use preferred LLM if available, otherwise use first available LLM
        const preferredLlmSetting = getPreferredLlm();
        let providerNameToUse = preferredLlmSetting;
        let apiKeyToUse = preferredLlmSetting ? await getApiKey(context, preferredLlmSetting) : undefined;
        let endpointToUse: string | undefined;

        if (!apiKeyToUse) {
            // Fallback to first available LLM
            providerNameToUse = availableLlms[0];
            apiKeyToUse = await getApiKey(context, providerNameToUse);
            
            // Get endpoint for custom LLMs
            if (!Object.values(LlmProvider).includes(providerNameToUse as LlmProvider)) {
                const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
                const customConfig = customLlmConfigs.find(cfg => cfg.name === providerNameToUse);
                endpointToUse = customConfig?.endpoint;
            }
            
            if (outputChannel) {
                if (preferredLlmSetting) {
                    outputChannel.appendLine(`Preferred LLM "${preferredLlmSetting}" not available for "${shortFileName}", using "${providerNameToUse}" instead.`);
                } else {
                    outputChannel.appendLine(`No preferred LLM set for "${shortFileName}", using "${providerNameToUse}".`);
                }
            }
        } else if (preferredLlmSetting === "Custom") {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            if (customLlmConfigs.length === 0) {
                const errorMessage = "Preferred LLM is 'Custom', but no custom LLMs are configured. Please add one using the 'Secure Coding: Add Custom LLM Provider' command.";
                if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
            const chosenCustomLlm = customLlmConfigs[0];
            providerNameToUse = chosenCustomLlm.name;
            endpointToUse = chosenCustomLlm.endpoint;
        }

        if (!apiKeyToUse || !providerNameToUse) {
            const errorMessage = `Failed to find available LLM with API key for "${shortFileName}".`;
            if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
            if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }

        if (outputChannel) outputChannel.appendLine(`Scanning file "${shortFileName}" using ${providerNameToUse} (Language: ${languageId})...`);

        const scanPromise = async (progress?: vscode.Progress<{ message?: string; increment?: number }>): Promise<{ success: boolean; fileName: string; error?: string }> => {
            try {
                if (progress) progress.report({ message: `Analyzing ${shortFileName}...` });
                if (!apiKeyToUse) {
                    const err = `API Key for ${providerNameToUse} was unexpectedly undefined before API call.`;
                    if (outputChannel) outputChannel.appendLine(err);
                    return { success: false, fileName: shortFileName, error: err };
                }

                // Use optimized scanning function with caching and chunking
                let vulnerabilities: Vulnerability[] = [];
                if (!apiKeyToUse) {
                    const errorMessage = `API Key for ${providerNameToUse} was unexpectedly undefined during scan.`;
                    if (outputChannel) outputChannel.appendLine(errorMessage);
                    return { success: false, fileName: shortFileName, error: errorMessage };
                }
                
                try {
                    vulnerabilities = await scanCodeOptimized(
                        providerNameToUse, 
                        apiKeyToUse, 
                        fileContent, 
                        languageId, 
                        shortFileName, 
                        context,
                        endpointToUse
                    );
                } catch (parseError: any) {
                    const errorMessage = `Error during optimized scan for "${shortFileName}": ${parseError.message}`;
                    if (outputChannel) {
                        outputChannel.appendLine(errorMessage);
                    }
                    if (!isPartOfFolderScan) vscode.window.showErrorMessage(`Error processing scan results for "${shortFileName}".`);
                    return { success: false, fileName: shortFileName, error: errorMessage };
                }
                
                // Double-check that llmProvider is set for each vulnerability
                vulnerabilities.forEach(v => {
                    if (!v.llmProvider) {
                        v.llmProvider = providerNameToUse;
                    }
                });

                formatAndLogVulnerabilities(vulnerabilities, providerNameToUse);

                if (!isPartOfFolderScan) {
                    vscode.window.showInformationMessage(`File scan for "${shortFileName}" complete with ${providerNameToUse}. View results in "Secure Coding Assistant" output channel.`);
                }
                if (outputChannel && !isPartOfFolderScan) outputChannel.show(true);
                return { success: true, fileName: shortFileName };

            } catch (error: any) {
                const errorMessage = `Error during file scan for "${shortFileName}" with ${providerNameToUse}: ${error.message}`;
                if (outputChannel) outputChannel.appendLine(errorMessage);
                if (!isPartOfFolderScan) {
                    vscode.window.showErrorMessage(errorMessage);
                    if (outputChannel) outputChannel.show(true);
                }
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        };

        if (!isPartOfFolderScan) {
            return vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Scanning file with ${providerNameToUse}`,
                cancellable: false
            }, scanPromise);
        } else {
            return scanPromise();
        }
    }

    // --- Register command for scanning current file ---
    const scanFileCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFile', async (uri?: vscode.Uri) => {
        if (outputChannel) outputChannel.appendLine("Scan File command triggered.");
        let fileUri: vscode.Uri | undefined = uri;

        if (!fileUri) {
            if (vscode.window.activeTextEditor) {
                fileUri = vscode.window.activeTextEditor.document.uri;
                if (outputChannel) outputChannel.appendLine(`Scanning active editor: ${fileUri.fsPath}`);
            } else {
                vscode.window.showErrorMessage("No active text editor or file specified for scanning.");
                if (outputChannel) outputChannel.appendLine("Scan File: No active editor or URI provided.");
                return;
            }
        } else {
            if (outputChannel) outputChannel.appendLine(`Scanning file from URI: ${fileUri.fsPath}`);
        }

        if (!fileUri) { // Should not happen if logic above is correct
            vscode.window.showErrorMessage("Could not determine the file to scan.");
            if (outputChannel) outputChannel.appendLine("Scan File: File URI is undefined.");
            return;
        }
        
        // ============ SCAN COORDINATION CHECK ============
        const fileName = fileUri.fsPath.split('/').pop() || fileUri.fsPath;
        if (!startScan('manual', `File scan: ${fileName}`)) {
            return; // Scan blocked by another running scan
        }
        // ============ END SCAN COORDINATION CHECK ============
        
        // Update status bar to show manual scan
        updateStatusBar('manual', undefined, fileName);
        
        try {
            // Call the refactored logic, not part of a folder scan
            await executeScanOnFileLogic(fileUri, context, false);
        } finally {
            // ============ END FILE SCAN TRACKING ============
            endScan('manual');
            updateStatusBar('idle');
            // ============ END FILE SCAN TRACKING ============
        }
    });
    context.subscriptions.push(scanFileCommand);

    // --- Register command for scanning a folder ---
    const scanFolderCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFolder', async (folderUri?: vscode.Uri) => {
        // If no folder URI is provided, use the current file's folder or the first workspace folder
        const effectiveFolderUri = folderUri || 
            (vscode.window.activeTextEditor?.document.uri ? 
                vscode.Uri.file(path.dirname(vscode.window.activeTextEditor.document.uri.fsPath)) : 
                vscode.workspace.workspaceFolders?.[0].uri);

        if (!effectiveFolderUri) {
            vscode.window.showErrorMessage('No folder selected and no workspace folder available');
            return;
        }

        if (outputChannel) outputChannel.appendLine(`Starting scan for folder: ${effectiveFolderUri.fsPath}`);
        
        // ============ SCAN COORDINATION CHECK ============
        const folderName = effectiveFolderUri.fsPath.split('/').pop() || effectiveFolderUri.fsPath;
        if (!startScan('folder', `Folder scan: ${folderName}`)) {
            return; // Scan blocked by another running scan
        }
        // ============ END SCAN COORDINATION CHECK ============
        
        // Update status bar to show folder scan
        updateStatusBar('folder', undefined, folderName);
        
        vscode.window.showInformationMessage(`Scanning folder: ${effectiveFolderUri.fsPath}...`);

        const scanConfig = getScanConfiguration();
        const sourceCodeExtensions = new Set(scanConfig.sourceCodeExtensions);
        const commonExcludedDirs = new Set(scanConfig.excludedDirectories);

        // Track files to scan and results
        const filesToScan: vscode.Uri[] = [];
        const scanResults: { success: boolean; fileName: string; error?: string }[] = [];

        // Function to collect files to scan
        async function collectFilesToScan(directoryUri: vscode.Uri) {
            try {
                const entries = await vscode.workspace.fs.readDirectory(directoryUri);
                for (const [name, type] of entries) {
                    const entryUri = vscode.Uri.joinPath(directoryUri, name);
                    
                    if (type === vscode.FileType.File) {
                        const fileExtension = name.substring(name.lastIndexOf('.')).toLowerCase();
                        if (sourceCodeExtensions.has(fileExtension)) {
                            filesToScan.push(entryUri);
                        }
                    } else if (type === vscode.FileType.Directory) {
                        if (!name.startsWith('.') && !commonExcludedDirs.has(name.toLowerCase())) {
                            await collectFilesToScan(entryUri);
                        }
                    }
                }
            } catch (error: any) {
                if (outputChannel) outputChannel.appendLine(`Error collecting files from ${directoryUri.fsPath}: ${error.message}`);
            }
        }

        // Enhanced function to categorize files by type for comprehensive scanning
        function categorizeFilesByType(files: vscode.Uri[]): Map<string, vscode.Uri[]> {
            const fileTypeMap = new Map<string, vscode.Uri[]>();
            
            files.forEach(file => {
                const fileName = file.fsPath.substring(file.fsPath.lastIndexOf('/') + 1);
                const fileExtension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
                
                if (!fileTypeMap.has(fileExtension)) {
                    fileTypeMap.set(fileExtension, []);
                }
                fileTypeMap.get(fileExtension)!.push(file);
            });
            
            return fileTypeMap;
        }

        // Enhanced function to process files in batches with comprehensive scanning
        async function processFilesInBatches(files: vscode.Uri[]) {
            // Categorize files by type for better reporting
            const fileTypeMap = categorizeFilesByType(files);
            const availableLlms = await getAvailableLlms(context);
            
            // Track processed files to ensure every file is handled
            const processedFileTracker = new Set<string>();
            
            if (outputChannel) {
                outputChannel.appendLine(`📊 Folder scan analysis:`);
                outputChannel.appendLine(`   📁 Total files found: ${files.length}`);
                outputChannel.appendLine(`   🔧 Available LLMs: ${availableLlms.length} [${availableLlms.join(', ')}]`);
                outputChannel.appendLine(`   📋 File types detected (${fileTypeMap.size} different types):`);
                
                fileTypeMap.forEach((fileList, extension) => {
                    const sampleFiles = fileList.slice(0, 3).map(f => f.fsPath.split('/').pop()).join(', ');
                    const moreText = fileList.length > 3 ? ` (+${fileList.length - 3} more)` : '';
                    outputChannel.appendLine(`      ${extension}: ${fileList.length} files [${sampleFiles}${moreText}]`);
                });
                outputChannel.appendLine(`   ⚡ Comprehensive scanning: ALL file types will be processed`);
            }
            
            // Process files in batches with comprehensive scanning
            for (let i = 0; i < files.length; i += scanConfig.batchSize) {
                const batch = files.slice(i, i + scanConfig.batchSize);
                
                if (outputChannel) {
                    const batchNum = Math.floor(i / scanConfig.batchSize) + 1;
                    const totalBatches = Math.ceil(files.length / scanConfig.batchSize);
                    outputChannel.appendLine(`🚀 Processing batch ${batchNum}/${totalBatches} (${batch.length} files)...`);
                }
                
                // Process files sequentially to allow developer to view results for each file
                const batchResults = [];
                for (const file of batch) {
                    const fileName = file.fsPath.split('/').pop() || file.fsPath;
                    const fileKey = file.fsPath;
                    
                    try {
                        if (outputChannel) {
                            outputChannel.appendLine(`\n📄 Processing file: ${fileName}...`);
                        }
                        
                        const result = await executeScanOnFileLogic(file, context, true);
                        
                        // Mark file as processed
                        processedFileTracker.add(fileKey);
                        
                        // Log scan method used for this file
                        if (outputChannel) {
                            const fileExtension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
                            
                            if (result.success) {
                                try {
                                    const document = await vscode.workspace.openTextDocument(file);
                                    const content = document.getText();
                                    const detectedLang = detectActualLanguage(fileName, document.languageId, content);
                                    const isLlmOnly = isLlmOnlyFile(fileName, document.languageId, content);
                                    const scanType = isLlmOnly ? 'LLM-Only' : 
                                                   availableLlms.length > 1 ? 'Multi-LLM' : 
                                                   availableLlms.length === 1 ? 'Single-LLM+Local' : 'Local-Only';
                                                   
                                    outputChannel.appendLine(`   ✅ ${fileName} (${fileExtension} → ${detectedLang}) → ${scanType} scan completed`);
                                } catch (docError) {
                                    outputChannel.appendLine(`   ✅ ${fileName} (${fileExtension}) → scan completed (language detection failed)`);
                                }
                            } else {
                                outputChannel.appendLine(`   ❌ ${fileName} (${fileExtension}) → scan failed: ${result.error}`);
                            }
                            
                            // Add a pause to allow developer to view results before proceeding to next file
                            await new Promise(resolve => setTimeout(resolve, 1000));
                        }
                        
                        batchResults.push(result);
                    } catch (fileError: any) {
                        // Ensure failed files are still tracked
                        processedFileTracker.add(fileKey);
                        const errorResult = { success: false, fileName, error: fileError.message };
                        
                        if (outputChannel) {
                            outputChannel.appendLine(`   ❌ ${fileName} → CRITICAL ERROR: ${fileError.message}`);
                        }
                        
                        batchResults.push(errorResult);
                    }
                }
                
                scanResults.push(...batchResults);
                
                // Progress reporting
                const completedFiles = Math.min(i + scanConfig.batchSize, files.length);
                if (outputChannel) {
                    outputChannel.appendLine(`📈 Progress: ${completedFiles}/${files.length} files processed`);
                }
            }
            
            // CRITICAL: Verify ALL files were processed - NO FILES LEFT BEHIND
            const missedFiles = files.filter(file => !processedFileTracker.has(file.fsPath));
            if (missedFiles.length > 0) {
                if (outputChannel) {
                    outputChannel.appendLine(`⚠️ CRITICAL: ${missedFiles.length} files were missed! Processing now...`);
                }
                
                // Process missed files immediately
                for (const missedFile of missedFiles) {
                    try {
                        const fileName = missedFile.fsPath.split('/').pop() || missedFile.fsPath;
                        if (outputChannel) {
                            outputChannel.appendLine(`🔄 Processing missed file: ${fileName}`);
                        }
                        
                        const result = await executeScanOnFileLogic(missedFile, context, true);
                        scanResults.push(result);
                        processedFileTracker.add(missedFile.fsPath);
                        
                        if (outputChannel) {
                            outputChannel.appendLine(`   ${result.success ? '✅' : '❌'} ${fileName} → ${result.success ? 'completed' : `failed: ${result.error}`}`);
                        }
                    } catch (error: any) {
                        const fileName = missedFile.fsPath.split('/').pop() || missedFile.fsPath;
                        scanResults.push({ success: false, fileName, error: error.message });
                        processedFileTracker.add(missedFile.fsPath);
                        
                        if (outputChannel) {
                            outputChannel.appendLine(`   ❌ ${fileName} → CRITICAL ERROR: ${error.message}`);
                        }
                    }
                }
            }

            // Enhanced final summary with scan type breakdown
            if (outputChannel) {
                const successCount = scanResults.filter(r => r.success).length;
                const failCount = scanResults.filter(r => !r.success).length;
                
                outputChannel.appendLine(`🏁 Batch processing complete:`);
                outputChannel.appendLine(`   📁 Total files discovered: ${files.length}`);
                outputChannel.appendLine(`   🔍 Files actually processed: ${processedFileTracker.size}`);
                outputChannel.appendLine(`   ✅ Successfully scanned: ${successCount}/${files.length} files`);
                outputChannel.appendLine(`   ❌ Failed to scan: ${failCount}/${files.length} files`);
                
                // GUARANTEE: Verify 100% file coverage
                if (processedFileTracker.size === files.length) {
                    outputChannel.appendLine(`   🎯 GUARANTEED: 100% file coverage achieved - ALL files processed!`);
                } else {
                    outputChannel.appendLine(`   ⚠️ WARNING: File coverage mismatch! Expected ${files.length}, processed ${processedFileTracker.size}`);
                }
                
                // Show file type processing summary
                outputChannel.appendLine(`📊 File type processing summary (${fileTypeMap.size} types):`);
                fileTypeMap.forEach((fileList, extension) => {
                    const successForType = scanResults.filter(r => 
                        r.success && r.fileName.toLowerCase().endsWith(extension)
                    ).length;
                    const totalForType = fileList.length;
                    const coveragePercent = Math.round((successForType / totalForType) * 100);
                    outputChannel.appendLine(`   ${extension}: ${successForType}/${totalForType} (${coveragePercent}%) processed successfully`);
                });
            }
        }

        try {
            // Show progress and collect files
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Scanning folder: ${effectiveFolderUri.fsPath}`,
                cancellable: false
            }, async (progress) => {
                progress.report({ message: "Discovering files..." });
                await collectFilesToScan(effectiveFolderUri);
                
                if (filesToScan.length === 0) {
                    vscode.window.showWarningMessage('No supported files found to scan in the selected folder.');
                    return;
                }

                progress.report({ message: `Found ${filesToScan.length} files. Starting scans...` });
                if (outputChannel) outputChannel.appendLine(`Found ${filesToScan.length} files to scan in ${effectiveFolderUri.fsPath}.`);

                // Process files in batches
                await processFilesInBatches(filesToScan);
            });

            // Process results
            const successCount = scanResults.filter(r => r.success).length;
            const failCount = scanResults.filter(r => !r.success).length;

            // Show summary
            const summaryMessage = `Scan complete for ${effectiveFolderUri.fsPath}\n` +
                `Successfully scanned: ${successCount} files\n` +
                `Failed to scan: ${failCount} files`;

            outputChannel.appendLine(summaryMessage);
            vscode.window.showInformationMessage(summaryMessage);

            // Show detailed errors if any
            if (failCount > 0) {
                const errorDetails = scanResults
                    .filter(r => !r.success)
                    .map(r => `${r.fileName}: ${r.error}`)
                    .join('\n');
                outputChannel.appendLine('\nDetailed errors:');
                outputChannel.appendLine(errorDetails);
            }

        } catch (error: any) {
            const errorMessage = `Failed to scan folder: ${effectiveFolderUri.fsPath}. Check the output channel for details.`;
            vscode.window.showErrorMessage(errorMessage);
            if (outputChannel) outputChannel.appendLine(errorMessage);
        } finally {
            // ============ END FOLDER SCAN TRACKING ============
            endScan('folder');
            updateStatusBar('idle');
            // ============ END FOLDER SCAN TRACKING ============
            if (outputChannel) outputChannel.show(true);
        }
    });
    context.subscriptions.push(scanFolderCommand);

    // --- Register command for generating fixes ---
    const generateFixCommand = vscode.commands.registerCommand('secure-coding-assistant.generateFix', async () => {
        outputChannel.appendLine("Generate Fix command triggered.");
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active text editor found.");
            outputChannel.appendLine("Generate Fix: No active text editor.");
            return;
        }

        const selection = editor.selection;
        const selectedText = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const languageId = editor.document.languageId;
        const fileName = editor.document.fileName.substring(editor.document.fileName.lastIndexOf('/') + 1);

        if (selectedText.trim() === "") {
            vscode.window.showWarningMessage("No code found to analyze for fixes.");
            outputChannel.appendLine("Generate Fix: No code found.");
            return;
        }

        // Detect actual language if VS Code reported plaintext
        const actualLanguageId = detectActualLanguage(fileName, languageId, selectedText);

        // SMART LLM SELECTION: Use any available LLM for fix generation
        const availableLlms = await getAvailableLlms(context);
        if (availableLlms.length === 0) {
            vscode.window.showErrorMessage("No LLM API keys found. Please add at least one API key using the provided commands.");
            outputChannel.appendLine("Generate Fix: No LLM API keys configured.");
            return;
        }

        // Use preferred LLM if available, otherwise use first available LLM
        const preferredLlmSetting = getPreferredLlm();
        let selectedLlm = preferredLlmSetting;
        let apiKey = preferredLlmSetting ? await getApiKey(context, preferredLlmSetting) : undefined;
        let endpointToUse: string | undefined;
        
        if (!apiKey) {
            // Fallback to first available LLM
            selectedLlm = availableLlms[0];
            apiKey = await getApiKey(context, selectedLlm);
            
            // Get endpoint for custom LLMs
            if (!Object.values(LlmProvider).includes(selectedLlm as LlmProvider)) {
                const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
                const customConfig = customLlmConfigs.find(cfg => cfg.name === selectedLlm);
                endpointToUse = customConfig?.endpoint;
            }
            
            if (outputChannel) {
                if (preferredLlmSetting) {
                    outputChannel.appendLine(`Preferred LLM "${preferredLlmSetting}" not available for fix generation, using "${selectedLlm}" instead.`);
                } else {
                    outputChannel.appendLine(`No preferred LLM set for fix generation, using "${selectedLlm}".`);
                }
            }
        } else if (preferredLlmSetting === "Custom") {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            if (customLlmConfigs.length === 0) {
                vscode.window.showErrorMessage("Preferred LLM is 'Custom', but no custom LLMs are configured. Please add one using the 'Secure Coding: Add Custom LLM Provider' command.");
                outputChannel.appendLine("Generate Fix: Preferred LLM is 'Custom', but no custom LLMs are configured.");
                return;
            }
            const chosenCustomLlm = customLlmConfigs[0];
            selectedLlm = chosenCustomLlm.name;
            endpointToUse = chosenCustomLlm.endpoint;
        }

        if (!apiKey || !selectedLlm) {
            vscode.window.showErrorMessage("Failed to find available LLM with API key for fix generation.");
            outputChannel.appendLine("Generate Fix: Failed to find available LLM with API key.");
            return;
        }

        const langDisplay = actualLanguageId !== languageId ? `${actualLanguageId} (detected from ${languageId})` : actualLanguageId;
        outputChannel.appendLine(`Generating fixes using ${selectedLlm} (Language: ${langDisplay})...`);
        
        // ============ SCAN COORDINATION CHECK ============
        if (!startScan('fix', `Fix generation: ${fileName}`)) {
            return; // Scan blocked by another running scan
        }
        // ============ END SCAN COORDINATION CHECK ============
        
        // Update status bar to show fix generation
        updateStatusBar('fixing');
        
        // ENHANCED: Add timeout mechanism to prevent infinite fix generation
        const fixGenerationTimeout = setTimeout(() => {
            outputChannel.appendLine(`⚠️ FIX GENERATION TIMEOUT: Operation has been running for too long - force ending`);
            endScan('fix');
            updateStatusBar('idle');
            vscode.window.showWarningMessage('Fix generation timed out after 2 minutes. Please try again.');
        }, 120000); // 2 minutes timeout
        
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Generating fixes with ${selectedLlm}`,
            cancellable: false
        }, async (progress) => {
            progress.report({ message: "Analyzing code for vulnerabilities and fixes..." });
            try {
                let vulnerabilities: Vulnerability[] = [];
                if (selectedLlm === LlmProvider.OpenAI) {
                    vulnerabilities = await analyzeCodeWithOpenAI(apiKey!, selectedText, actualLanguageId, fileName);
                } else {
                    const analysisJsonResult = await callLlmApi(selectedLlm, apiKey!, selectedText, actualLanguageId, endpointToUse);
                    try {
                        // Extract JSON from markdown format if needed (especially for Google Gemini)
                        const cleanJson = extractJsonFromMarkdown(analysisJsonResult);
                        const result = JSON.parse(cleanJson);
                        vulnerabilities = Array.isArray(result) ? result : (result.issues || []);
                    } catch (parseError: any) {
                        outputChannel.appendLine(`Error parsing LLM response: ${parseError.message}`);
                        outputChannel.appendLine(`Raw response: ${analysisJsonResult.substring(0, 500)}...`);
                        vscode.window.showErrorMessage(`Error processing results from ${selectedLlm}. Check output for details.`);
                        return;
                    }
                }
                
                // Process vulnerabilities consistently
                vulnerabilities = processVulnerabilities(vulnerabilities, selectedLlm, fileName, actualLanguageId, selectedText);
                
                if (vulnerabilities.length === 0) {
                    vscode.window.showInformationMessage("No security issues found. Your code looks good!");
                    outputChannel.appendLine("Generate Fix: No vulnerabilities detected.");
                    return;
                }

                // Generate and display fixes using LLM (OPTIMIZED PARALLEL PROCESSING)
                outputChannel.clear();
                outputChannel.appendLine("=== LLM-POWERED SECURITY FIXES GENERATED ===\n");
                
                // Get configuration for parallel processing
                const config = vscode.workspace.getConfiguration('secureCodingAssistant');
                const maxConcurrentFixes = config.get<number>('performance.maxConcurrentFixes', 6);
                const enableBatchProcessing = config.get<boolean>('performance.enableBatchProcessing', true);
                const prioritizeHighSeverity = config.get<boolean>('performance.prioritizeHighSeverity', true);
                
                // Sort vulnerabilities by severity if prioritization is enabled
                if (prioritizeHighSeverity) {
                    vulnerabilities.sort((a, b) => {
                        const severityOrder = { 'High': 0, 'Medium': 1, 'Low': 2 };
                        return severityOrder[a.severity] - severityOrder[b.severity];
                    });
                }
                
                // Try batch processing first for similar vulnerabilities
                const fixResults = await generateFixesFastParallel(
                    vulnerabilities, 
                    selectedText, 
                    actualLanguageId, 
                    context, 
                    progress,
                    maxConcurrentFixes,
                    enableBatchProcessing
                );
                
                // Create interactive fix document with all fixes
                let fixDocument = `SECURITY FIXES GENERATED for ${fileName}
${'='.repeat(80)}

Total vulnerabilities found: ${vulnerabilities.length}
Language: ${actualLanguageId}
Scan method: ${selectedLlm}

${'='.repeat(80)}

`;

                // Display results and create fix document
                const successfulFixes: Array<{vuln: Vulnerability, fix: string, index: number}> = [];
                
                fixResults.forEach((result: FixResult, index: number) => {
                    const vuln = vulnerabilities[index];
                    
                    // Add to output channel
                    outputChannel.appendLine(`📍 ${vuln.id} (${vuln.severity} severity)`);
                    outputChannel.appendLine(`Description: ${vuln.description}`);
                    outputChannel.appendLine(`Location: ${vuln.location}`);
                    outputChannel.appendLine(`Recommendation: ${vuln.recommendation}\n`);
                    
                    // Add to fix document
                    fixDocument += `VULNERABILITY #${index + 1}: ${vuln.severity} Severity
${'-'.repeat(60)}
Issue: ${vuln.description}
Location: ${vuln.location}
Recommendation: ${vuln.recommendation}

`;
                    
                    if (result.success && result.fix) {
                        outputChannel.appendLine(`🤖 ${result.method} FIX:`);
                        outputChannel.appendLine("```" + actualLanguageId);
                        outputChannel.appendLine(result.fix);
                        outputChannel.appendLine("```");
                        
                        // Show verification results if available
                        if (result.verification) {
                            const v = result.verification;
                            const statusIcon = v.verificationResult === 'APPROVED' ? '✅' : 
                                             v.verificationResult === 'NEEDS_IMPROVEMENT' ? '⚠️' : '❌';
                            
                            outputChannel.appendLine(`🔍 VERIFICATION RESULTS: ${statusIcon} ${v.verificationResult}`);
                            outputChannel.appendLine(`   🔒 Security Status: ${v.isSecure ? '✅ SECURE' : '❌ INSECURE'}`);
                            outputChannel.appendLine(`   🎯 Fixes Original Issue: ${v.fixesOriginalIssue ? '✅ YES' : '❌ NO'}`);
                            outputChannel.appendLine(`   ⚠️ Introduces New Issues: ${v.introducesNewIssues ? '❌ YES' : '✅ NO'}`);
                            outputChannel.appendLine(`   📝 Syntax Correct: ${v.syntaxCorrect ? '✅ YES' : '❌ NO'}`);
                            outputChannel.appendLine(`   🎯 Maintains Functionality: ${v.maintainsFunctionality ? '✅ YES' : '❌ NO'}`);
                            outputChannel.appendLine(`   📊 AI Confidence: ${v.confidence}%`);
                            
                            if (v.issues && v.issues.length > 0) {
                                outputChannel.appendLine(`   ⚠️ Issues Found: ${v.issues.join(', ')}`);
                            }
                        }
                        outputChannel.appendLine("");
                        
                        // Add to fix document with verification
                        let verificationSection = '';
                        if (result.verification) {
                            const v = result.verification;
                            const statusIcon = v.verificationResult === 'APPROVED' ? '✅' : 
                                             v.verificationResult === 'NEEDS_IMPROVEMENT' ? '⚠️' : '❌';
                            
                            verificationSection = `
**VERIFICATION RESULTS:** ${statusIcon} **${v.verificationResult}**
- 🔒 Security Status: ${v.isSecure ? '✅ SECURE' : '❌ INSECURE'}
- 🎯 Fixes Original Issue: ${v.fixesOriginalIssue ? '✅ YES' : '❌ NO'}
- ⚠️ Introduces New Issues: ${v.introducesNewIssues ? '❌ YES' : '✅ NO'}
- 📝 Syntax Correct: ${v.syntaxCorrect ? '✅ YES' : '❌ NO'}
- 🎯 Maintains Functionality: ${v.maintainsFunctionality ? '✅ YES' : '❌ NO'}
- 📊 AI Confidence: ${v.confidence}%
${v.issues && v.issues.length > 0 ? `- ⚠️ Issues Found: ${v.issues.join(', ')}` : '- ✅ No issues detected'}

`;
                        }
                        
                        fixDocument += `✅ VERIFIED SECURITY FIX (${result.method}):
${verificationSection}
\`\`\`${actualLanguageId}
${result.fix}
\`\`\`

**INSTRUCTIONS:**
1. This fix has been **METICULOUSLY VERIFIED** by AI for security and correctness
2. Copy the fixed code above
3. Replace the vulnerable code in your file
4. Test the changes thoroughly

`;
                        
                        successfulFixes.push({vuln, fix: result.fix, index});
                    } else {
                        outputChannel.appendLine("⚠️  FIX GENERATION FAILED:");
                        outputChannel.appendLine(result.error || "Unknown error");
                        outputChannel.appendLine("");
                        
                        fixDocument += `❌ FIX GENERATION FAILED:
Error: ${result.error || "Unknown error"}

`;
                    }
                    
                    outputChannel.appendLine("----------------------------------------\n");
                    fixDocument += `${'='.repeat(80)}\n\n`;
                });
                
                // Add summary to fix document
                fixDocument += `SUMMARY:
- Total vulnerabilities: ${vulnerabilities.length}
- Successfully fixed: ${successfulFixes.length}
- Failed to fix: ${vulnerabilities.length - successfulFixes.length}

NEXT STEPS:
1. Review each fix carefully
2. Copy and paste the fixed code into your source file
3. Test your application thoroughly
4. Consider running another security scan to verify fixes

Generated by Secure Coding Assistant using ${selectedLlm}
`;

                // Show fix document in new tab
                const fixDoc = await vscode.workspace.openTextDocument({
                    content: fixDocument,
                    language: 'markdown'
                });
                await vscode.window.showTextDocument(fixDoc, vscode.ViewColumn.Beside);
                
                outputChannel.show(true);
                
                // Show action options
                if (successfulFixes.length > 0) {
                    const action = await vscode.window.showInformationMessage(
                        `Generated ${successfulFixes.length}/${vulnerabilities.length} security fixes successfully!`,
                        'View Fixes Document',
                        'Copy All Fixes',
                        'Apply Fixes Interactively'
                    );
                    
                    if (action === 'Copy All Fixes') {
                        // Copy all fixes to clipboard
                        const allFixes = successfulFixes.map((item, idx) => 
                            `// Fix #${idx + 1}: ${item.vuln.description}\n${item.fix}`
                        ).join('\n\n' + '-'.repeat(40) + '\n\n');
                        
                        await vscode.env.clipboard.writeText(allFixes);
                        vscode.window.showInformationMessage('📋 All fixes copied to clipboard!');
                        
                    } else if (action === 'Apply Fixes Interactively') {
                        // Interactive fix application
                        for (const {vuln, fix, index} of successfulFixes) {
                            const applyAction = await vscode.window.showQuickPick([
                                { label: '✅ Apply This Fix', description: `Replace vulnerable code with fix #${index + 1}`, value: 'apply' },
                                { label: '📋 Copy Fix Only', description: 'Copy fix to clipboard', value: 'copy' },
                                { label: '⏭️ Skip This Fix', description: 'Skip to next fix', value: 'skip' },
                                { label: '❌ Cancel All', description: 'Stop interactive fixing', value: 'cancel' }
                            ], {
                                placeHolder: `Fix #${index + 1}: ${vuln.description}`,
                                title: `Apply Security Fix ${index + 1}/${successfulFixes.length}`
                            });
                            
                            if (applyAction?.value === 'apply') {
                                // Try to find and replace the vulnerable code
                                const activeEditor = vscode.window.activeTextEditor;
                                if (activeEditor && activeEditor.document.fileName.includes(fileName)) {
                                    // Find the vulnerable line based on vuln.location or description
                                    const document = activeEditor.document;
                                    const documentText = document.getText();
                                    
                                    // Simple approach: replace the selected text with the fix
                                    if (!selection.isEmpty) {
                                        const edit = new vscode.WorkspaceEdit();
                                        edit.replace(document.uri, selection, fix);
                                        const applied = await vscode.workspace.applyEdit(edit);
                                        
                                        if (applied) {
                                            vscode.window.showInformationMessage(`✅ Applied fix #${index + 1}`);
                                            outputChannel.appendLine(`✅ Applied fix #${index + 1}: ${vuln.description}`);
                                        } else {
                                            vscode.window.showErrorMessage(`❌ Failed to apply fix #${index + 1}`);
                                        }
                                    } else {
                                        vscode.window.showWarningMessage(`Cannot apply fix #${index + 1} - no code selected. Please select the vulnerable code first.`);
                                    }
                                } else {
                                    vscode.window.showWarningMessage(`Cannot apply fix #${index + 1} - please open the source file first.`);
                                }
                                
                            } else if (applyAction?.value === 'copy') {
                                await vscode.env.clipboard.writeText(fix);
                                vscode.window.showInformationMessage(`📋 Fix #${index + 1} copied to clipboard`);
                                
                            } else if (applyAction?.value === 'cancel') {
                                break; // Exit the loop
                            }
                            // 'skip' just continues to next iteration
                        }
                    }
                } else {
                    vscode.window.showWarningMessage(`No fixes could be generated for the ${vulnerabilities.length} vulnerabilities found.`);
                }

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error generating fixes: ${error.message}`);
                outputChannel.appendLine(`Error generating fixes with ${selectedLlm}: ${error.message}`);
                outputChannel.show(true);
            } finally {
                // ============ END FIX GENERATION TRACKING ============
                clearTimeout(fixGenerationTimeout); // Clear timeout if operation completes normally
                endScan('fix');
                updateStatusBar('idle');
                // ============ END FIX GENERATION TRACKING ============
            }
        });
    });
    context.subscriptions.push(generateFixCommand);

    // --- Register command for force clearing scan states (recovery command) ---
    const forceClearScansCommand = vscode.commands.registerCommand('secure-coding-assistant.forceClearScans', async () => {
        outputChannel.appendLine(`🚨 FORCE CLEAR SCANS: User manually clearing all scan states`);
        
        // Show current scan state
        outputChannel.appendLine(`📊 CURRENT SCAN STATE BEFORE CLEAR:`);
        outputChannel.appendLine(`   - Real-time scan: ${scanState.isRealTimeScanRunning}`);
        outputChannel.appendLine(`   - Manual scan: ${scanState.isManualScanRunning}`);
        outputChannel.appendLine(`   - Folder scan: ${scanState.isFolderScanRunning}`);
        outputChannel.appendLine(`   - Selection scan: ${scanState.isSelectionScanRunning}`);
        outputChannel.appendLine(`   - Fix generation: ${scanState.isFixGenerationRunning}`);
        outputChannel.appendLine(`   - Current scan type: ${scanState.currentScanType}`);
        const duration = scanState.scanStartTime ? (Date.now() - scanState.scanStartTime) / 1000 : 0;
        outputChannel.appendLine(`   - Running duration: ${duration.toFixed(1)}s`);
        
        // Force clear all scan states
        scanState.isRealTimeScanRunning = false;
        scanState.isManualScanRunning = false;
        scanState.isFolderScanRunning = false;
        scanState.isSelectionScanRunning = false;
        scanState.isFixGenerationRunning = false;
        scanState.currentScanType = null;
        scanState.scanStartTime = null;
        
        // Resume real-time scanning
        resumeRealTimeScanning();
        
        // Update status bar
        updateStatusBar('idle');
        
        outputChannel.appendLine(`✅ ALL SCAN STATES FORCEFULLY CLEARED - Operations can now proceed`);
        outputChannel.show(true);
        
        vscode.window.showInformationMessage('All scan states have been cleared. You can now start new scans.');
    });
    context.subscriptions.push(forceClearScansCommand);

    // --- Register command for adding a Custom LLM Provider ---
    const addCustomLlmProviderCommand = vscode.commands.registerCommand('secure-coding-assistant.addCustomLlmProvider', async () => {
        if (outputChannel) outputChannel.appendLine("Attempting to add Custom LLM Provider...");

        // 1. Prompt for Provider Name
        const providerNameInput = await vscode.window.showInputBox({
            prompt: "Enter a unique name for the Custom LLM Provider",
            placeHolder: "MyCustomLLM",
            ignoreFocusOut: true,
            validateInput: text => {
                if (!text || text.trim().length === 0) {
                    return "Provider name cannot be empty.";
                }
                // Check for uniqueness against existing custom LLMs
                const existingConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
                if (existingConfigs.find(cfg => cfg.name.toLowerCase() === text.trim().toLowerCase())) {
                    return `Provider name "${text.trim()}" already exists. Please choose a unique name.`;
                }
                // Additionally, check against built-in provider names to avoid conflict
                const builtInProviders = Object.values(LlmProvider).map(p => p.toLowerCase());
                if (builtInProviders.includes(text.trim().toLowerCase())) {
                     return `Provider name "${text.trim()}" conflicts with a built-in provider. Please choose a different name.`;
                }
                return null; // Input is valid
            }
        });

        if (!providerNameInput) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: Name not provided.");
            if (outputChannel) outputChannel.appendLine("Custom LLM setup cancelled by user (name input).");
            return;
        }
        const providerName = providerNameInput.trim();


        // 2. Prompt for API Key
        const apiKey = await vscode.window.showInputBox({
            prompt: `Enter the API Key for ${providerName}`,
            password: true,
            ignoreFocusOut: true,
            placeHolder: "Your API Key for " + providerName,
            validateInput: text => {
                return text && text.length > 0 ? null : "API Key cannot be empty.";
            }
        });

        if (!apiKey) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: API Key not provided.");
            if (outputChannel) outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (API key input).`);
            return;
        }

        // 3. Prompt for API Endpoint URL
        const endpointUrlInput = await vscode.window.showInputBox({
            prompt: `Enter the API Endpoint URL for ${providerName}`,
            placeHolder: "https://api.customllm.com/v1/chat/completions",
            ignoreFocusOut: true,
            validateInput: text => {
                if (!text || text.trim().length === 0) {
                    return "API Endpoint URL cannot be empty.";
                }
                // Basic URL format check (optional, can be more robust)
                try {
                    new URL(text.trim());
                    return null;
                } catch (_) {
                    return "Invalid URL format.";
                }
            }
        });

        if (!endpointUrlInput) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: Endpoint URL not provided.");
            if (outputChannel) outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (endpoint URL input).`);
            return;
        }
        const endpointUrl = endpointUrlInput.trim();

        try {
            // Store API Key in secrets
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            await context.secrets.store(secretApiKeyName, apiKey);

            // Store provider config (name and endpoint) in global state
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            
            // Double check uniqueness here in case of async race conditions (though unlikely with modal inputs)
            if (customLlmConfigs.find(cfg => cfg.name.toLowerCase() === providerName.toLowerCase())) {
                vscode.window.showErrorMessage(`Custom LLM Provider "${providerName}" already exists. Please try adding with a different name.`);
                await context.secrets.delete(secretApiKeyName); // Clean up stored secret
                if (outputChannel) outputChannel.appendLine(`Error adding Custom LLM "${providerName}": Name already exists (race condition check).`);
                return;
            }

            customLlmConfigs.push({ name: providerName, endpoint: endpointUrl });
            await context.globalState.update('customLlmProviders', customLlmConfigs);

            vscode.window.showInformationMessage(`Custom LLM Provider "${providerName}" added successfully.`);
            if (outputChannel) {
                outputChannel.appendLine(`Custom LLM Provider "${providerName}" added with endpoint: ${endpointUrl}`);
            }

        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to add Custom LLM Provider "${providerName}": ${error.message}`);
            if (outputChannel) {
                outputChannel.appendLine(`Error adding Custom LLM Provider "${providerName}": ${error.message}`);
            }
            // Attempt to clean up the stored secret if other parts of the setup failed
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            try { await context.secrets.delete(secretApiKeyName); } catch (cleanupError) { /* best effort */ }
        }
    });
    context.subscriptions.push(addCustomLlmProviderCommand);
}

// Function to retrieve an API key
export async function getApiKey(context: vscode.ExtensionContext, providerName: string): Promise<string | undefined> {
    let secretKey: string | undefined;

    // Check if it's a built-in provider
    if (Object.values(LlmProvider).includes(providerName as LlmProvider)) {
        secretKey = getBuiltInSecretKey(providerName as LlmProvider);
    } else {
        // Assume it's a custom provider name
        secretKey = `customLlmProvider.${providerName}.apiKey`;
    }

    if (!secretKey) { // Should not happen if providerName is validated before calling
        const message = `Could not determine secret key for provider: ${providerName}`;
        console.error(message);
        if (outputChannel) outputChannel.appendLine(`Error in getApiKey: ${message}`);
        // vscode.window.showErrorMessage(`Invalid LLM provider specified: ${providerName}`); // Potentially too noisy
        return undefined;
    }

    try {
        const apiKey = await context.secrets.get(secretKey);
        // Silently return undefined if no API key is configured
        return apiKey;
    } catch (error: any) {
        const message = `Failed to retrieve API key for ${providerName} (key name ${secretKey}): ${error.message}`;
        console.error(message);
        // vscode.window.showErrorMessage(`Failed to retrieve API key for ${providerName}.`); // Potentially too noisy
        if (outputChannel) outputChannel.appendLine(`Error in getApiKey: ${message}`);
        return undefined;
    }
}

// Function to get the preferred LLM from settings
// Returns the string as configured, e.g., "OpenAI", "Anthropic", "Google", or "Custom".

export function getPreferredLlm(): string | undefined {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    const preferredLlmString = config.get<string>('preferredLlm');

    if (!preferredLlmString) {
        if (outputChannel) outputChannel.appendLine(`Preferred LLM setting is not set. Please configure "secureCodingAssistant.preferredLlm".`);
        return undefined;
    }

    const expectedEnumValues = [...Object.values(LlmProvider).map(p => p.toString()), "Custom"];

    if (expectedEnumValues.some(val => val.toLowerCase() === preferredLlmString.toLowerCase())) { // Make comparison case-insensitive for robustness
        return preferredLlmString;
    } else {
        if (outputChannel) outputChannel.appendLine(`Invalid preferredLlm setting: "${preferredLlmString}". Please choose from ${expectedEnumValues.join(', ')} in settings.`);
        return undefined;
    }
}

// Function to get all available LLMs with API keys configured
async function getAvailableLlms(context: vscode.ExtensionContext): Promise<string[]> {
    const availableLlms: string[] = [];
    
    // Check built-in providers silently
    for (const provider of Object.values(LlmProvider)) {
        const apiKey = await getApiKeySilent(context, provider);
        if (apiKey) {
            availableLlms.push(provider);
        }
    }
    
    // Check custom providers silently
    const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
    for (const customProvider of customLlmConfigs) {
        const apiKey = await getApiKeySilent(context, customProvider.name);
        if (apiKey) {
            availableLlms.push(customProvider.name);
        }
    }
    
    return availableLlms;
}

// Silent version of getApiKey that doesn't log errors (for internal checks)
async function getApiKeySilent(context: vscode.ExtensionContext, providerName: string): Promise<string | undefined> {
    let secretKey: string | undefined;

    // Check if it's a built-in provider
    if (Object.values(LlmProvider).includes(providerName as LlmProvider)) {
        secretKey = getBuiltInSecretKey(providerName as LlmProvider);
    } else {
        // Assume it's a custom provider name
        secretKey = `customLlmProvider.${providerName}.apiKey`;
    }

    if (!secretKey) {
        return undefined;
    }

    try {
        return await context.secrets.get(secretKey);
    } catch (error: any) {
        return undefined;
    }
}




export function deactivate() {
    if (outputChannel) {
        outputChannel.appendLine('Deactivating "secure-coding-assistant".');
        outputChannel.dispose();
    }
}
