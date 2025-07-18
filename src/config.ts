// Configuration for Secure Coding Assistant Extension

// API Configuration
export const API_CONFIG = {
    DEFAULT_MODEL: 'gpt-4-turbo-preview',
    DEFAULT_TEMPERATURE: 0,
    DEFAULT_TOP_P: 1,
    DEFAULT_FREQUENCY_PENALTY: 0,
    DEFAULT_PRESENCE_PENALTY: 0,
    DEFAULT_MAX_TOKENS: 4000,
    DEFAULT_TIMEOUT: 30000, // 30 seconds
    DEFAULT_BATCH_SIZE: 5
};

// Security Configuration
export const SECURITY_CONFIG = {
    DEFAULT_HALLUCINATION_SCORE: 0.1,
    DEFAULT_CONFIDENCE_SCORE: 0.9,
    DEFAULT_SEVERITY: 'High' as 'High' | 'Medium' | 'Low'
};

// File Extension Configuration
export const FILE_CONFIG = {
    SOURCE_CODE_EXTENSIONS: [
        '.ts', '.js', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb',
        '.cs', '.swift', '.kt', '.m', '.h', '.hpp', '.json', '.yaml', '.yml',
        '.xml', '.html', '.css', '.scss', '.less', '.sh', '.ps1', '.bat'
    ],
    EXCLUDED_DIRECTORIES: [
        'node_modules', 'dist', 'build', 'out', 'extension', 'bin', 'obj', 
        '.git', '.svn', '.hg', '.vscode', '.vscode-test', 
        'venv', 'env', '.env', '__pycache__'
    ]
};

// Message Configuration
export const MESSAGES = {
    PREFERRED_LLM_NOT_CONFIGURED: "Preferred LLM not configured. Please set it in the extension settings.",
    CUSTOM_LLM_NOT_CONFIGURED: "Preferred LLM is 'Custom', but no custom LLMs are configured. Please add one using the 'Secure Coding: Add Custom LLM Provider' command.",
    NO_ACTIVE_EDITOR: "No active text editor found.",
    NO_TEXT_SELECTED: "No text selected or selection is empty.",
    API_KEY_NOT_FOUND: "API Key not found. Please add it using the provided commands.",
    SCAN_COMPLETE: "Selection scan complete. View results in \"Secure Coding Assistant\" output channel.",
    SCAN_ERROR: "Error during selection scan: ",
    FILE_SCAN_ERROR: "Failed to open file: ",
    EMPTY_FILE: "File is empty or contains only whitespace. Skipping.",
    FOLDER_SCAN_COMPLETE: "Scan complete for ",
    FOLDER_SCAN_ERROR: "Failed to scan folder: ",
    CUSTOM_LLM_SETUP_CANCELLED: "Custom LLM Provider setup cancelled: ",
    CUSTOM_LLM_ADDED: "Custom LLM Provider \"{name}\" added successfully.",
    CUSTOM_LLM_ERROR: "Failed to add Custom LLM Provider \"{name}\": ",
    INVALID_PROVIDER: "Invalid LLM provider specified: ",
    API_KEY_ERROR: "Failed to retrieve API key for {name}."
};

// Secret Key Configuration
export const SECRET_KEYS = {
    OPENAI: 'secureCodingAssistant.openaiApiKey',
    ANTHROPIC: 'secureCodingAssistant.anthropicApiKey',
    GOOGLE: 'secureCodingAssistant.googleApiKey',
    CUSTOM: 'secureCodingAssistant.customApiKey'
}; 