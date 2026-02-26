use mjolnir_static::StaticAnalysisResult;

/// Suspicious Windows API imports that indicate potential malicious behavior
pub const SUSPICIOUS_IMPORTS: &[&str] = &[
    // Process injection
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "NtWriteVirtualMemory",
    // Code execution
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
    // Privilege escalation
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    // Anti-debug
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    // Persistence
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    // Network
    "InternetOpenA",
    "InternetOpenW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "HttpSendRequestA",
    // Keylogging
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyboardState",
    // File operations
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileExA",
];

/// Suspicious string patterns found in malware
pub const SUSPICIOUS_STRING_PATTERNS: &[&str] = &[
    "cmd.exe /c",
    "powershell",
    "powershell.exe",
    "-ExecutionPolicy Bypass",
    "-EncodedCommand",
    "IEX(",
    "Invoke-Expression",
    "Net.WebClient",
    "DownloadString",
    "DownloadFile",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "schtasks /create",
    "vssadmin",
    "bcdedit",
    "wmic",
    "whoami",
    "net user",
    "net localgroup",
    "taskkill",
    "sc stop",
    "sc delete",
];

/// Known packer section names
pub const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".nsp0", ".nsp1", ".nsp2", "pec1",
    "pec2", ".petite", ".spack", ".svkp", "Themida", ".themida", ".winlice", ".yP", "yP",
    ".perplex", ".packed",
];

/// Analyze imports for suspicious patterns
pub fn score_imports(result: &StaticAnalysisResult) -> (f64, Vec<String>) {
    let mut suspicious = Vec::new();
    let mut score: f64 = 0.0;

    for import in &result.imports {
        for &sus in SUSPICIOUS_IMPORTS {
            if import.function == sus {
                suspicious.push(import.function.clone());
                score += 0.15;
            }
        }
    }

    // Dangerous combinations
    let has_valloc = suspicious.iter().any(|s| s == "VirtualAllocEx");
    let has_write = suspicious.iter().any(|s| s == "WriteProcessMemory");
    let has_thread = suspicious
        .iter()
        .any(|s| s == "CreateRemoteThread" || s == "NtCreateThreadEx");

    if has_valloc && has_write && has_thread {
        score += 0.5; // Process injection trifecta
    }

    (score.min(1.0), suspicious)
}

/// Analyze strings for suspicious patterns
pub fn score_strings(result: &StaticAnalysisResult) -> (f64, Vec<String>) {
    let mut suspicious = Vec::new();
    let mut score: f64 = 0.0;

    for extracted in &result.strings {
        let lower = extracted.value.to_lowercase();
        for &pattern in SUSPICIOUS_STRING_PATTERNS {
            if lower.contains(&pattern.to_lowercase()) {
                suspicious.push(extracted.value.clone());
                score += 0.1;
                break;
            }
        }

        // Check for IP addresses
        if looks_like_ip(&extracted.value) {
            suspicious.push(format!("IP: {}", extracted.value));
            score += 0.05;
        }

        // Check for URLs
        if extracted.value.starts_with("http://") || extracted.value.starts_with("https://") {
            suspicious.push(format!("URL: {}", extracted.value));
            score += 0.05;
        }
    }

    (score.min(1.0), suspicious)
}

/// Check for packer indicators
pub fn score_packing(result: &StaticAnalysisResult) -> (f64, Vec<String>) {
    let mut indicators = Vec::new();
    let mut score: f64 = 0.0;

    // Check section names for known packers
    for section in &result.sections {
        for &packer in PACKER_SECTIONS {
            if section.name.contains(packer) {
                indicators.push(format!("Packer section: {}", section.name));
                score += 0.3;
            }
        }

        // High entropy sections (> 7.0 suggests encrypted/compressed)
        if section.entropy > 7.0 && section.raw_size > 1024 {
            indicators.push(format!(
                "High entropy section: {} (entropy: {:.2})",
                section.name, section.entropy
            ));
            score += 0.2;
        }
    }

    // Overall high entropy
    if result.overall_entropy > 7.2 {
        indicators.push(format!(
            "High overall entropy: {:.2}",
            result.overall_entropy
        ));
        score += 0.2;
    }

    // Few sections with high entropy (common in packed binaries)
    let high_entropy_count = result
        .sections
        .iter()
        .filter(|s| s.entropy > 6.5 && s.raw_size > 512)
        .count();
    if high_entropy_count >= 2 && result.sections.len() <= 4 {
        indicators.push("Multiple high-entropy sections in small binary".to_string());
        score += 0.15;
    }

    (score.min(1.0), indicators)
}

/// Check for structural anomalies
pub fn score_anomalies(result: &StaticAnalysisResult) -> (f64, Vec<String>) {
    let mut anomalies = Vec::new();
    let mut score: f64 = 0.0;

    // Large overlay data
    if result.overlay_size > 0 && result.overlay_size > result.file_size / 2 {
        anomalies.push(format!("Large overlay: {} bytes", result.overlay_size));
        score += 0.15;
    }

    // Section size mismatches
    for section in &result.sections {
        if section.virtual_size > 0
            && section.raw_size > 0
            && section.virtual_size > section.raw_size * 10
        {
            anomalies.push(format!(
                "Section size mismatch: {} (virtual: {}, raw: {})",
                section.name, section.virtual_size, section.raw_size
            ));
            score += 0.1;
        }
    }

    // No imports (unusual for legitimate executables)
    if result.imports.is_empty()
        && (result.format == mjolnir_static::BinaryFormat::PE
            || result.format == mjolnir_static::BinaryFormat::ELF)
    {
        anomalies.push("No imports detected".to_string());
        score += 0.2;
    }

    // Unsigned PE
    if result.format == mjolnir_static::BinaryFormat::PE && !result.is_signed {
        anomalies.push("Unsigned PE binary".to_string());
        score += 0.05;
    }

    (score.min(1.0), anomalies)
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}
