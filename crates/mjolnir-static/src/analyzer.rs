use goblin::Object;
use serde::{Deserialize, Serialize};

use crate::entropy::calculate_entropy;
use mjolnir_core::error::{MjolnirError, Result};

/// Detected binary format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
    Unknown,
}

/// Information about a binary section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
}

/// An imported function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
}

/// A string extracted from the binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub is_wide: bool,
}

/// Complete static analysis result for a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub format: BinaryFormat,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub entry_point: u64,
    pub is_signed: bool,
    pub strings: Vec<ExtractedString>,
    pub overlay_size: u64,
    pub file_size: u64,
    pub overall_entropy: f64,
}

pub struct StaticAnalyzer;

impl StaticAnalyzer {
    /// Full static analysis of a binary
    pub fn analyze(data: &[u8]) -> Result<StaticAnalysisResult> {
        let overall_entropy = calculate_entropy(data);

        match Object::parse(data).map_err(|e| MjolnirError::Parse(e.to_string()))? {
            Object::PE(pe) => Self::analyze_pe(&pe, data, overall_entropy),
            Object::Elf(elf) => Self::analyze_elf(&elf, data, overall_entropy),
            Object::Mach(mach) => Self::analyze_mach(&mach, data, overall_entropy),
            _ => Ok(Self::unknown_format(data, overall_entropy)),
        }
    }

    /// Quick parse for ML feature extraction (skips strings)
    pub fn quick_parse(data: &[u8]) -> Result<StaticAnalysisResult> {
        let overall_entropy = calculate_entropy(data);

        match Object::parse(data).map_err(|e| MjolnirError::Parse(e.to_string()))? {
            Object::PE(pe) => {
                let mut result = Self::analyze_pe(&pe, data, overall_entropy)?;
                result.strings.clear(); // Skip expensive string extraction
                Ok(result)
            }
            Object::Elf(elf) => {
                let mut result = Self::analyze_elf(&elf, data, overall_entropy)?;
                result.strings.clear();
                Ok(result)
            }
            Object::Mach(mach) => {
                let mut result = Self::analyze_mach(&mach, data, overall_entropy)?;
                result.strings.clear();
                Ok(result)
            }
            _ => Ok(Self::unknown_format(data, overall_entropy)),
        }
    }

    fn analyze_pe(
        pe: &goblin::pe::PE,
        data: &[u8],
        overall_entropy: f64,
    ) -> Result<StaticAnalysisResult> {
        let sections: Vec<SectionInfo> = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();
                let offset = s.pointer_to_raw_data as usize;
                let size = s.size_of_raw_data as usize;
                let section_data = if offset + size <= data.len() {
                    &data[offset..offset + size]
                } else {
                    &[]
                };
                SectionInfo {
                    name,
                    virtual_size: s.virtual_size as u64,
                    raw_size: s.size_of_raw_data as u64,
                    entropy: calculate_entropy(section_data),
                    characteristics: s.characteristics,
                }
            })
            .collect();

        let imports: Vec<ImportEntry> = pe
            .imports
            .iter()
            .map(|imp| ImportEntry {
                library: imp.dll.to_string(),
                function: imp.name.to_string(),
            })
            .collect();

        let exports: Vec<String> = pe
            .exports
            .iter()
            .filter_map(|exp| exp.name.map(|n| n.to_string()))
            .collect();

        // Calculate overlay size (data after last section)
        let last_section_end = pe
            .sections
            .iter()
            .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
            .max()
            .unwrap_or(0);
        let overlay_size = if data.len() as u64 > last_section_end {
            data.len() as u64 - last_section_end
        } else {
            0
        };

        let strings = Self::extract_strings(data);

        Ok(StaticAnalysisResult {
            format: BinaryFormat::PE,
            imports,
            exports,
            sections,
            entry_point: pe.entry as u64,
            is_signed: !pe.certificates.is_empty(),
            strings,
            overlay_size,
            file_size: data.len() as u64,
            overall_entropy,
        })
    }

    fn analyze_elf(
        elf: &goblin::elf::Elf,
        data: &[u8],
        overall_entropy: f64,
    ) -> Result<StaticAnalysisResult> {
        let sections: Vec<SectionInfo> = elf
            .section_headers
            .iter()
            .map(|s| {
                let name = elf
                    .shdr_strtab
                    .get_at(s.sh_name)
                    .unwrap_or("")
                    .to_string();
                let offset = s.sh_offset as usize;
                let size = s.sh_size as usize;
                let section_data = if offset + size <= data.len() {
                    &data[offset..offset + size]
                } else {
                    &[]
                };
                SectionInfo {
                    name,
                    virtual_size: s.sh_size,
                    raw_size: s.sh_size,
                    entropy: calculate_entropy(section_data),
                    characteristics: s.sh_flags as u32,
                }
            })
            .collect();

        let imports: Vec<ImportEntry> = elf
            .dynsyms
            .iter()
            .filter(|sym| sym.is_import())
            .filter_map(|sym| {
                elf.dynstrtab.get_at(sym.st_name).map(|name| ImportEntry {
                    library: String::new(),
                    function: name.to_string(),
                })
            })
            .collect();

        let exports: Vec<String> = elf
            .dynsyms
            .iter()
            .filter(|sym| !sym.is_import() && sym.st_name != 0)
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(|n| n.to_string()))
            .collect();

        let strings = Self::extract_strings(data);

        Ok(StaticAnalysisResult {
            format: BinaryFormat::ELF,
            imports,
            exports,
            sections,
            entry_point: elf.entry,
            is_signed: false,
            strings,
            overlay_size: 0,
            file_size: data.len() as u64,
            overall_entropy,
        })
    }

    fn analyze_mach(
        mach: &goblin::mach::Mach,
        data: &[u8],
        overall_entropy: f64,
    ) -> Result<StaticAnalysisResult> {
        match mach {
            goblin::mach::Mach::Binary(macho) => {
                let sections: Vec<SectionInfo> = macho
                    .segments
                    .iter()
                    .flat_map(|seg| {
                        seg.sections().unwrap_or_default().into_iter().map(
                            move |(section, _data)| {
                                let name = format!(
                                    "{}.{}",
                                    String::from_utf8_lossy(&section.segname)
                                        .trim_end_matches('\0'),
                                    String::from_utf8_lossy(&section.sectname)
                                        .trim_end_matches('\0')
                                );
                                let offset = section.offset as usize;
                                let size = section.size as usize;
                                let section_data = if offset + size <= data.len() {
                                    &data[offset..offset + size]
                                } else {
                                    &[]
                                };
                                SectionInfo {
                                    name,
                                    virtual_size: section.size,
                                    raw_size: section.size,
                                    entropy: calculate_entropy(section_data),
                                    characteristics: section.flags,
                                }
                            },
                        )
                    })
                    .collect();

                let imports: Vec<ImportEntry> = macho
                    .imports()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|imp| ImportEntry {
                        library: imp.dylib.to_string(),
                        function: imp.name.to_string(),
                    })
                    .collect();

                let exports: Vec<String> = macho
                    .exports()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|exp| exp.name.to_string())
                    .collect();

                let is_signed = false; // Code signature detection requires deeper Mach-O parsing
                let strings = Self::extract_strings(data);

                Ok(StaticAnalysisResult {
                    format: BinaryFormat::MachO,
                    imports,
                    exports,
                    sections,
                    entry_point: macho.entry,
                    is_signed,
                    strings,
                    overlay_size: 0,
                    file_size: data.len() as u64,
                    overall_entropy,
                })
            }
            goblin::mach::Mach::Fat(_) => Ok(Self::unknown_format(data, overall_entropy)),
        }
    }

    fn unknown_format(data: &[u8], overall_entropy: f64) -> StaticAnalysisResult {
        StaticAnalysisResult {
            format: BinaryFormat::Unknown,
            imports: vec![],
            exports: vec![],
            sections: vec![],
            entry_point: 0,
            is_signed: false,
            strings: Self::extract_strings(data),
            overlay_size: 0,
            file_size: data.len() as u64,
            overall_entropy,
        }
    }

    /// Extract printable ASCII strings (minimum 4 chars)
    fn extract_strings(data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut current = String::new();
        let mut start_offset = 0;
        let min_len = 4;
        let max_strings = 1000; // Cap to prevent memory issues

        for (i, &byte) in data.iter().enumerate() {
            if byte >= 0x20 && byte <= 0x7E {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte as char);
            } else {
                if current.len() >= min_len {
                    strings.push(ExtractedString {
                        value: current.clone(),
                        offset: start_offset,
                        is_wide: false,
                    });
                    if strings.len() >= max_strings {
                        break;
                    }
                }
                current.clear();
            }
        }

        // Don't forget the last string
        if current.len() >= min_len && strings.len() < max_strings {
            strings.push(ExtractedString {
                value: current,
                offset: start_offset,
                is_wide: false,
            });
        }

        strings
    }
}
