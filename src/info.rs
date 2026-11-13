use std::collections::HashMap;
use std::fmt;

use crate::device::AdbDevice;
use crate::error::Result;

/// Comprehensive hardware and system information of an Android device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHardwareInfo {
    /// Device model name (e.g. "Pixel 4", "MiTV 4A", "Nexus 5").
    pub model: String,
    /// Brand name (e.g. "google", "Xiaomi", "LGE").
    pub brand: String,
    /// Manufacturer (e.g. "Google", "Xiaomi", "LGE").
    pub manufacturer: String,
    /// 64-bit unique Android ID in hex (e.g. "9774d56d682e549c").
    pub android_id: Option<String>,
    /// Android OS release version (e.g. "5.1.1", "10", "13").
    pub android_version: String,
    /// Android SDK API level (e.g. 21, 29, 33).
    pub sdk_version: u32,

    /// CPU primary architecture / ABI (e.g. "arm64-v8a", "armeabi-v7a", "x86_64").
    pub cpu_abi: String,
    /// Total number of available CPU cores (e.g. 4, 8).
    pub cpu_cores: usize,
    /// Hardware platform / SoC model (e.g. "qcom", "kirin980", "mt6768", "s905x").
    pub cpu_hardware: String,

    /// Total system RAM in bytes.
    pub total_ram_bytes: u64,
    /// Currently available system RAM in bytes.
    pub available_ram_bytes: u64,

    /// Total storage size of the `/data` partition in bytes.
    pub total_storage_bytes: u64,
    /// Available storage size of the `/data` partition in bytes.
    pub available_storage_bytes: u64,
}

impl fmt::Display for DeviceHardwareInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ram_total_gb = self.total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let ram_avail_gb = self.available_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let disk_total_gb = self.total_storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let disk_avail_gb = self.available_storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        writeln!(f, "Device Hardware & System Information:")?;
        writeln!(f, "--------------------------------------------------")?;
        writeln!(f, "Model:             {} ({})", self.model, self.manufacturer)?;
        if let Some(ref aid) = self.android_id {
            writeln!(f, "Android ID:        {}", aid)?;
        }
        writeln!(f, "Android OS:        {} (SDK API {})", self.android_version, self.sdk_version)?;
        writeln!(
            f,
            "CPU:               {} ({} cores, {})",
            self.cpu_abi, self.cpu_cores, self.cpu_hardware
        )?;
        writeln!(
            f,
            "RAM (Memory):      {:.2} GB total / {:.2} GB available",
            ram_total_gb, ram_avail_gb
        )?;
        writeln!(
            f,
            "Storage (/data):   {:.2} GB total / {:.2} GB available",
            disk_total_gb, disk_avail_gb
        )?;
        write!(f, "--------------------------------------------------")
    }
}

/// Retrieves detailed hardware, CPU, memory, storage, and Android ID info from `device`.
///
/// Executes an optimized single batch command across the persistent stream to fetch
/// `/proc/meminfo`, `df`, `settings get secure android_id`, and `getprop` in one network round-trip.
pub async fn query_device_hardware_info(device: &AdbDevice) -> Result<DeviceHardwareInfo> {
    // Combine queries into a single shell execution to minimize latency
    let compound_cmd = "cat /proc/meminfo; echo '===AIRADB_DF==='; df /data; echo '===AIRADB_AID==='; settings get secure android_id 2>/dev/null; echo '===AIRADB_CPU==='; cat /sys/devices/system/cpu/possible 2>/dev/null; cat /proc/cpuinfo; echo '===AIRADB_PROPS==='; getprop";

    let raw = device.shell(compound_cmd).await?;

    let mut meminfo_section = "";
    let mut df_section = "";
    let mut aid_section = "";
    let mut cpu_section = "";
    let mut props_section = "";

    // Split compound output by our unique section markers
    let parts: Vec<&str> = raw.split("===AIRADB_").collect();
    for part in parts {
        if let Some((header, body)) = part.split_once("===") {
            let body = body.trim_start_matches(['\r', '\n']);
            match header {
                "DF" => df_section = body,
                "AID" => aid_section = body,
                "CPU" => cpu_section = body,
                "PROPS" => props_section = body,
                _ => {}
            }
        } else {
            // First section before any marker is meminfo
            meminfo_section = part;
        }
    }

    let props = parse_getprop(props_section);
    let (total_ram_bytes, available_ram_bytes) = parse_meminfo(meminfo_section);
    let (total_storage_bytes, available_storage_bytes) = parse_df(df_section);
    let android_id = parse_android_id(aid_section);
    let cpu_cores = parse_cpu_cores(cpu_section);

    let model = props
        .get("ro.product.model")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());
    let brand = props
        .get("ro.product.brand")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());
    let manufacturer = props
        .get("ro.product.manufacturer")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());
    let android_version = props
        .get("ro.build.version.release")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());
    let sdk_version: u32 = props
        .get("ro.build.version.sdk")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cpu_abi = props
        .get("ro.product.cpu.abi")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());

    let cpu_hardware = props
        .get("ro.board.platform")
        .or_else(|| props.get("ro.hardware"))
        .cloned()
        .unwrap_or_else(|| extract_cpu_hardware(cpu_section));

    Ok(DeviceHardwareInfo {
        model,
        brand,
        manufacturer,
        android_id,
        android_version,
        sdk_version,
        cpu_abi,
        cpu_cores,
        cpu_hardware,
        total_ram_bytes,
        available_ram_bytes,
        total_storage_bytes,
        available_storage_bytes,
    })
}

fn parse_getprop(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if let Some((k_part, v_part)) = trimmed.split_once("]: [") {
                let key = k_part.trim_start_matches('[');
                let val = v_part.trim_end_matches(']');
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    map
}

fn parse_android_id(section: &str) -> Option<String> {
    let trimmed = section.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.contains("not found")
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_meminfo(content: &str) -> (u64, u64) {
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    let mut free_kb = 0u64;
    let mut buffers_kb = 0u64;
    let mut cached_kb = 0u64;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("").trim_end_matches(':');
        let val: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        match key {
            "MemTotal" => total_kb = val,
            "MemAvailable" => avail_kb = val,
            "MemFree" => free_kb = val,
            "Buffers" => buffers_kb = val,
            "Cached" => cached_kb = val,
            _ => {}
        }
    }

    if avail_kb == 0 {
        avail_kb = free_kb + buffers_kb + cached_kb;
    }

    (total_kb * 1024, avail_kb * 1024)
}

fn parse_size_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let last = s.chars().last()?;
    match last {
        'G' | 'g' => {
            let num: f64 = s[..s.len() - 1].parse().ok()?;
            Some((num * 1024.0 * 1024.0 * 1024.0) as u64)
        }
        'M' | 'm' => {
            let num: f64 = s[..s.len() - 1].parse().ok()?;
            Some((num * 1024.0 * 1024.0) as u64)
        }
        'K' | 'k' => {
            let num: f64 = s[..s.len() - 1].parse().ok()?;
            Some((num * 1024.0) as u64)
        }
        'B' | 'b' => {
            let num: u64 = s[..s.len() - 1].parse().ok()?;
            Some(num)
        }
        '0'..='9' => {
            // Raw 1K blocks in standard POSIX df output
            let blocks: u64 = s.parse().ok()?;
            Some(blocks * 1024)
        }
        _ => None,
    }
}

fn parse_df(content: &str) -> (u64, u64) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Filesystem") || trimmed.is_empty() {
            continue;
        }

        // Format 1 (Android 5 toolbox format with labels):
        // "/data: 28282880K total, 7282880K used, 21000000K free"
        if trimmed.contains("total") && trimmed.contains("free") {
            let mut total_bytes = 0u64;
            let mut free_bytes = 0u64;
            for token in trimmed.split(',') {
                let token = token.trim();
                if let Some(pos) = token.find("total") {
                    let num_str = token[..pos]
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_end_matches(['K', 'M', 'G', 'B', 'k', 'm', 'g']);
                    if let Ok(n) = num_str.parse::<u64>() {
                        total_bytes = n * 1024;
                    }
                } else if let Some(pos) = token.find("free") {
                    let num_str = token[..pos]
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_end_matches(['K', 'M', 'G', 'B', 'k', 'm', 'g']);
                    if let Ok(n) = num_str.parse::<u64>() {
                        free_bytes = n * 1024;
                    }
                }
            }
            if total_bytes > 0 {
                return (total_bytes, free_bytes);
            }
        }

        // Format 2:
        // Table format, e.g.:
        // "/dev/block/dm-0  28282880 7282880 21000000  26% /data"
        // or Android 5 toolbox humanized:
        // "/data               1.5G     93.4M    1.4G   4096"
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4 {
            if let (Some(total), Some(avail)) = (parse_size_bytes(parts[1]), parse_size_bytes(parts[3])) {
                return (total, avail);
            }
        }
    }
    (0, 0)
}

fn parse_cpu_cores(cpu_section: &str) -> usize {
    // First line might be "0-7" from /sys/devices/system/cpu/possible
    if let Some(first_line) = cpu_section.lines().next() {
        let trimmed = first_line.trim();
        if let Some((start, end)) = trimmed.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<usize>(), end.parse::<usize>()) {
                if e >= s {
                    return e - s + 1;
                }
            }
        } else if let Ok(n) = trimmed.parse::<usize>() {
            return n + 1;
        }
    }

    // Fallback count "processor" in /proc/cpuinfo
    let mut count = 0;
    for line in cpu_section.lines() {
        if line.trim_start().starts_with("processor") {
            count += 1;
        }
    }
    if count > 0 {
        count
    } else {
        1
    }
}

fn extract_cpu_hardware(cpuinfo: &str) -> String {
    for line in cpuinfo.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hardware") || trimmed.starts_with("model name") {
            if let Some((_, val)) = trimmed.split_once(':') {
                let clean = val.trim();
                if !clean.is_empty() {
                    return clean.to_string();
                }
            }
        }
    }
    "Unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_meminfo() {
        let sample = "MemTotal:        3934524 kB\nMemFree:          456789 kB\nMemAvailable:    2134567 kB\n";
        let (total, avail) = parse_meminfo(sample);
        assert_eq!(total, 3934524 * 1024);
        assert_eq!(avail, 2134567 * 1024);
    }

    #[test]
    fn test_parse_df_formats() {
        // POSIX format
        let df_posix = "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/block/dm-0  28282880 7282880  21000000  26% /data\n";
        let (total, avail) = parse_df(df_posix);
        assert_eq!(total, 28282880 * 1024);
        assert_eq!(avail, 21000000 * 1024);

        // Android 5 legacy format
        let df_legacy = "/data: 14141440K total, 3641440K used, 10500000K free (block size 4096)\n";
        let (total_leg, avail_leg) = parse_df(df_legacy);
        assert_eq!(total_leg, 14141440 * 1024);
        assert_eq!(avail_leg, 10500000 * 1024);
    }

    #[test]
    fn test_parse_android_id() {
        assert_eq!(
            parse_android_id("9774d56d682e549c\n"),
            Some("9774d56d682e549c".to_string())
        );
        assert_eq!(parse_android_id("null\n"), None);
        assert_eq!(parse_android_id("/system/bin/sh: not found\n"), None);
    }

    #[test]
    fn test_parse_cpu_cores() {
        assert_eq!(parse_cpu_cores("0-7\nprocessor: 0\n"), 8);
        assert_eq!(parse_cpu_cores("0-3\n"), 4);
        assert_eq!(parse_cpu_cores("processor: 0\nprocessor: 1\n"), 2);
    }
}
