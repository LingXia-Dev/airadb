//! Installed apps with their names and icons. `pm` prints neither, so a
//! 4 KB dex (`helper/`) runs on the device through `app_process` as the
//! shell user and asks `PackageManager`. It is pushed on first use; when it
//! cannot run, listing falls back to `pm` without names.

use std::sync::LazyLock;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::types::PackageName;

const DEX: &[u8] = include_bytes!("../helper/helper.dex");
const MISSING: &[u8] = b"__airadb_helper_missing__";

/// Versioned by content, so an updated helper never meets a stale copy.
static REMOTE: LazyLock<String> = LazyLock::new(|| {
    let hash = DEX.iter().fold(0x811c9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    format!("/data/local/tmp/airadb-helper-{hash:08x}.dex")
});

/// An installed app.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct App {
    pub package: String,
    /// The label the launcher shows; `None` when the device would not say.
    pub name: Option<String>,
    pub system: bool,
}

impl Device {
    /// Apps with a launcher entry (phone or TV), as a launcher lists them.
    pub async fn apps(&self) -> Result<Vec<App>> {
        self.list_apps(false).await
    }

    /// Every installed package, including system ones without a launcher entry.
    pub async fn all_apps(&self) -> Result<Vec<App>> {
        self.list_apps(true).await
    }

    /// The app's icon as a 128-pixel square PNG.
    pub async fn app_icon(&self, package: &PackageName) -> Result<Vec<u8>> {
        let png = self.helper(&format!("icon {} 128", package.as_str())).await?;
        if png.starts_with(b"\x89PNG") {
            Ok(png)
        } else {
            Err(Error::new(crate::ErrorKind::NotFound, format!("no icon for {package}")))
        }
    }

    async fn list_apps(&self, all: bool) -> Result<Vec<App>> {
        let parsed = match self.helper(if all { "apps all" } else { "apps" }).await {
            Ok(out) => parse(&String::from_utf8_lossy(&out)),
            Err(e) if e.kind() == crate::ErrorKind::Unauthorized || e.kind() == crate::ErrorKind::Disconnected => {
                return Err(e)
            }
            Err(e) => {
                tracing::debug!("helper unavailable, falling back to pm: {e}");
                Vec::new()
            }
        };
        let mut apps = if parsed.is_empty() { self.pm_list(all).await? } else { parsed };
        apps.sort_by(|a, b| a.package.cmp(&b.package));
        Ok(apps)
    }

    /// Run the helper; push it first if this device does not have it yet.
    async fn helper(&self, args: &str) -> Result<Vec<u8>> {
        let path = REMOTE.as_str();
        let cmd = format!(
            "if [ -f {path} ]; then CLASSPATH={path} exec app_process / airadb.Helper {args}; else echo {}; fi",
            String::from_utf8_lossy(MISSING)
        );
        let out = self.exec_raw(&cmd).await?;
        if out.trim_ascii() != MISSING {
            return Ok(out);
        }
        self.push_bytes_with_mode(DEX, path, 0o644).await?;
        self.exec_raw(&cmd).await
    }

    /// `pm list packages -f`: no names. Without `all`, third-party only
    /// (the closest `pm` gets to "what the launcher shows").
    async fn pm_list(&self, all: bool) -> Result<Vec<App>> {
        let mut cmd = self.shell("pm").arg("list").arg("packages").arg("-f");
        if !all {
            cmd = cmd.arg("-3");
        }
        Ok(cmd
            .await?
            .lines()
            .filter_map(|line| line.trim().strip_prefix("package:"))
            .map(|rest| {
                let (path, package) = rest.rsplit_once('=').unwrap_or(("", rest));
                App { package: package.to_string(), name: None, system: !path.starts_with("/data/") }
            })
            .collect())
    }
}

/// `package TAB system TAB label` lines; anything else (a JVM error) is skipped.
fn parse(out: &str) -> Vec<App> {
    out.lines()
        .filter_map(|line| {
            let mut f = line.splitn(3, '\t');
            let (package, system, name) = (f.next()?, f.next()?, f.next()?);
            PackageName::new(package).ok()?;
            Some(App {
                package: package.to_string(),
                name: (!name.trim().is_empty()).then(|| name.to_string()),
                system: system == "1",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_helper_lines() {
        let out = "com.a\t1\t设置\nException in thread main\ncom.b\t0\t\n";
        let apps = parse(out);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0], App { package: "com.a".into(), name: Some("设置".into()), system: true });
        assert_eq!(apps[1].name, None);
        assert!(!apps[1].system);
    }

    #[test]
    fn helper_path_is_versioned() {
        assert!(REMOTE.starts_with("/data/local/tmp/airadb-helper-") && REMOTE.ends_with(".dex"));
    }
}
