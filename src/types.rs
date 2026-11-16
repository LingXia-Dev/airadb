//! Validated argument types. Everything that ends up in a command sent to the
//! device goes through one of these; shell arguments are additionally
//! quoted by [`ShellCommand`](crate::ShellCommand).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;


use crate::error::{Error, Result};

/// A remote-control key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(rename_all = "camelCase"))]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Back,
    Home,
    Menu,
    VolumeUp,
    VolumeDown,
    Power,
}

impl Key {
    pub const ALL: [Key; 11] = [
        Key::Up,
        Key::Down,
        Key::Left,
        Key::Right,
        Key::Enter,
        Key::Back,
        Key::Home,
        Key::Menu,
        Key::VolumeUp,
        Key::VolumeDown,
        Key::Power,
    ];

    /// The lower-case name (`home`, `volumeup`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Left => "left",
            Self::Right => "right",
            Self::Enter => "enter",
            Self::Back => "back",
            Self::Home => "home",
            Self::Menu => "menu",
            Self::VolumeUp => "volumeup",
            Self::VolumeDown => "volumedown",
            Self::Power => "power",
        }
    }

    /// The Android `KeyEvent` code for the same key.
    pub fn android_keycode(self) -> u32 {
        match self {
            Self::Home => 3,
            Self::Back => 4,
            Self::Up => 19,
            Self::Down => 20,
            Self::Left => 21,
            Self::Right => 22,
            Self::VolumeUp => 24,
            Self::VolumeDown => 25,
            Self::Power => 26,
            Self::Enter => 66,
            Self::Menu => 82,
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let normalized = s.trim().to_lowercase().replace(['-', '_', ' '], "");
        Ok(match normalized.as_str() {
            "up" => Self::Up,
            "down" => Self::Down,
            "left" => Self::Left,
            "right" => Self::Right,
            "enter" | "ok" | "select" | "center" => Self::Enter,
            "back" | "return" | "esc" => Self::Back,
            "home" => Self::Home,
            "menu" => Self::Menu,
            "volumeup" | "volup" | "v+" | "+" => Self::VolumeUp,
            "volumedown" | "voldown" | "v-" | "-" => Self::VolumeDown,
            "power" | "pwr" => Self::Power,
            _ => {
                return Err(Error::invalid_arg(format!(
                    "unknown key '{s}' (expected one of: up, down, left, right, enter, back, \
                     home, menu, volumeup, volumedown, power)"
                )));
            }
        })
    }
}

fn is_java_ident(segment: &str, allow_dollar: bool) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || (allow_dollar && c == '$'))
}

/// An Android package name such as `com.example.app`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(try_from = "String", into = "String"))]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.len() <= 255 && name.split('.').all(|s| is_java_ident(s, false)) {
            Ok(Self(name))
        } else {
            Err(Error::invalid_arg(format!("invalid package name '{name}'")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An activity class name: fully qualified (`com.example.app.MainActivity`)
/// or relative to its package (`.MainActivity`). Inner classes (`$`) allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(try_from = "String", into = "String"))]
pub struct ActivityName(String);

impl ActivityName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let body = name.strip_prefix('.').unwrap_or(&name);
        if name.len() <= 255 && body.split('.').all(|s| is_java_ident(s, true)) {
            Ok(Self(name))
        } else {
            Err(Error::invalid_arg(format!("invalid activity name '{name}'")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The fully qualified class name, resolving a leading `.` against `package`.
    pub fn qualified(&self, package: &PackageName) -> String {
        if self.0.starts_with('.') {
            format!("{}{}", package.as_str(), self.0)
        } else {
            self.0.clone()
        }
    }
}

macro_rules! string_newtype_impls {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl FromStr for $ty {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }
        impl TryFrom<String> for $ty {
            type Error = Error;
            fn try_from(s: String) -> Result<Self> {
                Self::new(s)
            }
        }
        impl TryFrom<&str> for $ty {
            type Error = Error;
            fn try_from(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }
        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.0
            }
        }
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype_impls!(PackageName);
string_newtype_impls!(ActivityName);

/// An IPv4 /24 network to sweep, e.g. `192.168.1` or `192.168.1.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Subnet([u8; 3]);

impl Subnet {
    /// The /24 that contains `ip`.
    pub fn containing(ip: Ipv4Addr) -> Self {
        let [a, b, c, _] = ip.octets();
        Self([a, b, c])
    }

    /// The /24 of the interface that carries the default route, if any.
    ///
    /// Uses a connected UDP socket; nothing is sent on the wire.
    pub fn detect() -> Option<Self> {
        local_ipv4().map(Self::containing)
    }

    /// Host addresses `.1` through `.254`.
    pub fn hosts(self) -> impl Iterator<Item = Ipv4Addr> {
        let [a, b, c] = self.0;
        (1..=254).map(move |d| Ipv4Addr::new(a, b, c, d))
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        ip.octets()[..3] == self.0
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c] = self.0;
        write!(f, "{a}.{b}.{c}.0/24")
    }
}

impl FromStr for Subnet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || Error::invalid_arg(format!("invalid subnet '{s}' (expected a.b.c or a.b.c.0/24)"));
        let trimmed = s.trim().trim_end_matches('.');
        let (base, mask) = match trimmed.split_once('/') {
            Some((base, mask)) => (base, Some(mask)),
            None => (trimmed, None),
        };
        if mask.is_some_and(|m| m != "24") {
            return Err(bad());
        }
        let parts: Vec<&str> = base.split('.').collect();
        let octets: Vec<u8> = match (parts.len(), mask) {
            (3, None) => parts.iter().map(|p| p.parse()).collect::<Result<_, _>>().map_err(|_| bad())?,
            (4, Some(_)) => parts[..3].iter().map(|p| p.parse()).collect::<Result<_, _>>().map_err(|_| bad())?,
            _ => return Err(bad()),
        };
        if parts.len() == 4 {
            parts[3].parse::<u8>().map_err(|_| bad())?;
        }
        Ok(Self([octets[0], octets[1], octets[2]]))
    }
}

/// The local IPv4 address of the interface carrying the default route.
pub fn local_ipv4() -> Option<Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};
    // Multicast first: it routes to the physical LAN interface and skips VPN tunnels.
    for probe in ["224.0.0.1:80", "239.255.255.250:80", "8.8.8.8:80"] {
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { continue };
        if socket.connect(probe).is_err() {
            continue;
        }
        if let Ok(addr) = socket.local_addr() {
            if let IpAddr::V4(ip) = addr.ip() {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names() {
        assert!(PackageName::new("com.example.app").is_ok());
        assert!(PackageName::new("android").is_ok());
        assert!(PackageName::new("com.ex_1.a2").is_ok());
        for bad in ["", "com..x", "1com.x", "com.x&y=1", "com.x/y", "com.x y", "com.$x", "a.b.", ".a"] {
            assert!(PackageName::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn activity_names() {
        let pkg = PackageName::new("com.example").unwrap();
        let rel = ActivityName::new(".ui.Main$Inner").unwrap();
        assert_eq!(rel.qualified(&pkg), "com.example.ui.Main$Inner");
        assert!(ActivityName::new("com.example.Main").is_ok());
        for bad in ["", ".", "com..Main", "com.Main&x", "com.Main'", "com.Main\"", "com.$(x)"] {
            assert!(ActivityName::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn subnets() {
        let s: Subnet = "192.168.1".parse().unwrap();
        assert_eq!(s.to_string(), "192.168.1.0/24");
        assert_eq!("192.168.1.0/24".parse::<Subnet>().unwrap(), s);
        assert_eq!("192.168.1.".parse::<Subnet>().unwrap(), s);
        assert_eq!(s.hosts().count(), 254);
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 9)));
        for bad in ["192.168", "192.168.1.0/16", "a.b.c", "192.168.300", "192.168.1.5"] {
            assert!(bad.parse::<Subnet>().is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_round_trip() {
        for key in Key::ALL {
            assert_eq!(key.as_str().parse::<Key>().unwrap(), key);
        }
        assert_eq!("OK".parse::<Key>().unwrap(), Key::Enter);
        assert_eq!("volume-up".parse::<Key>().unwrap(), Key::VolumeUp);
    }
}
