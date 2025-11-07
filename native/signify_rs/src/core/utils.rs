/// Utility functions for KERI operations
use crate::error::{Result, SignifyError};
use serde_json::Value;

/// Concatenate byte slices
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// KERI protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocols {
    KERI,
    ACDC,
}

impl Protocols {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocols::KERI => "KERI",
            Protocols::ACDC => "ACDC",
        }
    }
}

/// Event types (Ilks)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ilks {
    Icp, // Inception
    Rot, // Rotation
    Ixn, // Interaction
    Dip, // Delegated Inception
    Drt, // Delegated Rotation
    Rct, // Receipt
    Vrc, // Validator Receipt
}

impl Ilks {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ilks::Icp => "icp",
            Ilks::Rot => "rot",
            Ilks::Ixn => "ixn",
            Ilks::Dip => "dip",
            Ilks::Drt => "drt",
            Ilks::Rct => "rct",
            Ilks::Vrc => "vrc",
        }
    }
}

/// Serialization types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serials {
    JSON,
    CBOR,
    MGPK,
}

impl Serials {
    pub fn as_str(&self) -> &'static str {
        match self {
            Serials::JSON => "JSON",
            Serials::CBOR => "CBOR",
            Serials::MGPK => "MGPK",
        }
    }
}

/// Version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

pub const VRSN_1_0: Version = Version { major: 1, minor: 0 };

/// Create version string for KERI events
/// Format: KERI10JSON000260_
pub fn versify(
    proto: Protocols,
    version: Option<Version>,
    kind: Option<Serials>,
    size: usize,
) -> String {
    let version = version.unwrap_or(VRSN_1_0);
    let kind = kind.unwrap_or(Serials::JSON);

    format!(
        "{}{}{}{}{}_",
        proto.as_str(),
        version.major,
        version.minor,
        kind.as_str(),
        format!("{:06x}", size).to_uppercase()
    )
}

/// Parse version string
pub fn deversify(vs: &str) -> Result<(Protocols, Version, Serials, usize)> {
    if vs.len() < 17 {
        return Err(SignifyError::InvalidEvent(format!(
            "Version string too short: {}",
            vs
        )));
    }

    let proto = match &vs[0..4] {
        "KERI" => Protocols::KERI,
        "ACDC" => Protocols::ACDC,
        _ => {
            return Err(SignifyError::InvalidEvent(format!(
                "Unknown protocol: {}",
                &vs[0..4]
            )))
        }
    };

    let major = vs.chars().nth(4).unwrap().to_digit(10).unwrap() as u8;
    let minor = vs.chars().nth(5).unwrap().to_digit(10).unwrap() as u8;
    let version = Version { major, minor };

    let kind = match &vs[6..10] {
        "JSON" => Serials::JSON,
        "CBOR" => Serials::CBOR,
        "MGPK" => Serials::MGPK,
        _ => {
            return Err(SignifyError::InvalidEvent(format!(
                "Unknown serialization: {}",
                &vs[6..10]
            )))
        }
    };

    let size_hex = &vs[10..16];
    let size = usize::from_str_radix(size_hex, 16)
        .map_err(|_| SignifyError::InvalidEvent(format!("Invalid size: {}", size_hex)))?;

    Ok((proto, version, kind, size))
}

/// Convert integer to base64
pub fn int_to_b64(num: usize, length: usize) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let bytes = num.to_be_bytes();
    let b64 = URL_SAFE_NO_PAD.encode(&bytes[bytes.len() - ((length * 3 + 3) / 4)..]);

    if b64.len() > length {
        b64[b64.len() - length..].to_string()
    } else {
        format!("{:0>width$}", b64, width = length)
    }
}

/// Read integer from bytes
pub fn read_int(data: &[u8], length: usize) -> usize {
    let mut result = 0usize;
    for i in 0..length.min(data.len()).min(8) {
        result = (result << 8) | data[i] as usize;
    }
    result
}

/// JSON canonicalization (simplified - stringify)
pub fn canonicalize_json(value: &Value) -> Result<String> {
    serde_json::to_string(value).map_err(|e| SignifyError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concat() {
        let a = b"hello";
        let b = b" ";
        let c = b"world";
        let result = concat(&[a, b, c]);
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_versify() {
        let vs = versify(Protocols::KERI, None, None, 608);
        assert!(vs.starts_with("KERI10JSON"));
        assert!(vs.ends_with("_"));
    }

    #[test]
    fn test_deversify() {
        let vs = "KERI10JSON000260_";
        let (proto, version, kind, size) = deversify(vs).unwrap();

        assert_eq!(proto, Protocols::KERI);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 0);
        assert_eq!(kind, Serials::JSON);
        assert_eq!(size, 0x260);
    }

    #[test]
    fn test_versify_deversify_roundtrip() {
        let vs1 = versify(Protocols::KERI, Some(VRSN_1_0), Some(Serials::JSON), 0x123);
        let (proto, version, kind, size) = deversify(&vs1).unwrap();
        let vs2 = versify(proto, Some(version), Some(kind), size);

        assert_eq!(vs1, vs2);
    }
}
