use std::fmt::Write as _;

use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Exact IEEE 754 `f64` safe integer bounds (`±(2^53 - 1)`).
const MAX_SAFE_I64: i64 = (1_i64 << 53) - 1;
const MIN_SAFE_I64: i64 = -MAX_SAFE_I64;
const MAX_SAFE_U64: u64 = (1_u64 << 53) - 1;

/// Encodes `bytes` as lowercase hexadecimal ASCII.
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Computes a `"sha256:<64 lowercase hex>"` digest over `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_encode_lower(&digest))
}

/// Returns `true` if `s` has the exact format `"sha256:<64 lowercase hex>"`.
pub fn is_valid_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Serializes any `Serialize` value into deterministic RFC 8785 JCS UTF-8 bytes.
///
/// Guarantees:
/// - Object keys are sorted explicitly by UTF-16 code-unit order (RFC 8785 §3.2.3),
///   independent of Rust struct field declaration order and immune to `serde_json/preserve_order`.
/// - Zero insignificant whitespace.
/// - Minimal RFC 8785 §3.2.2.2 string escaping.
/// - Finite numbers formatted strictly per RFC 8785 §3.2.2.3 (ECMA-262 IEEE 754 binary64);
///   `NaN`, `+Infinity`, and `-Infinity` are rejected with [`CoreError::NonFiniteNumber`].
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let jcs_val = value.serialize(JcsValueSerializer)?;
    let mut out = Vec::with_capacity(256);
    write_jcs_node(&jcs_val, &mut out)?;
    Ok(out)
}

/// Serializes a `serde_json::Value` into deterministic RFC 8785 JCS UTF-8 bytes.
pub fn value_to_jcs_bytes(value: &Value) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::with_capacity(256);
    write_serde_value(value, &mut out)?;
    Ok(out)
}

/// Internal JCS AST that preserves non-finite float rejection during `Serialize`.
enum JcsNode {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    String(String),
    Array(Vec<JcsNode>),
    Object(Vec<(String, JcsNode)>),
}

fn write_jcs_node(node: &JcsNode, out: &mut Vec<u8>) -> Result<(), CoreError> {
    match node {
        JcsNode::Null => out.extend_from_slice(b"null"),
        JcsNode::Bool(true) => out.extend_from_slice(b"true"),
        JcsNode::Bool(false) => out.extend_from_slice(b"false"),
        JcsNode::I64(i) => write_jcs_i64(*i, out)?,
        JcsNode::U64(u) => write_jcs_u64(*u, out)?,
        JcsNode::F64(f) => {
            let formatted = format_jcs_f64(*f)?;
            out.extend_from_slice(formatted.as_bytes());
        }
        JcsNode::String(s) => write_jcs_string(s, out),
        JcsNode::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_jcs_node(item, out)?;
            }
            out.push(b']');
        }
        JcsNode::Object(entries) => {
            let mut sorted: Vec<(&String, &JcsNode)> =
                entries.iter().map(|(k, v)| (k, v)).collect();
            // RFC 8785 §3.2.3: sort properties by UTF-16 code units.
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));

            out.push(b'{');
            for (idx, (key, val)) in sorted.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_jcs_string(key, out);
                out.push(b':');
                write_jcs_node(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_serde_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CoreError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(num) => write_jcs_number(num, out)?,
        Value::String(s) => write_jcs_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_serde_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785 §3.2.3: sort properties by UTF-16 code units.
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));

            out.push(b'{');
            for (idx, (key, val)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_jcs_string(key, out);
                out.push(b':');
                write_serde_value(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_jcs_i64(i: i64, out: &mut Vec<u8>) -> Result<(), CoreError> {
    if (MIN_SAFE_I64..=MAX_SAFE_I64).contains(&i) {
        out.extend_from_slice(i.to_string().as_bytes());
        Ok(())
    } else {
        let formatted = format_jcs_f64(i as f64)?;
        out.extend_from_slice(formatted.as_bytes());
        Ok(())
    }
}

fn write_jcs_u64(u: u64, out: &mut Vec<u8>) -> Result<(), CoreError> {
    if u <= MAX_SAFE_U64 {
        out.extend_from_slice(u.to_string().as_bytes());
        Ok(())
    } else {
        let formatted = format_jcs_f64(u as f64)?;
        out.extend_from_slice(formatted.as_bytes());
        Ok(())
    }
}

fn write_jcs_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let code = c as u8;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(code >> 4) as usize]);
                out.push(HEX[(code & 0x0F) as usize]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_jcs_number(num: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CoreError> {
    if let Some(i) = num.as_i64() {
        return write_jcs_i64(i, out);
    }
    if let Some(u) = num.as_u64() {
        return write_jcs_u64(u, out);
    }
    let f = num.as_f64().ok_or(CoreError::NonFiniteNumber)?;
    let formatted = format_jcs_f64(f)?;
    out.extend_from_slice(formatted.as_bytes());
    Ok(())
}

/// Formats an IEEE 754 `f64` according to RFC 8785 §3.2.2.3 (ECMA-262 `Number::toString`).
///
/// Rejects `NaN`, `+Infinity`, and `-Infinity` with [`CoreError::NonFiniteNumber`].
pub fn format_jcs_f64(f: f64) -> Result<String, CoreError> {
    if !f.is_finite() {
        return Err(CoreError::NonFiniteNumber);
    }
    if f == 0.0 {
        // RFC 8785 §3.2.2.3: both +0.0 and -0.0 serialize as "0".
        return Ok("0".to_owned());
    }

    let negative = f.is_sign_negative();
    let abs = f.abs();
    // `serde_json` produces the shortest exact round-trip decimal digits for finite IEEE 754 floats.
    let raw = serde_json::to_string(&abs)?;

    let (mantissa_str, exp10): (&str, i32) = match raw.find(['e', 'E']) {
        Some(idx) => {
            let exp: i32 = raw[idx + 1..]
                .parse()
                .map_err(|_| CoreError::NonFiniteNumber)?;
            (&raw[..idx], exp)
        }
        None => (raw.as_str(), 0),
    };

    let mut digits = String::with_capacity(mantissa_str.len());
    let mut frac_digits: i32 = 0;
    let mut seen_dot = false;
    for ch in mantissa_str.chars() {
        if ch == '.' {
            seen_dot = true;
        } else {
            digits.push(ch);
            if seen_dot {
                frac_digits += 1;
            }
        }
    }

    // Strip leading zeros (e.g., "0.001" -> digits "1", preserving decimal position).
    let trimmed_leading = digits.trim_start_matches('0');
    let mut sig = trimmed_leading.trim_end_matches('0').to_owned();
    let trailing_zeros = (trimmed_leading.len() - sig.len()) as i32;
    if sig.is_empty() {
        return Ok("0".to_owned());
    }

    let k = sig.len() as i32;
    // Value == (integer sig) * 10^(exp10 - frac_digits + trailing_zeros)
    //       == 0.<sig> * 10^n, so n = exp10 - frac_digits + trailing_zeros + k.
    let n = exp10 - frac_digits + trailing_zeros + k;

    let mut out = String::with_capacity(32);
    if negative {
        out.push('-');
    }

    if k <= n && n <= 21 {
        // ES6 §7.1.12.1 Rule 6: integer with trailing zeros.
        out.push_str(&sig);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        // ES6 §7.1.12.1 Rule 7: fixed-point with decimal point inside `sig`.
        let split = n as usize;
        out.push_str(&sig[..split]);
        out.push('.');
        out.push_str(&sig[split..]);
    } else if -6 < n && n <= 0 {
        // ES6 §7.1.12.1 Rule 8: fixed-point `0.000...<sig>`.
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&sig);
    } else {
        // ES6 §7.1.12.1 Rules 9-10: scientific notation.
        if k == 1 {
            out.push_str(&sig);
        } else {
            let first = sig.remove(0);
            out.push(first);
            out.push('.');
            out.push_str(&sig);
        }
        let exp = n - 1;
        out.push('e');
        if exp >= 0 {
            out.push('+');
            let _ = write!(out, "{exp}");
        } else {
            let _ = write!(out, "{exp}");
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Direct `serde::Serializer` into `JcsNode` (rejects non-finite floats strictly)
// ---------------------------------------------------------------------------

impl ser::Error for CoreError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Json(<serde_json::Error as ser::Error>::custom(msg))
    }
}

struct JcsValueSerializer;

impl ser::Serializer for JcsValueSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    type SerializeSeq = JcsSeqSerializer;
    type SerializeTuple = JcsSeqSerializer;
    type SerializeTupleStruct = JcsSeqSerializer;
    type SerializeTupleVariant = JcsTupleVariantSerializer;
    type SerializeMap = JcsMapSerializer;
    type SerializeStruct = JcsStructSerializer;
    type SerializeStructVariant = JcsStructVariantSerializer;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::I64(i64::from(v)))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::I64(i64::from(v)))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::I64(i64::from(v)))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::I64(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::U64(u64::from(v)))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::U64(u64::from(v)))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::U64(u64::from(v)))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::U64(v))
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        let f = f64::from(v);
        if !f.is_finite() {
            return Err(CoreError::NonFiniteNumber);
        }
        Ok(JcsNode::F64(f))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        if !v.is_finite() {
            return Err(CoreError::NonFiniteNumber);
        }
        Ok(JcsNode::F64(v))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::String(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::String(v.to_owned()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Array(
            v.iter().map(|&b| JcsNode::U64(u64::from(b))).collect(),
        ))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::String(variant.to_owned()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let node = value.serialize(self)?;
        Ok(JcsNode::Object(vec![(variant.to_owned(), node)]))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(JcsSeqSerializer {
            items: Vec::with_capacity(len.unwrap_or(0)),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(JcsTupleVariantSerializer {
            name: variant.to_owned(),
            items: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(JcsMapSerializer {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            next_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(JcsStructSerializer {
            entries: Vec::with_capacity(len),
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(JcsStructVariantSerializer {
            name: variant.to_owned(),
            entries: Vec::with_capacity(len),
        })
    }
}

struct JcsSeqSerializer {
    items: Vec<JcsNode>,
}

impl SerializeSeq for JcsSeqSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.items.push(value.serialize(JcsValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Array(self.items))
    }
}

impl SerializeTuple for JcsSeqSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for JcsSeqSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

struct JcsTupleVariantSerializer {
    name: String,
    items: Vec<JcsNode>,
}

impl SerializeTupleVariant for JcsTupleVariantSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.items.push(value.serialize(JcsValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Object(vec![(
            self.name,
            JcsNode::Array(self.items),
        )]))
    }
}

struct JcsMapSerializer {
    entries: Vec<(String, JcsNode)>,
    next_key: Option<String>,
}

impl SerializeMap for JcsMapSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        match key.serialize(JcsValueSerializer)? {
            JcsNode::String(s) => {
                self.next_key = Some(s);
                Ok(())
            }
            _ => Err(<CoreError as ser::Error>::custom(
                "JCS object keys must be strings",
            )),
        }
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self.next_key.take().ok_or_else(|| {
            <CoreError as ser::Error>::custom("serialize_value called before serialize_key")
        })?;
        let val = value.serialize(JcsValueSerializer)?;
        self.entries.push((key, val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Object(self.entries))
    }
}

struct JcsStructSerializer {
    entries: Vec<(String, JcsNode)>,
}

impl SerializeStruct for JcsStructSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let val = value.serialize(JcsValueSerializer)?;
        self.entries.push((key.to_owned(), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Object(self.entries))
    }
}

struct JcsStructVariantSerializer {
    name: String,
    entries: Vec<(String, JcsNode)>,
}

impl SerializeStructVariant for JcsStructVariantSerializer {
    type Ok = JcsNode;
    type Error = CoreError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let val = value.serialize(JcsValueSerializer)?;
        self.entries.push((key.to_owned(), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(JcsNode::Object(vec![(
            self.name,
            JcsNode::Object(self.entries),
        )]))
    }
}
