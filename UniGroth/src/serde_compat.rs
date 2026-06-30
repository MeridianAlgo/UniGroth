//! Serde compatibility layer for arkworks EC-parameterized types (feature: `serde`).
//!
//! Provides field-level `serialize`/`deserialize` helpers via `CanonicalSerialize`
//! (compressed bytes). Use with `#[serde(with = "crate::serde_compat")]` on fields
//! that implement `CanonicalSerialize + CanonicalDeserialize`.

/// Serialize a field via `CanonicalSerialize` (compressed bytes).
#[cfg(feature = "serde")]
pub fn serialize<T: ark_serialize::CanonicalSerialize, S: ::serde::Serializer>(
    val: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    use ::serde::ser::Error as _;
    let mut bytes = ark_std::vec::Vec::new();
    val.serialize_compressed(&mut bytes)
        .map_err(S::Error::custom)?;
    ::serde::Serialize::serialize(&bytes, s)
}

/// Deserialize a field via `CanonicalDeserialize` (compressed bytes).
#[cfg(feature = "serde")]
pub fn deserialize<'de, T: ark_serialize::CanonicalDeserialize, D: ::serde::Deserializer<'de>>(
    d: D,
) -> Result<T, D::Error> {
    use ::serde::de::Error as _;
    let bytes: ark_std::vec::Vec<u8> = ::serde::Deserialize::deserialize(d)?;
    T::deserialize_compressed(&bytes[..]).map_err(D::Error::custom)
}
