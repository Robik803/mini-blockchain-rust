/// Domain-separation context used for Ed25519 prehashed signing.
///
/// This ensures signatures from this blockchain cannot be reused
/// in other protocols, even if the message is identical.
pub const CONTEXT: &[u8] = b"Robik803MiniBlochainTxnSigning";