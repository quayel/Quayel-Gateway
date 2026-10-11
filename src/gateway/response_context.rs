// ── Response Context ─────────────────────────────────────────────────────────
// Captures response-level information for logging and header management.

#[derive(Debug, Clone, Default)]
pub struct ResponseContext {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub is_from_cache: bool,
    pub is_gateway_generated: bool,
}
