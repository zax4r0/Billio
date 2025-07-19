use crate::models::AuditLogEntry;
use log::info;

#[derive(Clone)]
pub struct InMemoryAuditLogger {
    logs: Vec<AuditLogEntry>,
}

impl InMemoryAuditLogger {
    pub fn new() -> Self {
        info!("Initializing InMemoryAuditLogger");
        InMemoryAuditLogger { logs: Vec::new() }
    }

    // Expose logs for testing purposes by returning a cloned copy
    pub fn get_logs(&self) -> Vec<AuditLogEntry> {
        self.logs.clone() // Clone the logs to avoid borrow conflicts
    }
}

impl super::AuditLogger for InMemoryAuditLogger {
    fn log(&mut self, entry: AuditLogEntry) {
        info!("Logging audit entry: {:?}", entry.action);
        self.logs.push(entry);
    }
}
