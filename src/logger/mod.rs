use crate::models::AuditLogEntry;

pub trait AuditLogger {
    fn log(&mut self, entry: AuditLogEntry);
}

pub mod in_memory;
