# Splitwise Clone

A Rust implementation of a Splitwise-like expense sharing system.

## Features
- User management with email-based uniqueness
- Group creation with OWNER/MEMBER roles
- Invite link management (revoke, regenerate)
- Immutable, reversible transactions
- Debt settlement with optional strict mode
- Granular logging and auditing
- In-memory storage (for testing)

## Setup
```bash
cargo build
cargo run