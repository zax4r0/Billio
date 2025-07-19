# Expence share app core 

This is a Rust implementation of a Splitwise-like application for managing group expenses, tracking transactions, and visualizing balances. The project is organized for modularity, testability, and extensibility.

## Features
- **User Management:** Add, update, and manage users.
- **Group Management:** Create groups, add/remove users, and manage group memberships.
- **Expense Tracking:** Record transactions, split expenses, and track who owes whom.
- **Audit Logging:** In-memory logging for auditing actions.
- **Visualization:** View balances and transaction summaries.
- **In-Memory Storage:** Fast, simple storage for prototyping and testing.
- **Unit Tests:** Comprehensive tests for core logic.

## Project Structure
```
src/
  constants.rs         # Application constants
  error.rs            # Error handling
  lib.rs              # Library entry point
  main.rs             # CLI entry point
  service.rs          # Business logic
  visualization.rs    # Balance and transaction visualization
  logger/             # In-memory logger
  models/             # Data models (user, group, transaction, etc.)
  storage/            # In-memory storage implementation
  tests/              # Unit tests for modules
Cargo.toml            # Rust project manifest
```

## Getting Started

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (stable)

### Build
```sh
cargo build
```

### Run
```sh
cargo run
```

### Test
```sh
cargo test
```

## Usage
The application is currently CLI-based. You can extend `main.rs` to add commands for user/group/transaction management, or integrate with a web or GUI frontend.

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](LICENSE)
