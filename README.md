<div align="center">
  <img src="assets/billio_logo.png" alt="Billio Logo" width="120" />
  
  <h1>Billio</h1>
  <p><b>A Rust implementation of a Splitwise-like expense sharing system.</b></p>

  <div style="background: #fffbe6; border: 1px solid #ffe58f; color: #7c6300ff; padding: 12px 18px; border-radius: 8px; margin: 18px 0; font-size: 1.1em;">
    <b>⚠️ Work in Progress:</b> This project is actively being developed and I'm new to Rust (Vibe code Alert 🥲). Feedback and suggestions are welcome!
  </div>
</div>

---

## 🚀 Features

- **User management** with email-based uniqueness
- **Group creation** with OWNER/MEMBER roles
- **Invite link management** (revoke, regenerate)
- **Immutable, reversible transactions**
- **Debt settlement** with optional strict mode
- **Granular logging and auditing**
- **In-memory storage** (for testing)

---

## 🛠️ Setup

```bash
cargo build
cargo run
```

---


## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

---

## 📄 License

Distributed under the MIT License.

---

## 📝 TODO

- Move the core logic into a separate crate/module for better separation
- Refactor to use more idiomatic Rust patterns (e.g., traits, error handling)
- Add authentication and authorization
- Improve test coverage and add integration tests
- Add persistent storage (e.g., database backend)
- Enhance API documentation
- Add CI/CD pipeline
- Improve error messages and user feedback
- Add more features for group management and settlements
- Your suggestions and contributions are welcome!
