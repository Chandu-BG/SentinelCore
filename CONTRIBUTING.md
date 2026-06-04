# Contributing to NovaSentinel

Thank you for your interest in contributing! NovaSentinel is an open-source AI-powered cybersecurity platform and welcomes community improvements.

---

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/Chandu-BG/SentinelCore.git
cd SentinelCore
```

### 2. Set Up Development Environment

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run the App

```bash
python main.py
```

### 4. Run Tests

```bash
pip install pytest pytest-timeout hypothesis
pytest tests/ -v
```

---

## Development Guidelines

### Code Style
- Follow **PEP 8** for all Python code
- Use **type hints** on all public functions and methods
- Keep functions focused — max ~50 lines per function
- Prefer `logging` over `print()` for all diagnostic output

### Thread Safety
- All Qt signal emissions **must** happen from the main thread or via `QTimer.singleShot(0, ...)`
- SecurityCore engine methods may be called from background threads — they are thread-safe by design
- Use `threading.Thread(daemon=True)` for all background workers

### Error Handling
- Never let exceptions propagate silently — catch and log with `logger.exception()`
- Use `logger.warning()` for recoverable errors, `logger.error()` for failures
- Don't crash the app for non-critical failures (engines are designed to degrade gracefully)

### Adding a New Engine
1. Create `engines/your_engine.py` following the existing engine pattern
2. Add it to `engines/__init__.py`
3. Register it in `core/security_core.py` (see existing engines for reference)
4. Add hidden import to `NovaSentinel.spec` if needed

### Adding a New UI Module
1. Create `gui/views/your_view.py` as a `QWidget` subclass
2. Register it in `gui/main_window.py` in the `_views` dict
3. Add the navigation label to `gui/widgets/sidebar.py` `NAV_LABELS`
4. Add keyboard shortcut in `_setup_keyboard_navigation()`

---

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Make your changes with clear, focused commits
3. Ensure all tests pass: `pytest tests/ -v`
4. Update documentation (docstrings, README if needed)
5. Submit a Pull Request with a clear description of what changed and why

---

## Reporting Issues

When reporting bugs, please include:
- Windows version (10/11, build number)
- Python version (`python --version`)
- Steps to reproduce
- Relevant log output from `sentinelcore.log`
- Screenshots if it's a UI issue

---

## Code of Conduct

- Be respectful and constructive
- Focus feedback on code, not people
- Security researchers: please use responsible disclosure for vulnerability reports

---

## License

By contributing to NovaSentinel, you agree that your contributions will be licensed under the MIT License.
