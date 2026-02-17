# Contributing to REDHAVEN

Thank you for your interest in contributing to REDHAVEN! 🎉

## 🤝 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🐛 Reporting Bugs

**Before submitting a bug report:**

1. Check existing [GitHub Issues](https://github.com/darkne55x/REDHAVEN/issues)
2. Test with the latest version
3. Ensure it's not a configuration issue

**Bug Report Template:**

```markdown
**Environment:**
- REDHAVEN version: [e.g., 1.0.3]
- Docker version: [e.g., 24.0.5]
- OS: [e.g., Ubuntu 24.04, macOS, Windows WSL2]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Steps to Reproduce:**
1. Run command: ./start.sh
2. Enter target: example.com
3. Select mode: 42
4. Error occurs at Phase X

**Logs:**
```

[Paste relevant error messages]

```

**Additional Context:**
[Any other relevant information]
```

## 💡 Feature Requests

We welcome feature suggestions! Please:

1. Search existing [feature requests](https://github.com/darkne55/REDHAVEN/labels/enhancement)
2. Open a new issue with `[Feature Request]` prefix
3. Describe:
   - **Use case**: Why is this needed?
   - **Proposed solution**: How would it work?
   - **Alternatives**: Other approaches you considered
   - **Impact**: On bug bounty workflow

## 🔧 Contributing Code

### Getting Started

1. **Fork the repository**

```bash
git clone https://github.com/YOUR_USERNAME/REDHAVEN.git
cd REDHAVEN
```

1. **Create a branch**

```bash
git checkout -b feature/amazing-new-module
```

1. **Make your changes**

- Follow existing code style
- Add comments for complex logic
- Test thoroughly

1. **Commit with clear messages**

```bash
git commit -m "feat: Add XSS polyglot fuzzing module"
git commit -m "fix: Resolve unbound variable in scanner.sh"
git commit -m "docs: Update README with new install instructions"
```

**Commit Message Format:**

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

1. **Push and create Pull Request**

```bash
git push origin feature/amazing-new-module
```

### Pull Request Guidelines

**Before submitting:**

- [ ] Code follows project style
- [ ] All tests pass (if applicable)
- [ ] Documentation updated
- [ ] No secrets/tokens in commits
- [ ] CHANGELOG.md updated (if significant change)

**PR Template:**

```markdown
## Description
[Brief description of changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Refactoring

## Testing
- [ ] Tested manually on: [target/environment]
- [ ] Docker build succeeds
- [ ] No regressions in existing features

## Checklist
- [ ] My code follows the project's style
- [ ] I have commented complex sections
- [ ] I have updated documentation
- [ ] My changes generate no new warnings
- [ ] I have added myself to CONTRIBUTORS.md (optional)

## Related Issues
Fixes #123
```

## 📂 Project Structure

```
REDHAVEN/
├── scanner.sh          # Main orchestrator
├── start.sh            # Entry point
├── correlator.py       # Findings correlation
├── ai_hunter.py        # AI-powered analysis
├── cve_matcher.py      # CVE auto-matching
├── s3_bruteforce.py    # Cloud storage discovery
└── [module].py         # Individual security modules
```

## 🎨 Code Style

### Bash Scripts

- Use `#!/bin/bash` shebang
- Indent with 4 spaces
- Quote variables: `"$VAR"`
- Use `|| true` for non-fatal commands
- Add comments for complex logic

**Example:**

```bash
# Good
if [ -s "$OUT_DIR/urls.txt" ]; then
    log_step "Processing URLs..."
    process_urls "$OUT_DIR/urls.txt" || true
fi

# Bad
if [ -s $OUT_DIR/urls.txt ]
then
process_urls $OUT_DIR/urls.txt
fi
```

### Python Scripts

- Follow PEP 8
- Use type hints where possible
- Docstrings for functions
- Classes for complex modules

**Example:**

```python
def analyze_finding(url: str, severity: str) -> dict:
    """
    Analyze security finding and calculate impact.
    
    Args:
        url: Target URL
        severity: CRITICAL, HIGH, MEDIUM, LOW
        
    Returns:
        dict with analysis results
    """
    # Implementation
    pass
```

## 🧪 Testing

**Manual Testing:**

```bash
# Build Docker image
docker build -t redhaven-test:dev .

# Test on safe target
./start.sh
> Target: testphp.vulnweb.com
> Mode: 42

# Verify output files
ls -la results/testphp.vulnweb.com/
```

**Module Testing:**

```bash
# Test individual module
python3 cve_matcher.py /tmp/test_results
python3 s3_bruteforce.py example.com
```

## 📚 Documentation

When adding features, update:

1. **README.md** - If user-facing feature
2. **CHANGELOG.md** - All changes
3. **TECHNICAL_OVERVIEW.txt** - If architectural change
4. **Inline comments** - For complex logic

## 🏆 Recognition

Contributors will be recognized in:

- `CONTRIBUTORS.md` file
- Release notes for significant contributions
- Special mentions for critical security fixes

## 💬 Communication

- **Questions**: [GitHub Discussions](https://github.com/darkne55x/REDHAVEN/discussions)
- **Bugs**: [GitHub Issues](https://github.com/darkne55x/REDHAVEN/issues)
- **Security**: `frandinosocial@gmail.com`

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the GPLv3 License.

---

**Thank you for making REDHAVEN better!** 🚀
