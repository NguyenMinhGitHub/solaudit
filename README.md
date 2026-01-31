# solaudit

**Solidity smart contract security auditor CLI. Scan for vulnerabilities, reentrancy attacks, integer overflows, and 50+ common security issues. CI/CD ready.**

[![npm version](https://img.shields.io/npm/v/solaudit-cli.svg)](https://www.npmjs.com/package/solaudit-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 **Vulnerability detection** - Reentrancy, overflow, access control, more
- ⛽ **Gas optimization** - Storage patterns, loop inefficiencies
- 📋 **Best practices** - Naming, documentation, code organization
- 🚀 **Fast** - Static analysis, no compilation required
- 🔧 **CI/CD ready** - Exit codes for pipeline integration
- 📊 **Multiple reports** - JSON, Markdown, table output
- 📁 **Recursive scanning** - Audit entire project directories

## Installation

```bash
npm install -g solaudit-cli
```

## Quick Start

```bash
# Audit a single contract
solaudit audit Contract.sol

# Audit all contracts in directory
solaudit audit ./contracts/ -r

# Quick security check
solaudit check MyToken.sol

# Gas optimization analysis
solaudit gas Contract.sol
```

## Commands

### `audit <path>`

Full security audit of Solidity contracts.

```bash
solaudit audit Contract.sol
solaudit audit ./contracts/ -r               # Recursive scan
solaudit audit . -s high                     # Only high+ severity
solaudit audit . --gas --best-practices      # Include all checks
solaudit audit . -o markdown --save report.md
```

**Options:**
- `-r, --recursive` - Scan directories recursively
- `-s, --severity <level>` - Minimum: low, medium, high, critical
- `--gas` - Include gas optimization suggestions
- `--best-practices` - Include best practice checks
- `-o, --output <format>` - table, json, markdown
- `--save <file>` - Save report to file

### `check <file>`

Quick security check on a single file.

```bash
solaudit check Token.sol
solaudit check Vault.sol -s critical
```

### `gas <file>`

Analyze gas optimization opportunities.

```bash
solaudit gas Contract.sol
solaudit gas ./contracts/ -r
```

### `patterns`

List all vulnerability patterns.

```bash
solaudit patterns
solaudit patterns --category reentrancy
solaudit patterns --severity critical
```

## Vulnerability Detection

### 🔴 Critical

- **Reentrancy** - State changes after external calls
- **Unprotected selfdestruct** - Anyone can destroy contract
- **Delegatecall injection** - Arbitrary code execution
- **Signature replay** - Missing nonce protection

### 🟡 High

- **Integer overflow/underflow** - Unchecked arithmetic (pre-0.8)
- **Access control** - Missing modifiers, public sensitive functions
- **Unchecked returns** - Ignored call return values
- **Price manipulation** - Flash loan vulnerabilities

### 🔵 Medium

- **tx.origin authentication** - Phishing vulnerability
- **Floating pragma** - Inconsistent compiler versions
- **Timestamp dependence** - Miner manipulation
- **Front-running** - Transaction ordering attacks

### ⚪ Low

- **Unused variables** - Dead code
- **Missing events** - Poor transparency
- **Implicit visibility** - Unclear function access
- **Magic numbers** - Unexplained constants

## Gas Optimizations

```bash
solaudit gas Contract.sol
```

**Detects:**
- Storage vs memory misuse
- Redundant SLOAD operations
- Loop inefficiencies
- Uncached array length
- Use of `> 0` vs `!= 0`
- Missing `calldata` for external functions

## Example Output

```
═══════════════════════════════════════
  SOLAUDIT SECURITY REPORT
═══════════════════════════════════════

Contracts scanned: 3
Issues found: 5

🔴 CRITICAL (1)
───────────────────────────────────────
  Vault.sol:45 - Reentrancy vulnerability
  External call to untrusted address before state update
  
  Fix: Move state changes before external calls, use ReentrancyGuard

🟡 HIGH (2)  
───────────────────────────────────────
  Token.sol:23 - Unchecked transfer return value
  ERC20.transfer() return value not checked
  
  Fix: Use SafeERC20 or check return value

  Token.sol:67 - Missing access control on mint()
  Critical function accessible by anyone
  
  Fix: Add onlyOwner or role-based modifier

🔵 MEDIUM (2)
───────────────────────────────────────
  Vault.sol:12 - Use of tx.origin for authentication
  Vulnerable to phishing attacks
  
  Fix: Use msg.sender instead

  Token.sol:1 - Floating pragma
  pragma solidity ^0.8.0 allows different compiler versions
  
  Fix: Lock pragma to specific version
```

## CI/CD Integration

Exit codes for automated pipelines:

```bash
# Fail on critical issues
solaudit audit ./contracts/ -s critical && echo "Passed" || echo "Failed"

# GitHub Actions example
- name: Security Audit
  run: |
    npm install -g solaudit-cli
    solaudit audit ./contracts/ -r -s high
```

### GitHub Action Workflow

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g solaudit-cli
      - run: solaudit audit ./contracts/ -r -o markdown --save audit-report.md
      - uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.md
```

## Output Formats

```bash
# Table (default, terminal-friendly)
solaudit audit Contract.sol

# JSON (for parsing)
solaudit audit Contract.sol -o json

# Markdown (for documentation)
solaudit audit Contract.sol -o markdown --save AUDIT.md
```

## Use Cases

- **Pre-deployment review** - Catch issues before mainnet
- **CI/CD gates** - Block deploys with critical issues
- **Code review** - Automated security feedback
- **Learning** - Understand common vulnerabilities
- **Auditor toolkit** - Speed up manual audits

## Why solaudit?

| Feature | solaudit | Slither | Manual |
|---------|----------|---------|--------|
| Setup time | 1 min | 10+ min | N/A |
| No dependencies | ✅ | ❌ Python | ✅ |
| Beginner friendly | ✅ | ⚠️ | ❌ |
| CI/CD ready | ✅ | ✅ | ❌ |
| Actionable fixes | ✅ | ⚠️ | ✅ |

## ⚠️ Limitations

- Static analysis only (no runtime detection)
- Not a replacement for professional audits
- Use alongside manual review for production contracts

---

**Built by [LXGIC Studios](https://lxgicstudios.com)**

🔗 [GitHub](https://github.com/lxgicstudios/solaudit) · [Twitter](https://x.com/lxgicstudios) · [npm](https://www.npmjs.com/package/solaudit-cli)
