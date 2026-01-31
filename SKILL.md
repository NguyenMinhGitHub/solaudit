---
name: Solidity Smart Contract Auditor
description: Audit Solidity smart contracts for vulnerabilities. Detect reentrancy, overflow, access control issues. AI-powered security analysis. Free CLI tool.
tags: [solidity, smart-contract, security, audit, ethereum, blockchain, defi]
---

# Solidity Smart Contract Auditor

Scan Solidity contracts for security vulnerabilities.

**Reentrancy. Overflow. Access control. All the classics.**

## Quick Start

```bash
npm install -g solaudit-cli
```

```bash
# Audit a contract
solaudit ./contracts/Token.sol

# Audit entire project
solaudit ./contracts/

# Get detailed report
solaudit ./Token.sol --verbose
```

## What It Detects

### Critical
- Reentrancy vulnerabilities
- Integer overflow/underflow
- Unchecked external calls
- Delegatecall injection

### High
- Access control issues
- tx.origin authentication
- Front-running vulnerabilities
- Flashloan attacks

### Medium
- Gas optimization issues
- Floating pragma
- Missing zero-address checks
- Unused return values

### Low
- Style issues
- Naming conventions
- Documentation gaps

## Commands

```bash
# Quick scan
solaudit ./contract.sol

# Full audit with gas analysis
solaudit ./contract.sol --full

# Export report
solaudit ./contract.sol -o report.md

# JSON output for CI/CD
solaudit ./contract.sol --json
```

## CI/CD Integration

```yaml
# GitHub Actions
- run: npx solaudit-cli ./contracts/ --json > audit.json
```

## When to Use This

- Before mainnet deployment
- Code review process
- Security audits
- Learning Solidity best practices
- DeFi protocol analysis

## Supported Solidity Versions

0.4.x through 0.8.x

---

**Built by [LXGIC Studios](https://lxgicstudios.com)**

🔗 [GitHub](https://github.com/lxgicstudios/solaudit) · [Twitter](https://x.com/lxgicstudios)
