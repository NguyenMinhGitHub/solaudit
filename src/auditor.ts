import * as fs from 'fs';

interface AuditOptions {
  minSeverity?: string;
  includeGas?: boolean;
  includeBestPractices?: boolean;
}

interface Issue {
  file: string;
  line: number;
  severity: string;
  category: string;
  title: string;
  description: string;
  recommendation: string;
  code?: string;
}

interface AuditResult {
  files: string[];
  issues: Issue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    gas: number;
  };
}

interface VulnPattern {
  name: string;
  category: string;
  severity: string;
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const VULNERABILITY_PATTERNS: VulnPattern[] = [
  // Reentrancy
  {
    name: 'Reentrancy',
    category: 'security',
    severity: 'critical',
    pattern: /\.call\{.*value.*\}\s*\(|\.call\.value\s*\(/g,
    description: 'External call before state update may allow reentrancy',
    recommendation: 'Use checks-effects-interactions pattern or ReentrancyGuard'
  },
  // Unchecked return value
  {
    name: 'Unchecked Return Value',
    category: 'security',
    severity: 'high',
    pattern: /\.(call|send|transfer)\s*\([^)]*\)\s*;(?!\s*require)/g,
    description: 'Return value of low-level call not checked',
    recommendation: 'Check return value: require(success, "Call failed")'
  },
  // tx.origin
  {
    name: 'tx.origin Authentication',
    category: 'security',
    severity: 'high',
    pattern: /tx\.origin\s*==|require\s*\(\s*tx\.origin/g,
    description: 'Using tx.origin for authentication is vulnerable to phishing',
    recommendation: 'Use msg.sender instead of tx.origin'
  },
  // Floating pragma
  {
    name: 'Floating Pragma',
    category: 'best-practice',
    severity: 'low',
    pattern: /pragma\s+solidity\s*\^/g,
    description: 'Using floating pragma allows different compiler versions',
    recommendation: 'Lock pragma to specific version: pragma solidity 0.8.20;'
  },
  // Unprotected selfdestruct
  {
    name: 'Unprotected Selfdestruct',
    category: 'security',
    severity: 'critical',
    pattern: /selfdestruct\s*\(|suicide\s*\(/g,
    description: 'selfdestruct can be called, potentially destroying contract',
    recommendation: 'Add access control or remove selfdestruct'
  },
  // Integer overflow (pre-0.8)
  {
    name: 'Potential Integer Overflow',
    category: 'security',
    severity: 'high',
    pattern: /pragma\s+solidity\s*[\^~]?0\.[0-7]\./g,
    description: 'Solidity < 0.8 requires SafeMath for overflow protection',
    recommendation: 'Upgrade to Solidity 0.8+ or use SafeMath'
  },
  // Delegatecall
  {
    name: 'Dangerous Delegatecall',
    category: 'security',
    severity: 'critical',
    pattern: /delegatecall\s*\(/g,
    description: 'Delegatecall can execute arbitrary code in caller context',
    recommendation: 'Validate target address, avoid user-controlled delegatecall'
  },
  // Timestamp dependence
  {
    name: 'Timestamp Dependence',
    category: 'security',
    severity: 'medium',
    pattern: /block\.timestamp|now/g,
    description: 'block.timestamp can be manipulated by miners',
    recommendation: 'Avoid using for critical logic, use block.number for intervals'
  },
  // Weak randomness
  {
    name: 'Weak Randomness',
    category: 'security',
    severity: 'high',
    pattern: /keccak256\s*\([^)]*block\.(timestamp|number|difficulty|prevrandao)/g,
    description: 'Block variables are predictable, not suitable for randomness',
    recommendation: 'Use Chainlink VRF or commit-reveal scheme'
  },
  // Missing zero address check
  {
    name: 'Missing Zero Address Check',
    category: 'best-practice',
    severity: 'medium',
    pattern: /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?:public|external)[^{]*\{(?![^}]*require\s*\([^)]*!=\s*address\(0\))/g,
    description: 'Address parameters not validated for zero address',
    recommendation: 'Add require(addr != address(0), "Zero address")'
  },
  // Assembly usage
  {
    name: 'Inline Assembly',
    category: 'security',
    severity: 'medium',
    pattern: /assembly\s*\{/g,
    description: 'Inline assembly bypasses Solidity safety checks',
    recommendation: 'Document thoroughly and review carefully'
  },
  // Force ether
  {
    name: 'Force Send Ether',
    category: 'security',
    severity: 'medium',
    pattern: /this\.balance|address\(this\)\.balance/g,
    description: 'Contract balance can be manipulated via selfdestruct',
    recommendation: 'Track deposits with internal accounting'
  },
  // Private visibility misconception
  {
    name: 'Private State Variable',
    category: 'best-practice',
    severity: 'low',
    pattern: /private\s+\w+\s+\w+\s*=/g,
    description: 'Private variables are still readable on-chain',
    recommendation: 'Never store secrets in contract storage'
  },
  // Missing events
  {
    name: 'Missing Event Emission',
    category: 'best-practice',
    severity: 'low',
    pattern: /function\s+\w+\s*\([^)]*\)\s*(?:public|external)[^}]*\b(owner|admin)\s*=/g,
    description: 'State changes should emit events for off-chain tracking',
    recommendation: 'Add event emissions for important state changes'
  },
  // Uninitialized storage pointer
  {
    name: 'Uninitialized Storage Pointer',
    category: 'security',
    severity: 'high',
    pattern: /\bstruct\s+\w+\s+storage\s+\w+\s*;/g,
    description: 'Uninitialized storage pointers can overwrite storage',
    recommendation: 'Initialize storage pointers or use memory'
  }
];

const GAS_PATTERNS = [
  {
    title: 'Use immutable for constants set in constructor',
    pattern: /public\s+(\w+)\s+(\w+)\s*;(?=[^}]*constructor[^}]*\2\s*=)/g,
    description: 'Variables set once in constructor can be immutable',
    savings: '~2100 gas per read'
  },
  {
    title: 'Cache array length in loops',
    pattern: /for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;/g,
    description: 'Reading array.length in each iteration costs extra gas',
    savings: '~100 gas per iteration'
  },
  {
    title: 'Use ++i instead of i++',
    pattern: /\w+\+\+(?!\s*\))|(?<!\()\+\+\w+/g,
    description: 'Pre-increment is cheaper than post-increment',
    savings: '~5 gas per operation'
  },
  {
    title: 'Use calldata for external function arrays',
    pattern: /function\s+\w+\s*\([^)]*\[\]\s+memory/g,
    description: 'calldata is cheaper than memory for read-only arrays',
    savings: '~600 gas per call'
  },
  {
    title: 'Pack struct variables',
    pattern: /struct\s+\w+\s*\{[^}]*uint256[^}]*uint8[^}]*uint256/g,
    description: 'Group smaller types together to use fewer storage slots',
    savings: '~20000 gas per slot saved'
  },
  {
    title: 'Use custom errors instead of strings',
    pattern: /require\s*\([^,]+,\s*"[^"]+"\)/g,
    description: 'Custom errors are cheaper than string messages',
    savings: '~50 gas per error'
  },
  {
    title: 'Avoid zero to non-zero storage writes',
    pattern: /(\w+)\s*=\s*0\s*;[^}]*\1\s*=/g,
    description: 'Setting storage from 0 to non-zero is expensive',
    savings: '~20000 gas difference'
  },
  {
    title: 'Use unchecked for safe arithmetic',
    pattern: /for\s*\([^)]*\)\s*\{(?![^}]*unchecked)/g,
    description: 'Loop counters rarely overflow, can use unchecked',
    savings: '~30 gas per operation'
  }
];

export class SolidityAuditor {
  private options: AuditOptions;
  private severityOrder = ['low', 'medium', 'high', 'critical'];
  
  constructor(options: AuditOptions) {
    this.options = options;
  }
  
  async auditFiles(files: string[]): Promise<AuditResult> {
    const allIssues: Issue[] = [];
    
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      const issues = this.analyzeContract(content, file);
      allIssues.push(...issues);
    }
    
    // Filter by severity
    const minIdx = this.severityOrder.indexOf(this.options.minSeverity || 'low');
    const filtered = allIssues.filter(i => 
      this.severityOrder.indexOf(i.severity) >= minIdx
    );
    
    return {
      files,
      issues: filtered,
      summary: {
        critical: filtered.filter(i => i.severity === 'critical').length,
        high: filtered.filter(i => i.severity === 'high').length,
        medium: filtered.filter(i => i.severity === 'medium').length,
        low: filtered.filter(i => i.severity === 'low').length,
        gas: filtered.filter(i => i.category === 'gas').length
      }
    };
  }
  
  analyzeContract(content: string, file: string): Issue[] {
    const issues: Issue[] = [];
    const lines = content.split('\n');
    
    for (const pattern of VULNERABILITY_PATTERNS) {
      // Skip best-practice if not requested
      if (pattern.category === 'best-practice' && !this.options.includeBestPractices) {
        continue;
      }
      
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
      let match;
      
      while ((match = regex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        const lineContent = lines[lineNum - 1]?.trim() || '';
        
        issues.push({
          file,
          line: lineNum,
          severity: pattern.severity,
          category: pattern.category,
          title: pattern.name,
          description: pattern.description,
          recommendation: pattern.recommendation,
          code: lineContent
        });
      }
    }
    
    // Add gas analysis if requested
    if (this.options.includeGas) {
      const gasIssues = this.analyzeGas(content).map(g => ({
        file,
        line: 0,
        severity: 'low',
        category: 'gas',
        title: g.title,
        description: g.description,
        recommendation: `Potential savings: ${g.savings}`
      }));
      issues.push(...gasIssues);
    }
    
    return issues;
  }
  
  analyzeGas(content: string): { title: string; description: string; savings: string }[] {
    const findings: { title: string; description: string; savings: string }[] = [];
    
    for (const pattern of GAS_PATTERNS) {
      if (pattern.pattern.test(content)) {
        findings.push({
          title: pattern.title,
          description: pattern.description,
          savings: pattern.savings
        });
      }
    }
    
    return findings;
  }
  
  getPatterns(): { name: string; category: string; severity: string }[] {
    return VULNERABILITY_PATTERNS.map(p => ({
      name: p.name,
      category: p.category,
      severity: p.severity
    }));
  }
}
