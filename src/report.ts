import Table from 'cli-table3';
import chalk from 'chalk';

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

export class ReportGenerator {
  private format: string;
  
  constructor(format: string) {
    this.format = format;
  }
  
  generate(result: AuditResult): string {
    switch (this.format) {
      case 'json':
        return JSON.stringify(result, null, 2);
      case 'markdown':
        return this.toMarkdown(result);
      case 'table':
      default:
        return this.toTable(result);
    }
  }
  
  private toTable(result: AuditResult): string {
    const output: string[] = [];
    
    // Summary
    output.push(chalk.bold('\n📋 Audit Summary\n'));
    
    const summaryTable = new Table({
      head: [
        chalk.red('Critical'),
        chalk.yellow('High'),
        chalk.blue('Medium'),
        chalk.gray('Low'),
        chalk.green('Gas')
      ]
    });
    
    summaryTable.push([
      result.summary.critical,
      result.summary.high,
      result.summary.medium,
      result.summary.low,
      result.summary.gas
    ]);
    
    output.push(summaryTable.toString());
    
    // Issues by severity
    if (result.issues.length > 0) {
      output.push(chalk.bold('\n🔍 Issues Found\n'));
      
      const severities = ['critical', 'high', 'medium', 'low'];
      
      for (const sev of severities) {
        const sevIssues = result.issues.filter(i => i.severity === sev);
        if (sevIssues.length === 0) continue;
        
        const color = sev === 'critical' ? chalk.red 
          : sev === 'high' ? chalk.yellow 
          : sev === 'medium' ? chalk.blue
          : chalk.gray;
        
        output.push(color(`\n━━━ ${sev.toUpperCase()} (${sevIssues.length}) ━━━`));
        
        for (const issue of sevIssues) {
          output.push(`\n${color('●')} ${chalk.bold(issue.title)}`);
          output.push(chalk.gray(`  File: ${issue.file}:${issue.line}`));
          output.push(`  ${issue.description}`);
          if (issue.code) {
            output.push(chalk.dim(`  Code: ${issue.code.slice(0, 60)}...`));
          }
          output.push(chalk.green(`  ✓ ${issue.recommendation}`));
        }
      }
    } else {
      output.push(chalk.green('\n✓ No security issues found!'));
    }
    
    return output.join('\n');
  }
  
  private toMarkdown(result: AuditResult): string {
    const lines: string[] = [];
    
    lines.push('# Smart Contract Security Audit Report');
    lines.push('');
    lines.push(`**Files Analyzed:** ${result.files.length}`);
    lines.push(`**Issues Found:** ${result.issues.length}`);
    lines.push('');
    
    // Summary table
    lines.push('## Summary');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    lines.push(`| 🟠 High | ${result.summary.high} |`);
    lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
    lines.push(`| ⚪ Low | ${result.summary.low} |`);
    lines.push(`| ⛽ Gas | ${result.summary.gas} |`);
    lines.push('');
    
    // Files
    lines.push('## Files Analyzed');
    lines.push('');
    for (const file of result.files) {
      lines.push(`- \`${file}\``);
    }
    lines.push('');
    
    // Issues
    if (result.issues.length > 0) {
      lines.push('## Findings');
      lines.push('');
      
      const severities = ['critical', 'high', 'medium', 'low'];
      
      for (const sev of severities) {
        const sevIssues = result.issues.filter(i => i.severity === sev);
        if (sevIssues.length === 0) continue;
        
        const emoji = sev === 'critical' ? '🔴' 
          : sev === 'high' ? '🟠'
          : sev === 'medium' ? '🟡'
          : '⚪';
        
        lines.push(`### ${emoji} ${sev.charAt(0).toUpperCase() + sev.slice(1)} Severity`);
        lines.push('');
        
        for (let i = 0; i < sevIssues.length; i++) {
          const issue = sevIssues[i];
          lines.push(`#### ${i + 1}. ${issue.title}`);
          lines.push('');
          lines.push(`**Location:** \`${issue.file}:${issue.line}\``);
          lines.push('');
          lines.push(`**Description:** ${issue.description}`);
          lines.push('');
          if (issue.code) {
            lines.push('```solidity');
            lines.push(issue.code);
            lines.push('```');
            lines.push('');
          }
          lines.push(`**Recommendation:** ${issue.recommendation}`);
          lines.push('');
        }
      }
    }
    
    return lines.join('\n');
  }
}
