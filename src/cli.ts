#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { SolidityAuditor } from './auditor.js';
import { ReportGenerator } from './report.js';
import { glob } from 'glob';
import * as fs from 'fs';

const program = new Command();

program
  .name('solaudit')
  .description('Solidity smart contract security auditor')
  .version('0.1.0');

// Audit command
program
  .command('audit <path>')
  .description('Audit Solidity contracts')
  .option('-r, --recursive', 'Scan directories recursively')
  .option('-s, --severity <level>', 'Minimum severity: low, medium, high, critical', 'low')
  .option('--gas', 'Include gas optimization suggestions')
  .option('--best-practices', 'Include best practice checks')
  .option('-o, --output <format>', 'Output format: table, json, markdown', 'table')
  .option('--save <file>', 'Save report to file')
  .action(async (path, opts) => {
    const spinner = ora('Analyzing contracts...').start();
    try {
      let files: string[];
      
      if (fs.statSync(path).isDirectory()) {
        const pattern = opts.recursive ? `${path}/**/*.sol` : `${path}/*.sol`;
        files = await glob(pattern);
      } else {
        files = [path];
      }
      
      if (files.length === 0) {
        spinner.fail('No .sol files found');
        return;
      }
      
      spinner.text = `Auditing ${files.length} contract(s)...`;
      
      const auditor = new SolidityAuditor({
        minSeverity: opts.severity,
        includeGas: opts.gas,
        includeBestPractices: opts.bestPractices
      });
      
      const results = await auditor.auditFiles(files);
      spinner.succeed(`Audit complete: ${results.issues.length} issues found`);
      
      const reporter = new ReportGenerator(opts.output);
      const report = reporter.generate(results);
      console.log(report);
      
      if (opts.save) {
        fs.writeFileSync(opts.save, report);
        console.log(chalk.gray(`Report saved to ${opts.save}`));
      }
      
      // Exit with error if critical issues found
      if (results.issues.some(i => i.severity === 'critical')) {
        process.exit(1);
      }
    } catch (err: any) {
      spinner.fail(err.message);
      process.exit(1);
    }
  });

// Quick check
program
  .command('check <file>')
  .description('Quick security check on single file')
  .action(async (file) => {
    try {
      const auditor = new SolidityAuditor({ minSeverity: 'medium' });
      const content = fs.readFileSync(file, 'utf-8');
      const issues = auditor.analyzeContract(content, file);
      
      if (issues.length === 0) {
        console.log(chalk.green('✓ No major issues found'));
      } else {
        for (const issue of issues) {
          const color = issue.severity === 'critical' ? chalk.red 
            : issue.severity === 'high' ? chalk.yellow 
            : chalk.gray;
          console.log(color(`[${issue.severity.toUpperCase()}] ${issue.title}`));
          console.log(chalk.gray(`  Line ${issue.line}: ${issue.description}`));
        }
      }
    } catch (err: any) {
      console.error(chalk.red(err.message));
      process.exit(1);
    }
  });

// Patterns command
program
  .command('patterns')
  .description('List vulnerability patterns checked')
  .option('--category <cat>', 'Filter by category')
  .action((opts) => {
    const auditor = new SolidityAuditor({});
    const patterns = auditor.getPatterns();
    
    const filtered = opts.category 
      ? patterns.filter(p => p.category === opts.category)
      : patterns;
    
    console.log(chalk.bold('\nVulnerability Patterns:\n'));
    
    const categories = [...new Set(filtered.map(p => p.category))];
    for (const cat of categories) {
      console.log(chalk.cyan(`\n${cat.toUpperCase()}`));
      for (const p of filtered.filter(p => p.category === cat)) {
        const severityColor = p.severity === 'critical' ? chalk.red 
          : p.severity === 'high' ? chalk.yellow 
          : p.severity === 'medium' ? chalk.blue
          : chalk.gray;
        console.log(`  ${severityColor('●')} ${p.name} (${p.severity})`);
      }
    }
  });

// Gas analysis
program
  .command('gas <file>')
  .description('Gas optimization analysis')
  .action(async (file) => {
    const spinner = ora('Analyzing gas usage...').start();
    try {
      const auditor = new SolidityAuditor({ includeGas: true });
      const content = fs.readFileSync(file, 'utf-8');
      const analysis = auditor.analyzeGas(content);
      
      spinner.succeed('Gas analysis complete');
      
      console.log(chalk.bold('\nGas Optimization Opportunities:\n'));
      
      for (const item of analysis) {
        console.log(chalk.yellow(`⛽ ${item.title}`));
        console.log(chalk.gray(`   ${item.description}`));
        console.log(chalk.green(`   Potential savings: ${item.savings}`));
        console.log();
      }
    } catch (err: any) {
      spinner.fail(err.message);
      process.exit(1);
    }
  });

program.parse();
