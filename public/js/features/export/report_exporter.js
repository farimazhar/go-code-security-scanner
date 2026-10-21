/**
 * Report Exporter Service
 * Exports security scan diagnostics into Markdown, JSON, and Clipboard summaries.
 */
export class ReportExporter {
  /**
   * Generates a comprehensive Markdown audit report.
   */
  static generateMarkdown(response, filename = 'code.go') {
    const timestamp = new Date().toISOString();
    const { score, status, stats, findings } = response;

    let md = `# GoSentry Security Audit Report\n\n`;
    md += `**Target:** \`${filename}\`  \n`;
    md += `**Timestamp:** ${timestamp}  \n`;
    md += `**Overall Score:** **${score}/100** (\`${status}\`)  \n`;
    md += `**Lines Analyzed:** ${stats?.lines || 0}  \n`;
    md += `**Total Vulnerabilities Found:** ${findings?.length || 0}  \n\n`;

    md += `## 📊 Severity Metrics\n\n`;
    md += `- **Critical Issues:** ${stats?.critical_issues || 0}\n`;
    md += `- **High Issues:** ${stats?.high_issues || 0}\n`;
    md += `- **Medium Issues:** ${stats?.medium_issues || 0}\n`;
    md += `- **Low Issues:** ${stats?.low_issues || 0}\n\n`;

    md += `## 🔍 Detected Findings\n\n`;

    if (!findings || findings.length === 0) {
      md += `✅ **No critical security vulnerabilities detected.** The code is clean and adheres to security guidelines.\n\n`;
    } else {
      findings.forEach((f, idx) => {
        md += `### ${idx + 1}. [${f.severity}] ${f.title}\n\n`;
        md += `- **Rule ID:** \`${f.rule_id}\`\n`;
        md += `- **Line:** ${f.line || 'N/A'}\n`;
        if (f.snippet) {
          md += `- **Code:**\n  \`\`\`go\n  ${f.snippet}\n  \`\`\`\n`;
        }
        if (f.remedy) {
          md += `- **Remediation:** ${f.remedy}\n`;
        }
        md += `\n---\n\n`;
      });
    }

    md += `*Generated automatically by [GoSentry Security Scanner](https://github.com/farimazhar/go-code-security-scanner)*\n`;
    return md;
  }

  /**
   * Triggers download of a string as a file.
   */
  static downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Exports Markdown report as a downloaded file.
   */
  static exportMarkdown(response, filename = 'security-audit-report.md') {
    const md = this.generateMarkdown(response);
    this.downloadFile(md, filename, 'text/markdown;charset=utf-8');
  }

  /**
   * Exports JSON report as a downloaded file.
   */
  static exportJSON(response, filename = 'security-scan.json') {
    const jsonStr = JSON.stringify({
      timestamp: new Date().toISOString(),
      ...response
    }, null, 2);
    this.downloadFile(jsonStr, filename, 'application/json;charset=utf-8');
  }

  /**
   * Copies summary to clipboard.
   */
  static async copySummary(response) {
    const summary = `🛡️ GoSentry Scan Result: Score ${response.score}/100 [${response.status}] with ${response.findings?.length || 0} vulnerabilities found.`;
    await navigator.clipboard.writeText(summary);
  }
}
