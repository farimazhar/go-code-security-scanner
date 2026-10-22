import { scanCode, getHealthStatus } from './common/api.js';
import { $ } from './common/utils.js';
import { CodeEditorController } from './features/scanner/editor.js';
import { FileLoaderController } from './features/scanner/file_loader.js';
import { ScoreCardController } from './features/diagnostics/score_card.js';
import { FindingsViewController } from './features/diagnostics/findings_view.js';
import { QuickFixEngine } from './features/remediation/quick_fix.js';
import { ReportExporter } from './features/export/report_exporter.js';

/**
 * Main Application Orchestrator
 */
class GoSentryApp {
  constructor() {
    this.currentResponse = null;
    this.currentFilename = 'code.go';

    this.scoreCard = new ScoreCardController();

    this.editor = new CodeEditorController({
      onScanRequested: (code) => this.handleScan(code),
      onCleared: () => this.handleClear()
    });

    this.fileLoader = new FileLoaderController({
      onFileLoaded: (content, filename) => {
        this.currentFilename = filename;
        this.editor.setCode(content);
        this.editor.setActivePreset(null);
        this.handleScan(content);
      }
    });

    this.findingsView = new FindingsViewController({
      onLineJump: (line) => {
        this.editor.jumpToLine(line);
      },
      onQuickFix: (finding) => {
        this.handleQuickFix(finding);
      }
    });

    this.bindExportEvents();
    this.init();
  }

  async init() {
    try {
      const health = await getHealthStatus();
      const badge = $('#ruleCountBadge');
      if (badge && health.rules_count) {
        badge.textContent = `${health.rules_count} SAST Rules`;
      }
    } catch (_) {}

    // Load initial default preset
    this.editor.loadPreset('sqli');
  }

  async handleScan(code) {
    if (!code || !code.trim()) {
      this.handleClear();
      return;
    }

    this.editor.setLoading(true);

    try {
      const response = await scanCode(code);
      this.currentResponse = response;
      this.scoreCard.update(response);
      this.findingsView.render(response.findings || []);
    } catch (err) {
      alert(`Security scan failed: ${err.message}`);
    } finally {
      this.editor.setLoading(false);
    }
  }

  handleQuickFix(finding) {
    const currentCode = this.editor.getCode();
    const patchedCode = QuickFixEngine.applyFix(currentCode, finding);

    if (patchedCode && patchedCode !== currentCode) {
      this.editor.setCode(patchedCode);
      // Re-scan immediately to verify score improvement!
      this.handleScan(patchedCode);
    } else {
      alert(`Could not automatically apply fix for "${finding.title}". Please refer to the remediation instructions.`);
    }
  }

  handleClear() {
    this.currentResponse = null;
    this.fileLoader.setFileBadge(null);
    this.scoreCard.reset();
    this.findingsView.renderEmptyPrompt();
  }

  bindExportEvents() {
    $('#exportMdBtn')?.addEventListener('click', () => {
      if (!this.currentResponse) {
        alert('Please run a security scan first before exporting.');
        return;
      }
      ReportExporter.exportMarkdown(this.currentResponse, `gosentry-audit-${Date.now()}.md`);
    });

    $('#exportJsonBtn')?.addEventListener('click', () => {
      if (!this.currentResponse) {
        alert('Please run a security scan first before exporting.');
        return;
      }
      ReportExporter.exportJSON(this.currentResponse, `gosentry-audit-${Date.now()}.json`);
    });

    $('#copySummaryBtn')?.addEventListener('click', async () => {
      if (!this.currentResponse) {
        alert('Please run a security scan first.');
        return;
      }
      try {
        await ReportExporter.copySummary(this.currentResponse);
        const btn = $('#copySummaryBtn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<span>✅ Copied!</span>';
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      } catch (err) {
        alert('Failed to copy: ' + err.message);
      }
    });
  }
}

// Bootstrap Application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.__app = new GoSentryApp();
});
