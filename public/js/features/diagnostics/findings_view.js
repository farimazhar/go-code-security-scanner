import { $, escapeHtml } from '../../common/utils.js';

/**
 * Controller for rendering the Security Findings list with Quick Fix and Line Jump capabilities.
 */
export class FindingsViewController {
  constructor({ onLineJump, onQuickFix } = {}) {
    this.containerEl = $('#findingsContainer');
    this.onLineJump = onLineJump;
    this.onQuickFix = onQuickFix;
  }

  render(findings = []) {
    if (!this.containerEl) return;
    this.containerEl.innerHTML = '';

    if (!findings || findings.length === 0) {
      this.renderCleanState();
      return;
    }

    findings.forEach((f, index) => {
      const card = document.createElement('div');
      card.className = `finding-card sev-${f.severity || 'LOW'}`;

      let sevTagClass = 'tag-critical';
      if (f.severity === 'HIGH') sevTagClass = 'tag-high';
      if (f.severity === 'MEDIUM') sevTagClass = 'tag-medium';

      const hasFix = !!(f.fix_target || ['insecure_tls', 'weak_crypto', 'unbounded_read', 'weak_random'].includes(f.rule_id));

      card.innerHTML = `
        <div class="finding-header">
          <span class="finding-title">${escapeHtml(f.title || f.description)}</span>
          <div class="finding-tags">
            <span class="tag ${sevTagClass}">${escapeHtml(f.severity)}</span>
            <button class="tag tag-line jump-btn" title="Jump to Line in Editor" data-line="${f.line || 1}">
              📍 Line ${f.line || 1}
            </button>
          </div>
        </div>
        ${f.snippet ? `<div class="finding-snippet">${escapeHtml(f.snippet)}</div>` : ''}
        ${f.remedy ? `<div class="finding-remedy">💡 <strong>Remediation:</strong> ${escapeHtml(f.remedy)}</div>` : ''}
        <div class="finding-actions">
          <button class="action-link jump-action" data-line="${f.line || 1}">
            🎯 Jump to Code
          </button>
          ${hasFix ? `
            <button class="action-link fix-action" data-index="${index}">
              ✨ Apply Quick Fix
            </button>
          ` : ''}
        </div>
      `;

      // Wire Jump Button
      card.querySelectorAll('.jump-btn, .jump-action').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const line = parseInt(btn.dataset.line, 10);
          if (this.onLineJump) this.onLineJump(line);
        });
      });

      // Wire Quick Fix Button
      const fixBtn = card.querySelector('.fix-action');
      if (fixBtn) {
        fixBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (this.onQuickFix) this.onQuickFix(f);
        });
      }

      this.containerEl.appendChild(card);
    });
  }

  renderCleanState() {
    if (!this.containerEl) return;
    this.containerEl.innerHTML = `
      <div class="empty-state">
        <span class="empty-state-icon" style="color: var(--safe);">✅</span>
        <h3 style="color: #fff; margin-bottom: 0.4rem;">Codebase is Clean!</h3>
        <p>No critical security vulnerabilities or risky coding patterns were identified.</p>
      </div>`;
  }

  renderEmptyPrompt() {
    if (!this.containerEl) return;
    this.containerEl.innerHTML = `
      <div class="empty-state">
        <span class="empty-state-icon">🛡️</span>
        <p>Paste Go code and click <strong>Scan Code Now</strong> to inspect for security vulnerabilities.</p>
      </div>`;
  }
}
