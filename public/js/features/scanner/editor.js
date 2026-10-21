import { $, $$ } from '../../common/utils.js';
import { ScannerPresets } from './presets.js';

/**
 * Controller for the Code Editor feature component.
 */
export class CodeEditorController {
  constructor({ onScanRequested, onCleared }) {
    this.editorEl = $('#codeEditor');
    this.scanBtn = $('#scanBtn');
    this.clearBtn = $('#clearBtn');
    this.presetBtns = $$('.pill-btn');
    this.onScanRequested = onScanRequested;
    this.onCleared = onCleared;

    this.bindEvents();
  }

  bindEvents() {
    this.scanBtn?.addEventListener('click', () => {
      const code = this.getCode();
      if (this.onScanRequested) this.onScanRequested(code);
    });

    this.clearBtn?.addEventListener('click', () => {
      this.clear();
      if (this.onCleared) this.onCleared();
    });

    this.presetBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const presetKey = btn.dataset.preset;
        this.loadPreset(presetKey);
      });
    });

    // Keyboard shortcut: Ctrl+Enter / Cmd+Enter to run scan
    this.editorEl?.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        const code = this.getCode();
        if (this.onScanRequested) this.onScanRequested(code);
      }
    });
  }

  getCode() {
    return this.editorEl?.value || '';
  }

  setCode(code) {
    if (this.editorEl) {
      this.editorEl.value = code;
    }
  }

  loadPreset(key) {
    const code = ScannerPresets[key];
    if (code !== undefined) {
      this.setCode(code);
      this.setActivePreset(key);
      if (this.onScanRequested) this.onScanRequested(code);
    }
  }

  setActivePreset(activeKey) {
    this.presetBtns.forEach(btn => {
      if (btn.dataset.preset === activeKey) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
  }

  clear() {
    this.setCode('');
    this.setActivePreset(null);
  }

  setLoading(isLoading) {
    if (!this.scanBtn) return;
    this.scanBtn.disabled = isLoading;
    if (isLoading) {
      this.scanBtn.innerHTML = '<span>Analyzing Code...</span> ⏳';
    } else {
      this.scanBtn.innerHTML = '<span>Scan Code Now</span> 🔍';
    }
  }

  /**
   * Highlights and scrolls to the specified line number in the editor.
   */
  jumpToLine(targetLine) {
    if (!this.editorEl || !targetLine || targetLine < 1) return;

    const lines = this.editorEl.value.split('\n');
    if (targetLine > lines.length) return;

    let startPos = 0;
    for (let i = 0; i < targetLine - 1; i++) {
      startPos += lines[i].length + 1; // +1 for the \n
    }
    const endPos = startPos + lines[targetLine - 1].length;

    this.editorEl.focus();
    this.editorEl.setSelectionRange(startPos, endPos);

    // Calculate approximate scroll offset based on line height (~24px)
    const lineHeight = 24;
    const targetScroll = Math.max(0, (targetLine - 3) * lineHeight);
    this.editorEl.scrollTop = targetScroll;
  }
}
