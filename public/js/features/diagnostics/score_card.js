import { $ } from '../../common/utils.js';
import { AppColors } from '../../app_theme/colors.js';

/**
 * Controller for the Score Card & Metrics display.
 */
export class ScoreCardController {
  constructor() {
    this.scoreNumEl = $('#scoreNum');
    this.statusBadgeEl = $('#statusBadge');
    this.linesCountEl = $('#linesCount');
    this.critValEl = $('#critVal');
    this.highValEl = $('#highVal');
    this.medValEl = $('#medVal');
    this.totalValEl = $('#totalVal');
  }

  update(response) {
    if (!response) {
      this.reset();
      return;
    }

    const { score, status, stats, findings } = response;

    // Update score number and color
    if (this.scoreNumEl) {
      this.scoreNumEl.textContent = score !== undefined ? score : '--';
      this.scoreNumEl.style.color = AppColors.forStatus(status);
    }

    // Update status badge
    if (this.statusBadgeEl) {
      this.statusBadgeEl.textContent = status || 'READY';
      this.statusBadgeEl.className = `status-badge status-${(status || 'safe').toLowerCase()}`;
    }

    // Update metric counters
    if (this.linesCountEl) this.linesCountEl.textContent = stats?.lines ?? 0;
    if (this.critValEl) this.critValEl.textContent = stats?.critical_issues ?? 0;
    if (this.highValEl) this.highValEl.textContent = stats?.high_issues ?? 0;
    if (this.medValEl) this.medValEl.textContent = stats?.medium_issues ?? 0;
    if (this.totalValEl) this.totalValEl.textContent = findings?.length ?? 0;
  }

  reset() {
    if (this.scoreNumEl) {
      this.scoreNumEl.textContent = '--';
      this.scoreNumEl.style.color = AppColors.textMain;
    }
    if (this.statusBadgeEl) {
      this.statusBadgeEl.textContent = 'READY';
      this.statusBadgeEl.className = 'status-badge status-safe';
    }
    if (this.linesCountEl) this.linesCountEl.textContent = '0';
    if (this.critValEl) this.critValEl.textContent = '0';
    if (this.highValEl) this.highValEl.textContent = '0';
    if (this.medValEl) this.medValEl.textContent = '0';
    if (this.totalValEl) this.totalValEl.textContent = '0';
  }
}
