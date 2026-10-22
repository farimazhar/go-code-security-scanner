/**
 * App Theme Color Tokens
 * Centralized theme colors for dynamic canvas/SVG rendering and UI components (White & Violet Theme).
 */
export const AppColors = {
  bgDark: '#f8fafc',
  bgDeep: '#ffffff',
  primary: '#7c3aed',
  accentCyan: '#d946ef',

  // Status and Severity Colors
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  safe: '#059669',

  // Text Colors
  textMain: '#0f172a',
  textMuted: '#64748b',

  // Status mapping
  forStatus(status) {
    switch (status) {
      case 'SAFE':
        return this.safe;
      case 'RISKY':
        return this.medium;
      case 'UNSAFE':
        return this.critical;
      default:
        return this.textMuted;
    }
  },

  forSeverity(severity) {
    switch (severity) {
      case 'CRITICAL':
        return this.critical;
      case 'HIGH':
        return this.high;
      case 'MEDIUM':
        return this.medium;
      case 'LOW':
        return this.primary;
      default:
        return this.textMuted;
    }
  }
};
