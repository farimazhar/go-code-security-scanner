/**
 * Quick-Fix Remediation Engine
 * Automatically rewrites insecure Go code snippets into secure, idiomatic patterns.
 */
export class QuickFixEngine {
  /**
   * Applies a safe fix for a given finding to the current source code.
   * @param {string} code - The current Go source code.
   * @param {object} finding - The finding object from the scan response.
   * @returns {string|null} - The patched code, or null if no fix could be applied.
   */
  static applyFix(code, finding) {
    if (!code || !finding) return null;

    // 1. Direct Fix Target & Replace from backend
    if (finding.fix_target && finding.fix_replace && code.includes(finding.fix_target)) {
      return code.replace(finding.fix_target, finding.fix_replace);
    }

    // 2. Rule-Specific Contextual Fixes
    switch (finding.rule_id) {
      case 'insecure_tls':
        if (code.includes('InsecureSkipVerify: true')) {
          return code.replace('InsecureSkipVerify: true', 'InsecureSkipVerify: false');
        }
        break;

      case 'weak_crypto':
        let updated = code;
        if (updated.includes('md5.New()')) {
          updated = updated.replace('md5.New()', 'sha256.New()');
          updated = updated.replace('"crypto/md5"', '"crypto/sha256"');
          return updated;
        }
        if (updated.includes('sha1.New()')) {
          updated = updated.replace('sha1.New()', 'sha256.New()');
          updated = updated.replace('"crypto/sha1"', '"crypto/sha256"');
          return updated;
        }
        break;

      case 'unbounded_read':
        if (code.includes('io.ReadAll(r.Body)')) {
          return code.replace('io.ReadAll(r.Body)', 'io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit');
        }
        if (code.includes('ioutil.ReadAll(r.Body)')) {
          return code.replace('ioutil.ReadAll(r.Body)', 'io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit');
        }
        break;

      case 'weak_random':
        if (code.includes('"math/rand"')) {
          return code.replace('"math/rand"', '"crypto/rand"');
        }
        break;

      case 'sql_concat':
        // Try replacing " + " inside db query with comma
        if (finding.snippet && code.includes(finding.snippet)) {
          const patchedSnippet = finding.snippet.replace(' + ', ', ');
          return code.replace(finding.snippet, patchedSnippet);
        }
        break;

      default:
        break;
    }

    return null;
  }
}
