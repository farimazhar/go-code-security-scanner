/**
 * Scan API Client
 * Centralized service for communicating with the GoSentry backend.
 */
export async function scanCode(code) {
  if (!code || !code.trim()) {
    throw new Error('Code payload cannot be empty');
  }

  const response = await fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ code })
  });

  if (!response.ok) {
    let errorMsg = `Server error (HTTP ${response.status})`;
    try {
      const errData = await response.json();
      if (errData.error) errorMsg = errData.error;
    } catch (_) {}
    throw new Error(errorMsg);
  }

  return await response.json();
}

/**
 * Fetch health & scanner status
 */
export async function getHealthStatus() {
  const response = await fetch('/health');
  if (!response.ok) {
    throw new Error(`Health check failed (HTTP ${response.status})`);
  }
  return await response.json();
}
