const AUTH_TOKEN_KEYS = [
  'token',
  'authToken',
  'accessToken',
  'primevpn-token',
  'primevpn.auth.token',
] as const;

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;

  for (const key of AUTH_TOKEN_KEYS) {
    const value = window.localStorage.getItem(key) || window.sessionStorage.getItem(key);
    if (value) return value;
  }

  return null;
}

export function setAuthToken(token: string) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem('token', token);
}

export function removeAuthToken() {
  if (typeof window === 'undefined') return;

  for (const key of AUTH_TOKEN_KEYS) {
    window.localStorage.removeItem(key);
    window.sessionStorage.removeItem(key);
  }
}
