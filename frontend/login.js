/**
 * Heimdall IDS Dashboard — Login page (RBAC-aware)
 */

const unInput   = document.getElementById('un');
const pwInput   = document.getElementById('pw');
const eyeBtn    = document.getElementById('eye-btn');
const submitBtn = document.getElementById('submit-btn');
const errorMsg  = document.getElementById('error-msg');

/* ── Toggle password visibility ── */
eyeBtn.addEventListener('click', () => {
  const show = pwInput.type === 'password';
  pwInput.type = show ? 'text' : 'password';
  eyeBtn.querySelector('svg').style.opacity = show ? '0.7' : '1';
});

/* ── Keyboard shortcuts ── */
unInput.addEventListener('keydown', e => { if (e.key === 'Enter') pwInput.focus(); });
pwInput.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
submitBtn.addEventListener('click', login);

/* ── Login handler ── */
async function login() {
  const username = unInput.value.trim();
  const password = pwInput.value;

  if (!username) { unInput.focus(); showError('Username is required.'); return; }
  if (!password) { pwInput.focus(); showError('Password is required.'); return; }

  setLoading(true);
  hideError();

  try {
    const res  = await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.ok && data.ok) {
      window.location.href = '/';
      return;
    }

    showError(data.error || 'Invalid username or password.');
    pwInput.value = '';
    pwInput.focus();
  } catch {
    showError('Connection error — is the server running?');
  }

  setLoading(false);
}

/* ── Helpers ── */
function setLoading(on) {
  submitBtn.disabled    = on;
  submitBtn.textContent = on ? 'Signing in…' : 'Sign in';
}

function showError(msg) {
  errorMsg.textContent   = msg;
  errorMsg.style.display = 'block';
}

function hideError() {
  errorMsg.style.display = 'none';
}
