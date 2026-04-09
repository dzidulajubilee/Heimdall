/**
 * Heimdall — Login page logic
 */

const pwInput  = document.getElementById('pw');
const eyeBtn   = document.getElementById('eye-btn');
const submitBtn = document.getElementById('submit-btn');
const errorMsg  = document.getElementById('error-msg');

// Toggle password visibility
eyeBtn.addEventListener('click', () => {
  pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
});

// Submit on Enter
pwInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') login();
});

submitBtn.addEventListener('click', login);

async function login() {
  const pw = pwInput.value.trim();
  if (!pw) { pwInput.focus(); return; }

  submitBtn.disabled   = true;
  submitBtn.textContent = 'Signing in…';
  errorMsg.style.display = 'none';

  try {
    const res  = await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ password: pw }),
    });
    const data = await res.json();

    if (res.ok && data.ok) {
      window.location.href = '/';
      return;
    }

    showError(data.error || 'Invalid password');
    pwInput.value = '';
    pwInput.focus();
  } catch {
    showError('Connection error — is the server running?');
  }

  submitBtn.disabled    = false;
  submitBtn.textContent = 'Sign in';
}

function showError(msg) {
  errorMsg.textContent   = msg;
  errorMsg.style.display = 'block';
}
