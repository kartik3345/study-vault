/* ═══════════════════════════════════════════
   STUDYVAULT — APP.JS
   Full secure student file storage system
   ═══════════════════════════════════════════ */

'use strict';

/* ══════════════════════════════
   SECURITY UTILITIES
   ══════════════════════════════ */

/** Simple hash function (FNV-1a variant for client-side demo) */
function hashPassword(password) {
  const salt = 'sv_salt_2024_$ecure!';
  let str = salt + password;
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    hash = hash >>> 0;
  }
  // Second pass for added security
  let hash2 = 0;
  for (let i = 0; i < str.length; i++) {
    hash2 = ((hash2 << 5) - hash2) + str.charCodeAt(i);
    hash2 |= 0;
  }
  return (hash.toString(16).padStart(8,'0') + Math.abs(hash2).toString(16).padStart(8,'0'));
}

/** Generate unique user ID */
function generateUID() {
  return 'uid_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
}

/** Validate username format */
function isValidUsername(u) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(u);
}

/** Password strength: returns 0-4 */
function checkPasswordStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 4);
}

/* ══════════════════════════════
   DATA STORE (IndexedDB & localStorage)
   ══════════════════════════════ */
const IDBWrapper = {
  dbName: 'MaterialStoreDB',
  dbVersion: 1,
  storeName: 'files',
  
  init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);
      request.onerror = (event) => reject('Database error: ' + event.target.errorCode);
      request.onsuccess = (event) => resolve(event.target.result);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };
    });
  },
  
  async get(key) {
    const db = await this.init();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get(key);
      request.onerror = () => reject('Error getting data');
      request.onsuccess = (event) => resolve(event.target.result);
    });
  },
  
  async set(key, value) {
    const db = await this.init();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(value, key);
      request.onerror = () => reject('Error saving data');
      request.onsuccess = () => resolve();
    });
  }
};

const DB = {
  KEY_USERS:   'sv_users',
  KEY_SESSION: 'sv_session',
  KEY_FILES:   'sv_files_',

  getUsers() {
    try { return JSON.parse(localStorage.getItem(this.KEY_USERS)) || {}; } catch { return {}; }
  },
  saveUsers(users) {
    localStorage.setItem(this.KEY_USERS, JSON.stringify(users));
  },
  getSession() {
    try { return JSON.parse(sessionStorage.getItem(this.KEY_SESSION)); } catch { return null; }
  },
  saveSession(user) {
    sessionStorage.setItem(this.KEY_SESSION, JSON.stringify(user));
  },
  clearSession() {
    sessionStorage.removeItem(this.KEY_SESSION);
  },
  async getFiles(uid) {
    try { 
      const data = await IDBWrapper.get(this.KEY_FILES + uid);
      return data || []; 
    } catch { return []; }
  },
  async saveFiles(uid, files) {
    try {
      await IDBWrapper.set(this.KEY_FILES + uid, files);
    } catch (e) { console.error('IndexedDB save error', e); }
  },
  async getReminders(uid) {
    try { 
      const data = await IDBWrapper.get('sv_rems_' + uid);
      return data || []; 
    } catch { return []; }
  },
  async saveReminders(uid, rems) {
    try {
      await IDBWrapper.set('sv_rems_' + uid, rems);
    } catch (e) { console.error('IndexedDB save error', e); }
  }
};

/* ══════════════════════════════
   STATE
   ══════════════════════════════ */
let state = {
  currentUser: null,
  files: [],
  filteredFiles: [],
  reminders: [],
  currentFilter: 'all',
  currentSort: 'date-desc',
  currentView: 'grid',
  pendingFiles: [],   // files queued for upload
  deleteTarget: null, // file ID pending deletion
  currentOtp: null,
  currentOtpUser: null
};

/* ══════════════════════════════
   THEME INIT
   ══════════════════════════════ */
function initTheme() {
  const theme = localStorage.getItem('sv_theme') || 'light';
  document.documentElement.setAttribute('data-theme', theme);
  const text = document.getElementById('theme-text');
  if (text) text.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}
initTheme();

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('sv_theme', newTheme);
  const text = document.getElementById('theme-text');
  if (text) text.textContent = newTheme === 'dark' ? 'Light Mode' : 'Dark Mode';
  document.getElementById('user-context-menu').classList.add('hidden');
}

/* ══════════════════════════════
   CRYPTO UTILITIES (E2EE)
   ══════════════════════════════ */
const E2EE = {
  async deriveKey(password) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
    );
    const salt = encoder.encode('StudyVault_Salt_2026');
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },
  async generateMasterKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },
  async encryptMasterKey(masterKey, password) {
    const derivedKey = await this.deriveKey(password);
    const exportedMaster = await crypto.subtle.exportKey('raw', masterKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, exportedMaster);
    return {
      ciphertext: Array.from(new Uint8Array(ciphertext)),
      iv: Array.from(iv)
    };
  },
  async decryptMasterKey(encryptedData, password) {
    const derivedKey = await this.deriveKey(password);
    const iv = new Uint8Array(encryptedData.iv);
    const ciphertext = new Uint8Array(encryptedData.ciphertext);
    const decryptedRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey, ciphertext);
    return crypto.subtle.importKey('raw', decryptedRaw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },
  async encryptFile(buffer, masterKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, buffer);
    return {
      ciphertextB64: this.arrayBufferToBase64(ciphertext),
      ivB64: this.arrayBufferToBase64(iv)
    };
  },
  async decryptFile(ciphertextB64, ivB64, masterKey) {
    const iv = new Uint8Array(this.base64ToArrayBuffer(ivB64));
    const ciphertext = this.base64ToArrayBuffer(ciphertextB64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ciphertext);
  },
  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },
  base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }
};

/* ══════════════════════════════
   INIT
   ══════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  // Password strength listener
  const pwInput = document.getElementById('reg-password');
  if (pwInput) pwInput.addEventListener('input', updateStrengthMeter);

  // Close context menu on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#user-context-menu') && !e.target.closest('#user-menu-btn')) {
      document.getElementById('user-context-menu').classList.add('hidden');
    }
  });

  // Check for existing session
  const session = DB.getSession();
  if (session) {
    const users = DB.getUsers();
    if (users[session.username]) {
      loginUser(users[session.username]);
      return;
    }
  }
  showScreen('auth-screen');
});

/* ══════════════════════════════
   SCREEN NAVIGATION
   ══════════════════════════════ */
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

/* ══════════════════════════════
   AUTH — TAB SWITCHER
   ══════════════════════════════ */
function switchTab(tab) {
  const indicator = document.getElementById('tab-indicator');
  const loginForm  = document.getElementById('login-form');
  const regForm    = document.getElementById('register-form');
  const otpForm    = document.getElementById('otp-login-form');
  const tabLogin   = document.getElementById('tab-login');
  const tabReg     = document.getElementById('tab-register');

  loginForm.classList.remove('active');
  regForm.classList.remove('active');
  if (otpForm) otpForm.classList.remove('active');

  if (tab === 'login') {
    loginForm.classList.add('active');
    tabLogin.classList.add('active');
    tabReg.classList.remove('active');
    indicator.style.transform = 'translateX(0)';
  } else if (tab === 'register') {
    regForm.classList.add('active');
    tabReg.classList.add('active');
    tabLogin.classList.remove('active');
    indicator.style.transform = 'translateX(100%)';
  } else if (tab === 'otp') {
    if (otpForm) otpForm.classList.add('active');
    tabLogin.classList.add('active');
    tabReg.classList.remove('active');
    indicator.style.transform = 'translateX(0)';
  }

  // Clear errors
  hideError('login-error');
  hideError('reg-error');
  if (otpForm) {
    hideError('otp-error-1');
    hideError('otp-error-2');
  }
}

/* ══════════════════════════════
   AUTH — PASSWORD TOGGLE
   ══════════════════════════════ */
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.innerHTML = `<svg class="eye-icon" viewBox="0 0 20 20" fill="none"><path d="M3.98 8.223A10.477 10.477 0 002 10s3 6 8 6c1.5 0 2.9-.4 4.1-1.1M12 6.7A4 4 0 0110 6c-5 0-8 4-8 4s.9 1.3 2.3 2.4M10 14a4 4 0 004-4c0-.5-.1-1-.3-1.4M4 4l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`;
  } else {
    input.type = 'password';
    btn.innerHTML = `<svg class="eye-icon" viewBox="0 0 20 20" fill="none"><path d="M2 10s3-6 8-6 8 6 8 6-3 6-8 6-8-6-8-6z" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2" stroke="currentColor" stroke-width="1.5"/></svg>`;
  }
}

/* ══════════════════════════════
   AUTH — PASSWORD STRENGTH
   ══════════════════════════════ */
function updateStrengthMeter() {
  const pw = document.getElementById('reg-password').value;
  const score = checkPasswordStrength(pw);
  const fill  = document.getElementById('strength-fill');
  const label = document.getElementById('strength-label');
  const colors = ['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
  const labels = ['','Weak','Fair','Good','Strong'];
  const widths = ['0%','25%','50%','75%','100%'];
  fill.style.width = widths[score];
  fill.style.background = colors[score];
  label.textContent = labels[score];
  label.style.color = colors[score];
}

/* ══════════════════════════════
   AUTH — ERROR HELPERS
   ══════════════════════════════ */
function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) { el.textContent = msg; el.classList.remove('hidden'); }
}
function hideError(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
}

/* ══════════════════════════════
   AUTH — REGISTER
   ══════════════════════════════ */
async function handleRegister(e) {
  e.preventDefault();
  hideError('reg-error');

  const name     = document.getElementById('reg-name').value.trim();
  const username = document.getElementById('reg-username').value.trim().toLowerCase();
  const mobile   = document.getElementById('reg-mobile').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;

  // Validations
  if (!name)              return showError('reg-error', 'Please enter your full name.');
  if (!isValidUsername(username)) return showError('reg-error', 'Username must be 3–24 characters using only letters, numbers, and underscores.');
  if (!mobile)            return showError('reg-error', 'Please enter your mobile number.');
  if (password.length < 6) return showError('reg-error', 'Password must be at least 6 characters.');
  if (password !== confirm) return showError('reg-error', 'Passwords do not match.');

  const users = DB.getUsers();
  if (users[username]) return showError('reg-error', 'Username is already taken. Please choose another.');

  // Check if mobile already exists
  const existingMobile = Object.values(users).find(u => u.mobile === mobile);
  if (existingMobile) return showError('reg-error', 'Mobile number is already registered.');

  // Generate E2EE Keys
  const masterKey = await E2EE.generateMasterKey();
  const encryptedMasterKey = await E2EE.encryptMasterKey(masterKey, password);

  // Create user
  const newUser = {
    uid: generateUID(),
    name,
    username,
    mobile,
    passwordHash: hashPassword(password),
    encryptedMasterKey,
    createdAt: Date.now(),
  };
  users[username] = newUser;
  DB.saveUsers(users);

  showToast('Account created successfully! Welcome to StudyVault 🎉', 'success');
  setTimeout(() => {
    // Auto-login after register
    loginUser(newUser, masterKey);
  }, 800);
}

/* ══════════════════════════════
   AUTH — LOGIN
   ══════════════════════════════ */
async function handleLogin(e) {
  e.preventDefault();
  hideError('login-error');

  const username = document.getElementById('login-username').value.trim().toLowerCase();
  const password = document.getElementById('login-password').value;

  if (!username || !password) return showError('login-error', 'Please fill in all fields.');

  const users = DB.getUsers();
  const user = users[username];

  if (!user) return showError('login-error', 'No account found with that username.');
  if (user.passwordHash !== hashPassword(password)) return showError('login-error', 'Incorrect password. Please try again.');

  let masterKey = null;
  if (user.encryptedMasterKey) {
    try {
      masterKey = await E2EE.decryptMasterKey(user.encryptedMasterKey, password);
    } catch (err) {
      console.error('Failed to decrypt master key', err);
      return showError('login-error', 'Decryption failed. Incorrect password?');
    }
  }

  loginUser(user, masterKey);
}

/* ══════════════════════════════
   AUTH — OTP LOGIN
   ══════════════════════════════ */
function sendOtp() {
  hideError('otp-error-1');
  const mobile = document.getElementById('login-mobile').value.trim();
  if (!mobile) return showError('otp-error-1', 'Please enter your mobile number.');
  
  const users = DB.getUsers();
  const user = Object.values(users).find(u => u.mobile === mobile);
  
  if (!user) return showError('otp-error-1', 'No account found with this mobile number.');
  
  // Generate mock OTP
  state.currentOtp = Math.floor(100000 + Math.random() * 900000).toString();
  state.currentOtpUser = user;
  
  // Switch to step 2
  document.getElementById('otp-step-1').classList.add('hidden');
  document.getElementById('otp-step-2').classList.remove('hidden');
  
  showToast(`Mock SMS: Your OTP is ${state.currentOtp}`, 'success');
}

function handleOtpLogin(e) {
  e.preventDefault();
  hideError('otp-error-2');
  
  const enteredOtp = document.getElementById('login-otp').value.trim();
  if (!enteredOtp) return showError('otp-error-2', 'Please enter the OTP.');
  
  if (enteredOtp !== state.currentOtp) {
    return showError('otp-error-2', 'Invalid OTP. Please try again.');
  }
  
  // Success
  loginUser(state.currentOtpUser);
  resetOtpFlow();
}

function resetOtpFlow() {
  document.getElementById('login-mobile').value = '';
  document.getElementById('login-otp').value = '';
  document.getElementById('otp-step-1').classList.remove('hidden');
  document.getElementById('otp-step-2').classList.add('hidden');
  hideError('otp-error-1');
  hideError('otp-error-2');
  state.currentOtp = null;
  state.currentOtpUser = null;
}

/* ══════════════════════════════
   BIOMETRICS (WEBAUTHN)
   ══════════════════════════════ */
async function registerBiometric() {
  const user = state.currentUser;
  if (!user || !state.masterKey) return showError('profile-error', 'You must be logged in with a password to register biometrics.');

  const userIdBuffer = new TextEncoder().encode(user.username);
  
  const publicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: "StudyVault Local", ...(window.location.hostname ? { id: window.location.hostname } : {}) },
    user: {
      id: userIdBuffer,
      name: user.username,
      displayName: user.name || user.username,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
    timeout: 60000,
    attestation: "none"
  };

  try {
    const credential = await navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions });
    const credentialId = E2EE.arrayBufferToBase64(credential.rawId);
    
    // Store Master Key securely in localStorage tied to this credential
    const exportedMaster = await crypto.subtle.exportKey('raw', state.masterKey);
    const masterKeyB64 = E2EE.arrayBufferToBase64(exportedMaster);
    localStorage.setItem(`biometric_key_${credentialId}`, masterKeyB64);

    const users = DB.getUsers();
    users[user.username].biometricCredentialId = credentialId;
    DB.saveUsers(users);
    state.currentUser = users[user.username];
    
    showToast('Biometric login registered successfully!', 'success');
  } catch (err) {
    console.error(err);
    showError('profile-error', 'Biometric registration failed or cancelled.');
  }
}

async function loginWithBiometric() {
  hideError('login-error');
  const username = document.getElementById('login-username').value.trim().toLowerCase();
  
  if (!username) {
    return showError('login-error', 'Please enter your username first to use Biometrics.');
  }
  
  const users = DB.getUsers();
  const user = users[username];
  
  if (!user) return showError('login-error', 'No account found with that username.');
  if (!user.biometricCredentialId) return showError('login-error', 'Biometric login is not registered for this account.');

  const credentialIdBuffer = E2EE.base64ToArrayBuffer(user.biometricCredentialId);
  
  const publicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [{
      id: credentialIdBuffer,
      type: 'public-key',
      transports: ['internal'],
    }],
    userVerification: 'required',
    timeout: 60000
  };

  try {
    const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
    const credentialId = E2EE.arrayBufferToBase64(assertion.rawId);
    const masterKeyB64 = localStorage.getItem(`biometric_key_${credentialId}`);
    
    let masterKey = null;
    if (masterKeyB64) {
      const masterKeyRaw = E2EE.base64ToArrayBuffer(masterKeyB64);
      masterKey = await crypto.subtle.importKey('raw', masterKeyRaw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }
    
    loginUser(user, masterKey);
  } catch (err) {
    console.error(err);
    showError('login-error', 'Biometric authentication failed.');
  }
}

/* ══════════════════════════════
   AUTH — LOGIN USER (set session)
   ══════════════════════════════ */
async function loginUser(user, masterKey = null) {
  state.currentUser = user;
  state.masterKey = masterKey;
  DB.saveSession({ username: user.username });

  // Load user files & reminders
  state.files = await DB.getFiles(user.uid);
  state.reminders = await DB.getReminders(user.uid);

  // Update sidebar UI
  const initials = (user.name || user.username).split(' ').map(w => w[0]).join('').substring(0,2).toUpperCase();
  document.getElementById('sidebar-name').textContent = user.name || user.username;
  document.getElementById('sidebar-avatar').textContent = initials;

  // Switch to dashboard
  showScreen('dashboard-screen');
  document.getElementById('dashboard-screen').classList.add('active');

  // Render
  applyFilterAndSort();
  updateStats();
  updateStorageBar();

  showToast(`Welcome back, ${user.name || user.username}! 👋`, 'success');
}

/* ══════════════════════════════
   AUTH — LOGOUT
   ══════════════════════════════ */
function handleLogout() {
  DB.clearSession();
  state.currentUser = null;
  state.masterKey = null;
  state.files = [];
  state.filteredFiles = [];
  state.reminders = [];
  state.pendingFiles = [];
  document.getElementById('user-context-menu').classList.add('hidden');

  // Reset auth form
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
  hideError('login-error');

  showScreen('auth-screen');
  showToast('You have been signed out.', 'info');
}

/* ══════════════════════════════
   SIDEBAR
   ══════════════════════════════ */
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

/* ══════════════════════════════
   USER MENU
   ══════════════════════════════ */
function showUserMenu(e) {
  e.stopPropagation();
  const menu = document.getElementById('user-context-menu');
  const btn  = document.getElementById('user-menu-btn');
  const rect = btn.getBoundingClientRect();
  menu.style.bottom = (window.innerHeight - rect.top + 8) + 'px';
  menu.style.left   = rect.left + 'px';
  menu.classList.toggle('hidden');
}

/* ══════════════════════════════
   PROFILE MODAL
   ══════════════════════════════ */
function openProfileModal() {
  document.getElementById('user-context-menu').classList.add('hidden');
  const u = state.currentUser;
  document.getElementById('profile-name').value = u.name || '';
  document.getElementById('profile-mobile').value = u.mobile || '';

  const initials = (u.name || u.username).split(' ').map(w => w[0]).join('').substring(0,2).toUpperCase();
  document.getElementById('profile-avatar-display').textContent = initials;
  document.getElementById('profile-display-name').textContent = u.name || u.username;
  document.getElementById('profile-display-username').textContent = '@' + u.username;

  document.getElementById('profile-old-pw').value = '';
  document.getElementById('profile-new-pw').value = '';
  hideError('profile-error');
  const succ = document.getElementById('profile-success');
  if (succ) succ.classList.add('hidden');

  openModal('profile-modal');
}

function saveProfile() {
  hideError('profile-error');
  const succ = document.getElementById('profile-success');
  succ.classList.add('hidden');

  const name  = document.getElementById('profile-name').value.trim();
  const mobile = document.getElementById('profile-mobile').value.trim();
  const oldPw = document.getElementById('profile-old-pw').value;
  const newPw = document.getElementById('profile-new-pw').value;

  if (!name) return showError('profile-error', 'Name cannot be empty.');
  if (!mobile) return showError('profile-error', 'Mobile number cannot be empty.');

  const users = DB.getUsers();
  const user  = users[state.currentUser.username];

  // Check if mobile is already used by someone else
  const existingMobile = Object.values(users).find(u => u.mobile === mobile && u.username !== user.username);
  if (existingMobile) return showError('profile-error', 'Mobile number is already used by another account.');

  // Handle password change
  if (oldPw || newPw) {
    if (!oldPw) return showError('profile-error', 'Enter your current password to change it.');
    if (user.passwordHash !== hashPassword(oldPw)) return showError('profile-error', 'Current password is incorrect.');
    if (newPw.length < 6) return showError('profile-error', 'New password must be at least 6 characters.');
    user.passwordHash = hashPassword(newPw);
  }

  user.name = name;
  user.mobile = mobile;
  users[state.currentUser.username] = user;
  DB.saveUsers(users);
  state.currentUser = user;
  DB.saveSession({ username: user.username });

  // Update sidebar
  const initials = name.split(' ').map(w => w[0]).join('').substring(0,2).toUpperCase();
  document.getElementById('sidebar-name').textContent = name;
  document.getElementById('sidebar-avatar').textContent = initials;

  succ.textContent = 'Profile updated successfully!';
  succ.classList.remove('hidden');
  showToast('Profile saved!', 'success');
}

/* ══════════════════════════════
   FILE UPLOAD
   ══════════════════════════════ */
function openUploadModal() {
  state.pendingFiles = [];
  renderQueue();
  document.getElementById('file-queue').classList.add('hidden');
  document.getElementById('category-group').style.display = 'none';
  document.getElementById('tags-group').style.display = 'none';
  document.getElementById('encrypt-group').style.display = 'none';
  document.getElementById('upload-confirm-btn').disabled = true;
  document.getElementById('upload-tags').value = '';
  document.getElementById('upload-encrypt').checked = false;
  openModal('upload-modal');
}

function handleCategoryChange() {
  const cat = document.getElementById('upload-category').value;
  const chk = document.getElementById('upload-encrypt');
  if (cat === 'results' || cat === 'certificate') {
    chk.checked = true;
  }
}

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.add('drag-over');
}
function handleDragLeave(e) {
  document.getElementById('drop-zone').classList.remove('drag-over');
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  addToQueue([...e.dataTransfer.files]);
}
function handleFileSelect(e) {
  addToQueue([...e.target.files]);
  e.target.value = '';
}

function addToQueue(files) {
  const MAX_SIZE = 500 * 1024 * 1024; // 500 MB
  let rejected = 0;
  files.forEach(f => {
    if (f.size > MAX_SIZE) {
      rejected++;
    } else {
      state.pendingFiles.push(f);
    }
  });
  
  if (rejected > 0) {
    showToast(`${rejected} file(s) exceeded the 500MB limit and were not added.`, 'error');
  }
  renderQueue();
  if (state.pendingFiles.length > 0) {
    document.getElementById('file-queue').classList.remove('hidden');
    document.getElementById('category-group').style.display = 'block';
    document.getElementById('tags-group').style.display = 'block';
    document.getElementById('encrypt-group').style.display = 'block';
    document.getElementById('upload-confirm-btn').disabled = false;
    handleCategoryChange(); // auto-check if needed
  }
}

function removeFromQueue(idx) {
  state.pendingFiles.splice(idx, 1);
  renderQueue();
  if (state.pendingFiles.length === 0) {
    document.getElementById('file-queue').classList.add('hidden');
    document.getElementById('category-group').style.display = 'none';
    document.getElementById('tags-group').style.display = 'none';
    document.getElementById('encrypt-group').style.display = 'none';
    document.getElementById('upload-confirm-btn').disabled = true;
  }
}

function renderQueue() {
  const list = document.getElementById('queue-list');
  list.innerHTML = state.pendingFiles.map((f, i) => `
    <div class="queue-item">
      <span class="queue-item-icon">${getFileEmoji(f.name)}</span>
      <div class="queue-item-info">
        <div class="queue-item-name">${escHtml(f.name)}</div>
        <div class="queue-item-size">${formatSize(f.size)}</div>
      </div>
      <button class="queue-item-remove" onclick="removeFromQueue(${i})" title="Remove">
        <svg viewBox="0 0 20 20" fill="none"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      </button>
    </div>
  `).join('');
}

function confirmUpload() {
  if (state.pendingFiles.length === 0) return;
  const category = document.getElementById('upload-category').value;
  const tagsRaw  = document.getElementById('upload-tags').value;
  const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);
  const encrypt = document.getElementById('upload-encrypt').checked;

  const promises = state.pendingFiles.map(f => processFile(f, category, tags, encrypt));
  Promise.all(promises).then(newFiles => {
    state.files.push(...newFiles);
    DB.saveFiles(state.currentUser.uid, state.files);
    closeModal('upload-modal');
    applyFilterAndSort();
    updateStats();
    updateStorageBar();
    showToast(`${newFiles.length} file${newFiles.length > 1 ? 's' : ''} uploaded successfully! 🎉`, 'success');
    state.pendingFiles = [];
  }).catch(err => {
    showToast('Upload failed: ' + err.message, 'error');
  });
}

async function processFile(file, category, tags, encrypt) {
  let dataPayload;
  let isEncrypted = false;
  let ivB64 = null;
  let mimeType = file.type || 'application/octet-stream';

  if (encrypt && state.masterKey) {
    const buffer = await file.arrayBuffer();
    const encrypted = await E2EE.encryptFile(buffer, state.masterKey);
    dataPayload = encrypted.ciphertextB64;
    ivB64 = encrypted.ivB64;
    isEncrypted = true;
  } else {
    dataPayload = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = () => reject(new Error('Failed to read ' + file.name));
      reader.readAsDataURL(file);
    });
  }

  return {
    id: generateUID(),
    name: file.name,
    size: file.size,
    type: mimeType,
    category,
    tags,
    isEncrypted,
    iv: ivB64,
    uploadedAt: Date.now(),
    data: dataPayload,
  };
}

/* ══════════════════════════════
   FILE OPERATIONS
   ══════════════════════════════ */
function filterFiles(filter) {
  state.currentFilter = filter;
  // Update nav
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.filter === filter);
  });
  
  const mainSec = document.querySelector('.files-section'); // main files section
  const remSec = document.getElementById('reminders-section');
  
  if (filter === 'reminders') {
    mainSec.classList.add('hidden');
    remSec.classList.remove('hidden');
    renderReminders();
    return;
  } else {
    mainSec.classList.remove('hidden');
    remSec.classList.add('hidden');
  }

  // Update title
  const titles = { all:'All Files', pdf:'PDFs', results:'Results', notes:'Notes', certificate:'Certificates', other:'Other' };
  document.getElementById('section-title').textContent = titles[filter] || 'Files';
  applyFilterAndSort();
}

/* ══════════════════════════════
   REMINDERS
   ══════════════════════════════ */
function showReminders() {
  filterFiles('reminders');
}

function addReminder(e) {
  e.preventDefault();
  const textInput = document.getElementById('reminder-text');
  const dateInput = document.getElementById('reminder-date');
  
  if (!textInput.value || !dateInput.value) return;
  
  const rem = {
    id: generateUID(),
    text: textInput.value.trim(),
    due: dateInput.value,
    completed: false,
    createdAt: Date.now()
  };
  
  state.reminders.push(rem);
  DB.saveReminders(state.currentUser.uid, state.reminders);
  
  textInput.value = '';
  dateInput.value = '';
  renderReminders();
  showToast('Task added!', 'success');
}

function toggleReminder(id) {
  const rem = state.reminders.find(r => r.id === id);
  if (rem) {
    rem.completed = !rem.completed;
    DB.saveReminders(state.currentUser.uid, state.reminders);
    renderReminders();
  }
}

function deleteReminder(id) {
  state.reminders = state.reminders.filter(r => r.id !== id);
  DB.saveReminders(state.currentUser.uid, state.reminders);
  renderReminders();
  showToast('Task deleted.', 'info');
}

function renderReminders() {
  const list = document.getElementById('reminders-list');
  if (state.reminders.length === 0) {
    list.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-2);">No tasks added yet. Keep up the good work!</div>';
  } else {
    const sorted = [...state.reminders].sort((a, b) => {
      if (a.completed !== b.completed) return a.completed ? 1 : -1;
      return new Date(a.due) - new Date(b.due);
    });
    
    list.innerHTML = sorted.map(r => `
      <div class="reminder-item ${r.completed ? 'completed' : ''}">
        <div class="reminder-left">
          <input type="checkbox" class="reminder-checkbox" ${r.completed ? 'checked' : ''} onchange="toggleReminder('${r.id}')" />
          <span class="reminder-text">${escHtml(r.text)}</span>
          <span class="reminder-due">Due: ${r.due}</span>
        </div>
        <button class="reminder-delete" onclick="deleteReminder('${r.id}')" title="Delete Task">
          <svg viewBox="0 0 20 20" fill="none" width="16" height="16"><path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        </button>
      </div>
    `).join('');
  }
}

function sortFiles(value) {
  state.currentSort = value;
  applyFilterAndSort();
}

function searchFiles(query) {
  state.searchQuery = query.toLowerCase();
  applyFilterAndSort();
}

function applyFilterAndSort() {
  let files = [...state.files];

  // Filter by category
  if (state.currentFilter !== 'all') {
    files = files.filter(f => f.category === state.currentFilter);
  }

  // Search
  if (state.searchQuery) {
    files = files.filter(f =>
      f.name.toLowerCase().includes(state.searchQuery) ||
      (f.tags || []).some(t => t.toLowerCase().includes(state.searchQuery))
    );
  }

  // Sort
  const sort = state.currentSort;
  files.sort((a, b) => {
    if (sort === 'date-desc') return b.uploadedAt - a.uploadedAt;
    if (sort === 'date-asc')  return a.uploadedAt - b.uploadedAt;
    if (sort === 'name-asc')  return a.name.localeCompare(b.name);
    if (sort === 'name-desc') return b.name.localeCompare(a.name);
    if (sort === 'size-desc') return b.size - a.size;
    return 0;
  });

  state.filteredFiles = files;
  renderFiles();
}

function renderFiles() {
  const grid = document.getElementById('files-grid');
  const list = document.getElementById('files-list');
  const listBody = document.getElementById('files-list-body');
  const empty = document.getElementById('empty-state');

  if (state.filteredFiles.length === 0) {
    empty.classList.remove('hidden');
    grid.classList.add('hidden');
    list.classList.add('hidden');
    return;
  }

  empty.classList.add('hidden');

  if (state.currentView === 'grid') {
    grid.classList.remove('hidden');
    list.classList.add('hidden');
    grid.innerHTML = state.filteredFiles.map(f => renderFileCard(f)).join('');
  } else {
    grid.classList.add('hidden');
    list.classList.remove('hidden');
    listBody.innerHTML = state.filteredFiles.map(f => renderListItem(f)).join('');
  }
}

function renderFileCard(f) {
  const emoji = getFileEmoji(f.name);
  const tag   = getCatInfo(f.category);
  const date  = formatDate(f.uploadedAt);
  const size  = formatSize(f.size);
  const lockIcon = f.isEncrypted ? '<span title="End-to-End Encrypted" style="margin-right:4px;font-size:14px;">🔒</span>' : '';
  return `
    <div class="file-card" onclick="previewFile('${f.id}')">
      <div class="file-card-icon" style="background:${tag.bg}">${emoji}</div>
      <div class="file-card-name">${lockIcon}${escHtml(f.name)}</div>
      <div class="file-card-meta">
        <span class="file-card-size">${size}</span>
        <span class="file-card-date">${date}</span>
      </div>
      <span class="file-card-tag tag-${f.category}">${tag.label}</span>
      <div class="file-card-actions">
        <button class="file-action-btn" onclick="event.stopPropagation(); downloadFile('${f.id}')" title="Download">
          <svg viewBox="0 0 20 20" fill="none"><path d="M10 4v8M6 12l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <button class="file-action-btn" onclick="event.stopPropagation(); openShareModal('${f.id}')" title="Share">
          <svg viewBox="0 0 20 20" fill="none"><path d="M15 8a3 3 0 10-2.977-2.63l-4.94 2.47a3 3 0 100 4.319l4.94 2.47a3 3 0 10.895-1.789l-4.94-2.47a3.027 3.027 0 000-1.74l4.94-2.47C13.456 7.68 14.19 8 15 8z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <button class="file-action-btn danger" onclick="event.stopPropagation(); showDeleteConfirm('${f.id}', '${escHtml(f.name).replace(/'/g,"\\'")}')" title="Delete">
          <svg viewBox="0 0 20 20" fill="none"><path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        </button>
      </div>
    </div>`;
}

function renderListItem(f) {
  const emoji = getFileEmoji(f.name);
  const tag   = getCatInfo(f.category);
  const date  = formatDate(f.uploadedAt);
  const size  = formatSize(f.size);
  const lockIcon = f.isEncrypted ? '<span title="End-to-End Encrypted" style="margin-right:4px;font-size:14px;">🔒</span>' : '';
  return `
    <div class="list-item">
      <div class="list-item-name" style="cursor:pointer" onclick="previewFile('${f.id}')">
        <span class="list-item-icon">${emoji}</span>
        <span>${lockIcon}${escHtml(f.name)}</span>
      </div>
      <div class="list-item-cat">
        <span class="file-card-tag tag-${f.category}">${tag.label}</span>
      </div>
      <div class="list-item-size">${size}</div>
      <div class="list-item-date">${date}</div>
      <div class="list-item-actions">
        <button class="file-action-btn" onclick="downloadFile('${f.id}')" title="Download">
          <svg viewBox="0 0 20 20" fill="none"><path d="M10 4v8M6 12l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <button class="file-action-btn" onclick="openShareModal('${f.id}')" title="Share">
          <svg viewBox="0 0 20 20" fill="none"><path d="M15 8a3 3 0 10-2.977-2.63l-4.94 2.47a3 3 0 100 4.319l4.94 2.47a3 3 0 10.895-1.789l-4.94-2.47a3.027 3.027 0 000-1.74l4.94-2.47C13.456 7.68 14.19 8 15 8z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <button class="file-action-btn danger" onclick="showDeleteConfirm('${f.id}', '${escHtml(f.name).replace(/'/g,"\\'")}')" title="Delete">
          <svg viewBox="0 0 20 20" fill="none"><path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        </button>
      </div>
    </div>`;
}

/* Preview */
let currentPreviewId = null;

async function previewFile(id) {
  const f = state.files.find(x => x.id === id);
  if (!f) return;
  
  currentPreviewId = id;
  const notepad = document.getElementById('notepad-textarea');
  if (notepad) {
    notepad.value = f.notes || '';
    document.getElementById('notepad-status').textContent = 'Saved';
  }

  document.getElementById('preview-title').textContent = (f.isEncrypted ? '🔒 ' : '') + f.name;
  const body = document.getElementById('preview-body');
  const downloadBtn = document.getElementById('preview-download-btn');
  downloadBtn.onclick = () => downloadFile(id);

  let dataUrl = f.data;
  if (f.isEncrypted) {
    body.innerHTML = '<div style="padding:40px;text-align:center;">Decrypting... 🔒</div>';
    openModal('preview-modal');
    if (!state.masterKey) {
      body.innerHTML = '<div style="padding:40px;text-align:center;color:var(--error);">Failed to decrypt: Master Key not loaded.</div>';
      return;
    }
    try {
      const decryptedBuffer = await E2EE.decryptFile(f.data, f.iv, state.masterKey);
      const blob = new Blob([decryptedBuffer], { type: f.type });
      dataUrl = URL.createObjectURL(blob);
    } catch (err) {
      body.innerHTML = '<div style="padding:40px;text-align:center;color:var(--error);">Failed to decrypt file.</div>';
      return;
    }
  }

  const mime = f.type || '';
  if (mime.startsWith('image/')) {
    body.innerHTML = `<img src="${dataUrl}" alt="${escHtml(f.name)}" style="max-width:100%;border-radius:8px;" />`;
  } else if (mime === 'application/pdf') {
    body.innerHTML = `<iframe src="${dataUrl}" title="${escHtml(f.name)}"></iframe>`;
  } else if (mime.startsWith('text/') || mime === 'application/json') {
    try {
      let text;
      if (f.isEncrypted) {
        const response = await fetch(dataUrl);
        text = await response.text();
      } else {
        const b64 = dataUrl.split(',')[1];
        text = atob(b64);
      }
      body.innerHTML = `<pre style="white-space:pre-wrap;word-break:break-word;color:var(--text-2);font-size:13px;line-height:1.7;max-height:500px;overflow:auto;">${escHtml(text)}</pre>`;
    } catch {
      renderUnsupported(body, f);
    }
  } else {
    renderUnsupported(body, f);
  }

  if (!f.isEncrypted) openModal('preview-modal');
}

function renderUnsupported(body, f) {
  body.innerHTML = `
    <div class="preview-unsupported">
      <div class="file-emoji">${getFileEmoji(f.name)}</div>
      <h3>${escHtml(f.name)}</h3>
      <p>Preview not available for this file type.<br>Download it to open.</p>
    </div>`;
}

/* Quick Notes */
function saveQuickNotes() {
  if (!currentPreviewId) return;
  const f = state.files.find(x => x.id === currentPreviewId);
  if (!f) return;
  
  const notepad = document.getElementById('notepad-textarea');
  f.notes = notepad.value;
  DB.saveFiles(state.currentUser.uid, state.files);
  
  const status = document.getElementById('notepad-status');
  status.textContent = 'Saving...';
  clearTimeout(state.notesTimeout);
  state.notesTimeout = setTimeout(() => {
    status.textContent = 'Saved';
  }, 500);
}

/* ══════════════════════════════
   SECURE LINK SHARING (MOCK)
   ══════════════════════════════ */
let currentShareId = null;

function openShareModal(id) {
  currentShareId = id;
  document.getElementById('share-password-toggle').checked = false;
  document.getElementById('share-password-group').style.display = 'none';
  document.getElementById('share-password').value = '';
  document.getElementById('share-link-result').style.display = 'none';
  document.getElementById('share-expiry').value = '24h';
  document.getElementById('share-generate-btn').style.display = 'inline-flex';
  openModal('share-modal');
}

function generateShareLink() {
  const f = state.files.find(x => x.id === currentShareId);
  if (!f) return;
  
  const linkId = Math.random().toString(36).substring(2, 12);
  const link = `${window.location.origin}/share/${linkId}`;
  
  const resultDiv = document.getElementById('share-link-result');
  const textSpan = document.getElementById('share-link-text');
  textSpan.textContent = link;
  resultDiv.style.display = 'block';
  
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(link).then(() => {
      showToast('Secure mock link copied to clipboard!', 'success');
    }).catch(err => {
      showToast('Link generated (mocked)', 'success');
    });
  } else {
    showToast('Link generated (mocked)', 'success');
  }
  
  document.getElementById('share-generate-btn').style.display = 'none';
}

/* Download */
async function downloadFile(id) {
  const f = state.files.find(x => x.id === id);
  if (!f) return;
  
  let dataUrl = f.data;
  if (f.isEncrypted) {
    if (!state.masterKey) return showToast('Cannot decrypt: Master Key not loaded', 'error');
    try {
      const decryptedBuffer = await E2EE.decryptFile(f.data, f.iv, state.masterKey);
      const blob = new Blob([decryptedBuffer], { type: f.type });
      dataUrl = URL.createObjectURL(blob);
    } catch(err) {
      return showToast('Failed to decrypt file for download', 'error');
    }
  }

  const link = document.createElement('a');
  link.href = dataUrl;
  link.download = f.name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast(`Downloading ${f.name}...`, 'info');

  if (f.isEncrypted) {
    setTimeout(() => URL.revokeObjectURL(dataUrl), 1000);
  }
}

/* Delete */
function showDeleteConfirm(id, name) {
  state.deleteTarget = id;
  document.getElementById('delete-filename').textContent = name;
  openModal('delete-modal');
}

function confirmDelete() {
  const idx = state.files.findIndex(f => f.id === state.deleteTarget);
  if (idx === -1) return;
  const name = state.files[idx].name;
  state.files.splice(idx, 1);
  DB.saveFiles(state.currentUser.uid, state.files);
  closeModal('delete-modal');
  applyFilterAndSort();
  updateStats();
  updateStorageBar();
  showToast(`"${name}" deleted.`, 'info');
  state.deleteTarget = null;
}

/* ══════════════════════════════
   VIEW TOGGLE
   ══════════════════════════════ */
function setView(view) {
  state.currentView = view;
  document.getElementById('view-grid').classList.toggle('active', view === 'grid');
  document.getElementById('view-list').classList.toggle('active', view === 'list');
  renderFiles();
}

/* ══════════════════════════════
   STATS & STORAGE
   ══════════════════════════════ */
function updateStats() {
  const count = cat => state.files.filter(f => f.category === cat).length;
  document.getElementById('stat-total').textContent        = state.files.length;
  document.getElementById('stat-pdf').textContent          = count('pdf');
  document.getElementById('stat-results').textContent      = count('results');
  document.getElementById('stat-notes').textContent        = count('notes');
  document.getElementById('stat-certificate').textContent  = count('certificate');

  // Nav badges
  document.getElementById('badge-all').textContent         = state.files.length;
  document.getElementById('badge-pdf').textContent         = count('pdf');
  document.getElementById('badge-results').textContent     = count('results');
  document.getElementById('badge-notes').textContent       = count('notes');
  document.getElementById('badge-certificate').textContent = count('certificate');
  document.getElementById('badge-other').textContent       = count('other');
}

function updateStorageBar() {
  const totalBytes = state.files.reduce((s, f) => s + (f.size || 0), 0);
  const limitBytes = 500 * 1024 * 1024; // 500 MB (visual only)
  const pct = Math.min((totalBytes / limitBytes) * 100, 100);
  document.getElementById('storage-fill').style.width = pct + '%';
  document.getElementById('storage-used-label').textContent = formatSize(totalBytes);
}

/* ══════════════════════════════
   MODAL HELPERS
   ══════════════════════════════ */
function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}
function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
  document.body.style.overflow = '';
}
function closeModalOnOverlay(e, id) {
  if (e.target.id === id) closeModal(id);
}

/* ══════════════════════════════
   TOAST
   ══════════════════════════════ */
function showToast(msg, type = 'info') {
  const icons = { success:'✅', error:'❌', info:'ℹ️' };
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type]}</span><span>${msg}</span>`;
  container.appendChild(el);
  setTimeout(() => {
    el.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

/* ══════════════════════════════
   UTILITIES
   ══════════════════════════════ */
function getCatInfo(cat) {
  const map = {
    pdf:         { label:'PDF',          bg:'rgba(244,63,94,0.12)' },
    results:     { label:'Results',      bg:'rgba(16,185,129,0.12)' },
    notes:       { label:'Notes',        bg:'rgba(245,158,11,0.12)' },
    certificate: { label:'Certificate',  bg:'rgba(245,158,11,0.15)' },
    other:       { label:'Other',        bg:'rgba(100,116,139,0.12)' },
  };
  return map[cat] || map.other;
}

function getFileEmoji(name) {
  const ext = (name || '').split('.').pop().toLowerCase();
  const map = {
    pdf: '📄', doc:'📝', docx:'📝', txt:'📃',
    xls:'📊', xlsx:'📊', csv:'📊',
    ppt:'📑', pptx:'📑',
    jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️', webp:'🖼️', svg:'🖼️',
    mp4:'🎬', mov:'🎬', avi:'🎬', mkv:'🎬',
    mp3:'🎵', wav:'🎵',
    zip:'📦', rar:'📦', '7z':'📦',
    py:'🐍', js:'📜', html:'🌐', css:'🎨', json:'📋',
  };
  return map[ext] || '📁';
}

function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024)          return bytes + ' B';
  if (bytes < 1024 * 1024)   return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

function formatDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
