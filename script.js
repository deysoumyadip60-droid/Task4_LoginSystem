/* =====================================================
   Simple Login System (runs fully in the browser)
   Accounts are saved in localStorage.
   ===================================================== */

const $ = id => document.getElementById(id);

const USERS_KEY = 'ls_users';
const SESSION_KEY = 'ls_session';

let mode = 'login';          // 'login' or 'signup'
let fails = 0;               // wrong password counter
let lockUntil = 0;           // lock timestamp
let clockTimer = null;

/* ---------- storage helpers ---------- */
function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || {}; }
    catch (e) { return {}; }
}
function saveUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

/* ---------- password hashing (salted SHA-256) ---------- */
function randomSalt() {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, salt) {
    const data = new TextEncoder().encode(salt + ':' + password);
    if (window.crypto && crypto.subtle) {
        const buf = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
    }
    // weak fallback for very old browsers
    let h = 5381;
    for (const c of data) h = ((h << 5) + h + c) >>> 0;
    return 'x' + h.toString(16);
}

/* ---------- messages ---------- */
function showMessage(text, type) {
    const box = $('errorMessage');
    box.textContent = text;
    box.classList.toggle('success', type === 'success');
    box.classList.add('show');
}
function clearMessage() {
    const box = $('errorMessage');
    box.classList.remove('show', 'success');
    box.textContent = '';
}
function fail(text) {
    showMessage(text, 'error');
    const card = document.querySelector('.auth-box');
    card.classList.remove('shake');
    void card.offsetWidth;            // restart animation
    card.classList.add('shake');
}

/* ---------- login / signup mode ---------- */
function setMode(newMode) {
    mode = newMode;
    const signup = mode === 'signup';

    $('authTitle').textContent = signup ? 'Create Account 🚀' : 'Welcome Back 👋';
    $('submitBtn').textContent = signup ? 'Sign Up' : 'Login';
    $('toggleText').textContent = signup ? 'Already have an account?' : "Don't have an account?";
    $('toggleLink').textContent = signup ? 'Login' : 'Sign up';
    $('password').autocomplete = signup ? 'new-password' : 'current-password';

    $('confirmGroup').hidden = !signup;
    $('pwHint').hidden = !signup;
    $('strength').hidden = !signup;

    $('password').value = '';
    $('confirmPassword').value = '';
    updateStrength();
    clearMessage();
}

$('toggleLink').addEventListener('click', () => {
    setMode(mode === 'login' ? 'signup' : 'login');
});

/* ---------- show / hide password ---------- */
$('pwToggle').addEventListener('click', () => {
    const show = $('password').type === 'password';
    $('password').type = show ? 'text' : 'password';
    $('confirmPassword').type = show ? 'text' : 'password';
    $('pwToggle').textContent = show ? 'Hide' : 'Show';
});

/* ---------- password strength ---------- */
function updateStrength() {
    const p = $('password').value;
    let score = 0;
    if (p.length >= 6) score++;
    if (p.length >= 10) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/\d/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    score = p ? Math.max(1, Math.min(score, 4)) : 0;

    const colors = ['transparent', '#e74c3c', '#f39c12', '#27ae60', '#667eea'];
    const labels = ['At least 6 characters', 'Weak password', 'Okay password', 'Strong password', 'Epic password 🔥'];

    $('strengthBar').style.width = (score / 4 * 100) + '%';
    $('strengthBar').style.background = colors[score];
    $('pwHint').textContent = labels[score];
}
$('password').addEventListener('input', updateStrength);

/* ---------- session ---------- */
function startSession(key, remember) {
    clearSession();
    (remember ? localStorage : sessionStorage).setItem(SESSION_KEY, JSON.stringify({ key, remember }));
}
function clearSession() {
    localStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(SESSION_KEY);
}
function readSession() {
    try {
        return JSON.parse(sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY));
    } catch (e) { return null; }
}

/* ---------- submit ---------- */
$('authForm').addEventListener('submit', async e => {
    e.preventDefault();
    clearMessage();

    if (Date.now() < lockUntil) {
        return fail('Too many attempts. Try again in ' + Math.ceil((lockUntil - Date.now()) / 1000) + 's.');
    }

    const name = $('username').value.trim();
    const password = $('password').value;
    const key = name.toLowerCase();

    if (!/^[a-z0-9_]{3,20}$/i.test(name)) {
        return fail('Username must be 3-20 characters (letters, numbers, underscore).');
    }
    if (!password) return fail('Please enter your password.');

    $('submitBtn').disabled = true;
    try {
        const users = getUsers();

        if (mode === 'signup') {
            /* ----- create account ----- */
            if (password.length < 6) return fail('Password must be at least 6 characters.');
            if (password !== $('confirmPassword').value) return fail('Passwords do not match.');
            if (users[key]) return fail('This username is already taken.');

            const salt = randomSalt();
            users[key] = {
                username: name,
                salt,
                hash: await hashPassword(password, salt),
                created: Date.now(),
                lastLogin: null,
                prevLogin: null,
                logins: 0
            };
            saveUsers(users);

            setMode('login');
            $('username').value = name;
            showMessage('Account created! Please login.', 'success');
        } else {
            /* ----- login ----- */
            const user = users[key];
            const ok = user && (await hashPassword(password, user.salt)) === user.hash;

            if (!ok) {
                fails++;
                if (fails >= 5) {
                    fails = 0;
                    lockUntil = Date.now() + 30000;
                    return fail('Too many failed attempts. Locked for 30 seconds.');
                }
                return fail('Invalid username or password.');
            }

            fails = 0;
            user.prevLogin = user.lastLogin;
            user.lastLogin = Date.now();
            user.logins = (user.logins || 0) + 1;
            saveUsers(users);

            startSession(key, $('remember').checked);
            openDashboard(key);
        }
    } finally {
        $('submitBtn').disabled = false;
    }
});

/* ---------- dashboard ---------- */
function openDashboard(key) {
    const user = getUsers()[key];
    if (!user) return logout();

    const hour = new Date().getHours();
    const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    const session = readSession();

    $('welcomeTitle').textContent = greet + ', ' + user.username + '! 🎉';
    $('infoUser').textContent = user.username;
    $('infoSince').textContent = new Date(user.created).toLocaleDateString(undefined, {
        day: 'numeric', month: 'long', year: 'numeric'
    });
    $('infoLast').textContent = user.prevLogin
        ? new Date(user.prevLogin).toLocaleString()
        : 'First login 🎊';
    $('infoCount').textContent = user.logins || 1;
    $('infoSession').textContent = session && session.remember ? 'Remembered on this device' : 'This tab only';

    $('authPage').hidden = true;
    $('dashboard').hidden = false;
    startClock();
}

function startClock() {
    const tick = () => { $('clock').textContent = new Date().toLocaleTimeString(); };
    tick();
    clearInterval(clockTimer);
    clockTimer = setInterval(tick, 1000);
}

/* ---------- logout ---------- */
function logout() {
    clearSession();
    clearInterval(clockTimer);
    $('dashboard').hidden = true;
    $('authPage').hidden = false;
    $('authForm').reset();
    setMode('login');
}
$('logoutBtn').addEventListener('click', logout);

/* ---------- auto login on page load ---------- */
(function init() {
    const session = readSession();
    if (session && getUsers()[session.key]) {
        openDashboard(session.key);
    }
})();