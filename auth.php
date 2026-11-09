<?php
// auth.php - Request bootstrap: security headers, sessions, CSRF, the site-wide
// master password, per-vault session keys, and login rate limiting.

declare(strict_types=1);

require_once __DIR__ . '/crypto.php';

define('SYSTEM_CONFIG_FILE', DATA_DIR . '/system.json');
define('RATE_LIMIT_FILE', DATA_DIR . '/ratelimit.json');
define('SESSIONS_DIR', DATA_DIR . '/sessions');
define('LEGACY_HTPASSWD_FILE', __DIR__ . '/.htpasswd');

define('MASTER_IDLE_TIMEOUT', 43200); // 12 hours
define('MIN_PASSWORD_LENGTH', 8);
define('MAX_PASSWORD_BYTES', 72);     // bcrypt silently ignores anything longer

define('RATE_LIMIT_FREE_ATTEMPTS', 5);
define('RATE_LIMIT_BASE_SECONDS', 30);
define('RATE_LIMIT_MAX_SECONDS', 900);
define('RATE_LIMIT_FORGET_AFTER', 3600);

function is_https(): bool {
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

// __Host- cookies must be Secure and host-only, and keep the HTTP and HTTPS
// versions of the site from fighting over one cookie.
function cookie_name(string $base): string {
    return (is_https() ? '__Host-' : '') . $base;
}

// Web path the app is installed under: '' at the domain root, '/notes' in a subfolder.
function app_base_path(): string {
    $dir = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')));
    return rtrim($dir, '/.');
}

function app_url(string $path): string {
    return app_base_path() . $path;
}

function install_problems(): array {
    $problems = [];
    if (PHP_VERSION_ID < 80100) {
        $problems[] = 'PHP 8.1 or newer is required (found ' . PHP_VERSION . ').';
    }
    foreach (['openssl', 'pdo_sqlite', 'session'] as $extension) {
        if (!extension_loaded($extension)) {
            $problems[] = "The PHP extension \"{$extension}\" is not enabled.";
        }
    }
    if (!is_dir(DATA_DIR) || !is_writable(DATA_DIR)) {
        $problems[] = 'The data/ folder must exist and be writable by the web server.';
    }
    return $problems;
}

function stop_if_install_incomplete(): void {
    $problems = install_problems();
    if ($problems === []) {
        return;
    }
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Keep Secured cannot start:\n\n- " . implode("\n- ", $problems) . "\n";
    exit;
}

function start_request(): void {
    stop_if_install_incomplete();

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

    ensure_base_dirs();
    if (!is_dir(SESSIONS_DIR)) {
        @mkdir(SESSIONS_DIR, 0700, true);
    }
    if (is_dir(SESSIONS_DIR) && is_writable(SESSIONS_DIR)) {
        session_save_path(SESSIONS_DIR);
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string)MASTER_IDLE_TIMEOUT);
    session_name(cookie_name('keep_secured_sid'));
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

// --- CSRF -------------------------------------------------------------------

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_is_valid(): bool {
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    return is_string($sent) && !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $sent);
}

// --- Master password --------------------------------------------------------

function legacy_htpasswd_hashes(): array {
    if (!is_file(LEGACY_HTPASSWD_FILE)) {
        return [];
    }
    $hashes = [];
    foreach ((array)@file(LEGACY_HTPASSWD_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $parts = explode(':', (string)$line, 2);
        if (count($parts) === 2) {
            $hashes[] = trim($parts[1]);
        }
    }
    return $hashes;
}

// Apache's MD5 variant ($apr1$). PHP's crypt() does not implement it.
function apr1_hash(string $password, string $salt): string {
    $len = strlen($password);
    $ctx = $password . '$apr1$' . $salt;
    $bin = md5($password . $salt . $password, true);
    for ($i = $len; $i > 0; $i -= 16) {
        $ctx .= substr($bin, 0, min(16, $i));
    }
    for ($i = $len; $i > 0; $i >>= 1) {
        $ctx .= ($i & 1) ? "\0" : $password[0];
    }
    $bin = md5($ctx, true);
    for ($i = 0; $i < 1000; $i++) {
        $round = ($i & 1) ? $password : $bin;
        if ($i % 3) $round .= $salt;
        if ($i % 7) $round .= $password;
        $round .= ($i & 1) ? $bin : $password;
        $bin = md5($round, true);
    }

    $itoa = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    $encode = static function (int $value, int $chars) use ($itoa): string {
        $out = '';
        while ($chars-- > 0) {
            $out .= $itoa[$value & 0x3f];
            $value >>= 6;
        }
        return $out;
    };
    $out = '';
    foreach ([[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]] as [$a, $b, $c]) {
        $out .= $encode((ord($bin[$a]) << 16) | (ord($bin[$b]) << 8) | ord($bin[$c]), 4);
    }
    $out .= $encode(ord($bin[11]), 2);
    return '$apr1$' . $salt . '$' . $out;
}

function legacy_password_matches(string $password, string $hash): bool {
    if ($password === '') {
        return false;
    }
    if (str_starts_with($hash, '$apr1$')) {
        $salt = explode('$', $hash)[2] ?? '';
        return hash_equals($hash, apr1_hash($password, $salt));
    }
    if (str_starts_with($hash, '$2')) {
        return password_verify($password, $hash);
    }
    return false;
}

// Until a password is saved here, the existing .htpasswd keeps the site locked.
function master_config(): array {
    if (is_file(SYSTEM_CONFIG_FILE)) {
        $saved = json_decode((string)@file_get_contents(SYSTEM_CONFIG_FILE), true);
        if (!is_array($saved)) {
            // Unreadable config must lock the site, not open it.
            return ['enabled' => true, 'hash' => '', 'epoch' => '', 'legacy' => false, 'unconfigured' => false];
        }
        return [
            'enabled' => !empty($saved['enabled']),
            'hash' => (string)($saved['hash'] ?? ''),
            'epoch' => (string)($saved['epoch'] ?? ''),
            'legacy' => false,
            'unconfigured' => false,
        ];
    }
    $legacy = legacy_htpasswd_hashes() !== [];
    return ['enabled' => $legacy, 'hash' => '', 'epoch' => '', 'legacy' => $legacy, 'unconfigured' => !$legacy];
}

function read_system_config(): array {
    $saved = json_decode((string)@file_get_contents(SYSTEM_CONFIG_FILE), true);
    return is_array($saved) ? $saved : [];
}

function write_system_config(array $changes): bool {
    $config = array_merge(read_system_config(), $changes, ['updated_at' => date('c')]);
    return atomic_write_json(SYSTEM_CONFIG_FILE, $config, 0600);
}

function master_save(bool $enabled, string $hash): bool {
    // A new epoch signs out every other session.
    return write_system_config([
        'enabled' => $enabled,
        'hash' => $hash,
        'epoch' => bin2hex(random_bytes(16)),
    ]);
}

function show_gated_vault_links(): bool {
    return !empty(read_system_config()['show_gated_links']);
}

function set_show_gated_vault_links(bool $show): bool {
    return write_system_config(['show_gated_links' => $show]);
}

function master_set_password(string $password): bool {
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    return master_save(true, password_hash($password, $algo));
}

function master_disable(): bool {
    return master_save(false, '');
}

function master_verify_password(string $password): bool {
    $config = master_config();
    if ($config['legacy']) {
        foreach (legacy_htpasswd_hashes() as $hash) {
            if (legacy_password_matches($password, $hash)) {
                if (!master_set_password($password)) {
                    error_log('keep-secured: could not migrate .htpasswd password to ' . SYSTEM_CONFIG_FILE);
                }
                return true;
            }
        }
        return false;
    }
    return $config['hash'] !== '' && password_verify($password, $config['hash']);
}

function master_mark_authenticated(): void {
    session_regenerate_id(true);
    $_SESSION['master'] = ['epoch' => master_config()['epoch'], 'last' => time()];
}

function master_is_authenticated(): bool {
    $config = master_config();
    if ($config['unconfigured']) {
        return false; // a fresh install must choose before anything is served
    }
    if (!$config['enabled']) {
        return true;
    }
    $auth = $_SESSION['master'] ?? null;
    if (
        !is_array($auth)
        || !hash_equals($config['epoch'], (string)($auth['epoch'] ?? ''))
        || (time() - (int)($auth['last'] ?? 0)) > MASTER_IDLE_TIMEOUT
    ) {
        unset($_SESSION['master']);
        return false;
    }
    $_SESSION['master']['last'] = time();
    return true;
}

function new_password_error(string $password): ?string {
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        return 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.';
    }
    if (strlen($password) > MAX_PASSWORD_BYTES) {
        return 'Password must be at most ' . MAX_PASSWORD_BYTES . ' bytes.';
    }
    return null;
}

// --- Per-vault session keys -------------------------------------------------

// Vault keys are stored encrypted in the session; the secret is only in the
// visitor's cookie, so a session file alone cannot decrypt notes.
function vault_wrap_secret(bool $create): ?string {
    $name = cookie_name('keep_secured_wk');
    $value = $_COOKIE[$name] ?? '';
    if (is_string($value) && preg_match('/^[a-f0-9]{64}$/', $value)) {
        return hex2bin($value);
    }
    if (!$create) {
        return null;
    }
    $secret = random_bytes(32);
    $_COOKIE[$name] = bin2hex($secret);
    setcookie($name, $_COOKIE[$name], [
        'expires' => 0,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    return $secret;
}

function store_vault_key(string $slug, string $key): void {
    session_regenerate_id(true);
    $_SESSION['vault_keys'][$slug] = encrypt_data($key, vault_wrap_secret(true));
    $_SESSION['vault_activity'][$slug] = time();
}

function clear_vault_key(string $slug): void {
    unset($_SESSION['vault_keys'][$slug], $_SESSION['vault_activity'][$slug]);
}

// Returns '' for an open vault, the key for an unlocked one, null when locked.
function get_vault_auth_key(string $slug): ?string {
    if (!is_vault_gated($slug)) {
        return '';
    }
    if (empty($_SESSION['vault_keys'][$slug])) {
        return null;
    }
    $last = $_SESSION['vault_activity'][$slug] ?? 0;
    $secret = vault_wrap_secret(false);
    $key = $secret === null ? null : decrypt_data((string)$_SESSION['vault_keys'][$slug], $secret);
    if ($key === null || (time() - $last) > INACTIVITY_TIMEOUT) {
        clear_vault_key($slug);
        return null;
    }
    $_SESSION['vault_activity'][$slug] = time();
    return $key;
}

// --- Rate limiting ----------------------------------------------------------

function rate_limit_key(string $bucket): string {
    return hash('sha256', $bucket . '|' . ($_SERVER['REMOTE_ADDR'] ?? ''));
}

function with_rate_limits(callable $change): void {
    $handle = @fopen(RATE_LIMIT_FILE, 'c+');
    if ($handle === false) {
        error_log('keep-secured: cannot open ' . RATE_LIMIT_FILE);
        return;
    }
    flock($handle, LOCK_EX);
    $entries = json_decode((string)stream_get_contents($handle), true);
    $entries = is_array($entries) ? $entries : [];

    $now = time();
    foreach ($entries as $key => $entry) {
        if ($now - (int)($entry['last'] ?? 0) > RATE_LIMIT_FORGET_AFTER) {
            unset($entries[$key]);
        }
    }
    $entries = $change($entries, $now);

    ftruncate($handle, 0);
    rewind($handle);
    fwrite($handle, (string)json_encode($entries));
    flock($handle, LOCK_UN);
    fclose($handle);
    @chmod(RATE_LIMIT_FILE, 0600);
}

// Seconds the visitor must wait before another attempt (0 = allowed).
function rate_limit_retry_after(string $bucket): int {
    $wait = 0;
    with_rate_limits(function (array $entries, int $now) use ($bucket, &$wait): array {
        $wait = max(0, (int)($entries[rate_limit_key($bucket)]['until'] ?? 0) - $now);
        return $entries;
    });
    return $wait;
}

function rate_limit_record_failure(string $bucket): void {
    with_rate_limits(function (array $entries, int $now) use ($bucket): array {
        $key = rate_limit_key($bucket);
        $fails = (int)($entries[$key]['fails'] ?? 0) + 1;
        $until = 0;
        if ($fails >= RATE_LIMIT_FREE_ATTEMPTS) {
            $doublings = min(10, $fails - RATE_LIMIT_FREE_ATTEMPTS);
            $until = $now + min(RATE_LIMIT_MAX_SECONDS, RATE_LIMIT_BASE_SECONDS * (2 ** $doublings));
        }
        $entries[$key] = ['fails' => $fails, 'until' => $until, 'last' => $now];
        return $entries;
    });
}

function rate_limit_clear(string $bucket): void {
    with_rate_limits(function (array $entries) use ($bucket): array {
        unset($entries[rate_limit_key($bucket)]);
        return $entries;
    });
}

// --- Shared page fragments --------------------------------------------------

function asset_url(string $file): string {
    return app_url('/' . $file) . '?v=' . (int)@filemtime(__DIR__ . '/' . $file);
}

function render_page_head(string $title): void {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
  <meta name="csrf-token" content="<?= htmlspecialchars(csrf_token()) ?>">
  <meta name="base-path" content="<?= htmlspecialchars(app_base_path()) ?>">
  <title><?= htmlspecialchars($title) ?></title>
  <link rel="stylesheet" href="<?= htmlspecialchars(asset_url('style.css')) ?>">
  <script src="<?= htmlspecialchars(asset_url('app.js')) ?>" defer></script>
</head>
<?php
}

function render_first_run(): never {
    render_page_head('Welcome — Keep Secured');
    ?>
<body>
  <div class="auth-container">
    <div class="auth-card">
      <div class="auth-icon">🔐</div>
      <h1 class="auth-title">Set a master password</h1>
      <p class="auth-subtitle">It protects this whole site. There is no username.</p>
      <form id="masterEnableForm" class="auth-form">
        <div class="auth-error" role="alert"></div>
        <div class="auth-input-group">
          <label for="firstRunPassword">Master Password</label>
          <input type="password" id="firstRunPassword" name="password" class="auth-input" required autofocus autocomplete="new-password" placeholder="At least 8 characters">
        </div>
        <div class="auth-input-group">
          <label for="firstRunConfirm">Confirm Password</label>
          <input type="password" id="firstRunConfirm" name="confirm" class="auth-input" required autocomplete="new-password" placeholder="Re-enter password">
        </div>
        <button type="submit" class="btn-primary">Set password</button>
      </form>
      <button id="masterSkipBtn" type="button" class="btn-secondary first-run-skip">Continue without a password</button>
    </div>
  </div>
</body>
</html>
<?php
    exit;
}

function render_master_login(): never {
    if (master_config()['unconfigured']) {
        render_first_run();
    }
    render_page_head('Locked — Keep Secured');
    ?>
<body>
  <div class="auth-container">
    <div class="auth-card">
      <div class="auth-icon">🔐</div>
      <h1 class="auth-title">Keep Secured is locked</h1>
      <p class="auth-subtitle">Enter the master password to continue.</p>
      <form id="masterLoginForm" class="auth-form">
        <div class="auth-error" role="alert"></div>
        <div class="auth-input-group">
          <label for="masterLoginPassword">Master Password</label>
          <input type="password" id="masterLoginPassword" name="password" class="auth-input" required autofocus autocomplete="current-password" placeholder="Enter master password">
        </div>
        <button type="submit" class="btn-primary">Unlock</button>
      </form>
    </div>
  </div>
</body>
</html>
<?php
    exit;
}
