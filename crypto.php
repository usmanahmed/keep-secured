<?php
// crypto.php - Multi-vault encryption, storage, and key derivation

declare(strict_types=1);

define('CANARY_TEXT', 'NOTEPAD_SECRET_VALIDATION_TOKEN_v1');
define('DATA_DIR', __DIR__ . '/data');
define('VAULTS_DIR', DATA_DIR . '/vaults');
define('INACTIVITY_TIMEOUT', 120); // 2 minutes
define('KDF_ITERATIONS', 600000);
define('LEGACY_KDF_ITERATIONS', 100000); // vaults created before kdf_iterations was recorded
define('MAX_SLUG_LENGTH', 64);
define('RESERVED_VAULT_SLUGS', ['settings']);

function ensure_base_dirs(): void {
    if (!is_dir(DATA_DIR)) {
        @mkdir(DATA_DIR, 0770, true);
    }
    if (!is_file(DATA_DIR . '/.htaccess')) {
        @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\n");
    }
    if (!is_dir(VAULTS_DIR)) {
        @mkdir(VAULTS_DIR, 0770, true);
    }
}

// Write-then-rename, so a crash or full disk cannot leave a truncated config.
function atomic_write_json(string $file, array $data, int $mode = 0640): bool {
    $json = json_encode($data, JSON_PRETTY_PRINT);
    $tmp = @tempnam(dirname($file), '.tmp');
    if ($json === false || $tmp === false) {
        return false;
    }
    if (@file_put_contents($tmp, $json) === false || !@chmod($tmp, $mode) || !@rename($tmp, $file)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

function is_reserved_vault_slug(string $slug): bool {
    return in_array($slug, RESERVED_VAULT_SLUGS, true);
}

function sanitize_vault_slug(?string $slug): string {
    if ($slug === null || trim($slug) === '' || trim($slug) === 'default') {
        return 'default';
    }
    $clean = preg_replace('/[^a-zA-Z0-9_-]/', '', strtolower(trim($slug)));
    $clean = substr((string)$clean, 0, MAX_SLUG_LENGTH);
    return $clean !== '' ? $clean : 'default';
}

function get_vault_dir(string $slug): string {
    ensure_base_dirs();
    return VAULTS_DIR . '/' . sanitize_vault_slug($slug);
}

function get_vault_config_file(string $slug): string {
    return get_vault_dir($slug) . '/config.json';
}

function get_vault_db_file(string $slug): string {
    return get_vault_dir($slug) . '/notes.db';
}

function is_vault_initialized(string $slug): bool {
    return file_exists(get_vault_config_file($slug));
}

function get_vault_config(string $slug): ?array {
    $file = get_vault_config_file($slug);
    if (!file_exists($file)) {
        return null;
    }
    $raw = file_get_contents($file);
    if ($raw === false) return null;
    return json_decode($raw, true);
}

function is_vault_gated(string $slug): bool {
    $config = get_vault_config($slug);
    if ($config === null) {
        return false;
    }
    if (isset($config['is_gated'])) {
        return (bool)$config['is_gated'];
    }
    return !empty($config['salt']);
}

function derive_key(string $password, string $salt, int $iterations = KDF_ITERATIONS): string {
    return hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
}

function encrypt_data(string $plaintext, string $key): string {
    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return base64_encode($iv . $tag . $ciphertext);
}

function decrypt_data(string $encoded, string $key): ?string {
    $raw = base64_decode($encoded, true);
    if ($raw === false || strlen($raw) < 28) {
        return null;
    }
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);
    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return ($plaintext === false) ? null : $plaintext;
}

function init_vault_db(string $slug, ?PDO $db = null): void {
    if ($db === null) {
        $db = get_vault_db($slug);
    }
    $db->exec("
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_cipher TEXT NOT NULL,
            body_cipher TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#ffffff',
            is_pinned INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_notes_pinned ON notes(is_pinned, updated_at DESC);
    ");
}

function get_vault_db(string $slug): PDO {
    $dir = get_vault_dir($slug);
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    $dbFile = get_vault_db_file($slug);
    $db = new PDO('sqlite:' . $dbFile);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA secure_delete = ON');
    init_vault_db($slug, $db);
    return $db;
}

function initialize_ungated_vault(string $slug): bool {
    $dir = get_vault_dir($slug);
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    $config = [
        'slug' => $slug,
        'is_gated' => false,
        'created_at' => date('c'),
    ];
    if (!atomic_write_json(get_vault_config_file($slug), $config)) return false;
    init_vault_db($slug);
    return true;
}

function initialize_gated_vault(string $slug, string $password): bool {
    $dir = get_vault_dir($slug);
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    $salt = random_bytes(32);
    $key = derive_key($password, $salt);
    $verifier = encrypt_data(CANARY_TEXT, $key);

    $config = [
        'slug' => $slug,
        'is_gated' => true,
        'salt' => bin2hex($salt),
        'verifier' => $verifier,
        'kdf_iterations' => KDF_ITERATIONS,
        'created_at' => date('c'),
    ];

    if (!atomic_write_json(get_vault_config_file($slug), $config)) return false;
    init_vault_db($slug);
    return true;
}

function verify_vault_password(string $slug, string $password): ?string {
    $config = get_vault_config($slug);
    if (!$config || empty($config['salt']) || empty($config['verifier'])) {
        return null;
    }
    $salt = hex2bin($config['salt']);
    $iterations = (int)($config['kdf_iterations'] ?? LEGACY_KDF_ITERATIONS);
    $key = derive_key($password, $salt, $iterations);
    $decrypted = decrypt_data($config['verifier'], $key);
    if ($decrypted === CANARY_TEXT) {
        return $key;
    }
    return null;
}

// Convert an ungated vault to gated
function convert_to_gated(string $slug, string $password): bool {
    if (!is_vault_initialized($slug) || is_vault_gated($slug)) {
        return false;
    }
    $salt = random_bytes(32);
    $key = derive_key($password, $salt);
    $verifier = encrypt_data(CANARY_TEXT, $key);

    $originalConfig = get_vault_config($slug) ?? [];
    $config = array_merge($originalConfig, [
        'slug' => $slug,
        'is_gated' => true,
        'salt' => bin2hex($salt),
        'verifier' => $verifier,
        'kdf_iterations' => KDF_ITERATIONS,
        'updated_at' => date('c'),
    ]);

    $db = get_vault_db($slug);
    $stmt = $db->query("SELECT id, title_cipher, body_cipher FROM notes");
    $notes = $stmt->fetchAll();

    // The config (salt) is saved before the commit: committed ciphertext with
    // no saved salt could never be decrypted again.
    $db->beginTransaction();
    try {
        $updateStmt = $db->prepare("UPDATE notes SET title_cipher = :t, body_cipher = :b WHERE id = :id");
        foreach ($notes as $n) {
            $tEnc = encrypt_data($n['title_cipher'], $key);
            $bEnc = encrypt_data($n['body_cipher'], $key);
            $updateStmt->execute([':t' => $tEnc, ':b' => $bEnc, ':id' => $n['id']]);
        }
        if (!atomic_write_json(get_vault_config_file($slug), $config)) {
            throw new RuntimeException('Could not save vault config.');
        }
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        atomic_write_json(get_vault_config_file($slug), $originalConfig);
        error_log('keep-secured: vault conversion failed: ' . $e->getMessage());
        return false;
    }

    // Rebuild the file so the old plaintext does not linger in free pages.
    try {
        $db->exec('VACUUM');
    } catch (Throwable $e) {
        error_log('keep-secured: VACUUM after encryption failed: ' . $e->getMessage());
    }
    return true;
}

function get_ungated_vaults(): array {
    return list_vaults(false);
}

// Open vaults, plus encrypted ones when $include_gated is true.
function list_vaults(bool $include_gated): array {
    ensure_base_dirs();
    
    // Ensure default vault exists and is ungated
    if (!is_vault_initialized('default')) {
        initialize_ungated_vault('default');
    }

    $vaults = [];
    $dirs = glob(VAULTS_DIR . '/*', GLOB_ONLYDIR);
    if ($dirs) {
        foreach ($dirs as $dir) {
            $slug = basename($dir);
            $is_gated = is_vault_gated($slug);
            if (!$is_gated || $include_gated) {
                $vaults[] = [
                    'slug' => $slug,
                    'name' => $slug === 'default' ? 'General' : $slug,
                    'url'  => $slug === 'default' ? '/' : '/' . $slug,
                    'is_gated' => $is_gated,
                ];
            }
        }
    }

    // Sort so 'default' comes first
    usort($vaults, function($a, $b) {
        if ($a['slug'] === 'default') return -1;
        if ($b['slug'] === 'default') return 1;
        return strcmp($a['slug'], $b['slug']);
    });

    return $vaults;
}
