<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';

start_request();
header('Content-Type: application/json; charset=utf-8');

const READ_ONLY_ACTIONS = ['status', 'get_ungated_vaults', 'get_notes'];

function json_out(array $data, int $status = 200): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function get_request_data(): array {
    $json = json_decode((string)file_get_contents('php://input'), true);
    return is_array($json) ? $json : [];
}

function req_string(array $req, string $name, string $default = ''): string {
    return isset($req[$name]) && is_string($req[$name]) ? $req[$name] : $default;
}

function require_attempt_allowed(string $bucket): void {
    $wait = rate_limit_retry_after($bucket);
    if ($wait > 0) {
        header('Retry-After: ' . $wait);
        json_out(['error' => "Too many attempts. Try again in {$wait} seconds."], 429);
    }
}

// Rate-limited check of the current master password.
function require_master_password(string $password): void {
    require_attempt_allowed('master');
    if (!master_verify_password($password)) {
        rate_limit_record_failure('master');
        json_out(['error' => 'Incorrect master password.'], 401);
    }
    rate_limit_clear('master');
}

function require_valid_new_password(string $password): void {
    $error = new_password_error($password);
    if ($error !== null) {
        json_out(['error' => $error], 400);
    }
}

$action = is_string($_GET['action'] ?? null) ? $_GET['action'] : '';
$req = get_request_data();
$rawSlug = $_GET['vault'] ?? ($req['vault'] ?? null);
$slug = sanitize_vault_slug(is_string($rawSlug) ? $rawSlug : null);

if (!in_array($action, READ_ONLY_ACTIONS, true)) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_out(['error' => 'POST required.'], 405);
    }
    if (!csrf_is_valid()) {
        json_out(['error' => 'Session expired. Reload the page.', 'csrf_failed' => true], 403);
    }
}

$openActions = master_config()['unconfigured']
    ? ['master_login', 'master_enable', 'master_skip']
    : ['master_login'];
if (!in_array($action, $openActions, true) && !master_is_authenticated()) {
    json_out(['error' => 'Master password required.', 'master_locked' => true], 401);
}

try {
    // Ensure default vault always exists as ungated
    if ($slug === 'default' && !is_vault_initialized('default')) {
        initialize_ungated_vault('default');
    }

    switch ($action) {
        case 'master_login':
            if (master_config()['enabled']) {
                require_master_password(req_string($req, 'password'));
                master_mark_authenticated();
            }
            json_out(['success' => true]);
            break;

        case 'master_logout':
            $_SESSION = [];
            session_regenerate_id(true);
            json_out(['success' => true]);
            break;

        case 'master_enable':
            if (master_config()['enabled']) {
                json_out(['error' => 'Master password is already enabled.'], 400);
            }
            $password = req_string($req, 'password');
            require_valid_new_password($password);
            if (!master_set_password($password)) {
                json_out(['error' => 'Could not save the master password.'], 500);
            }
            master_mark_authenticated();
            json_out(['success' => true]);
            break;

        case 'master_skip':
            if (master_config()['unconfigured'] && !master_disable()) {
                json_out(['error' => 'Could not save the setting.'], 500);
            }
            json_out(['success' => true]);
            break;

        case 'master_change':
            if (!master_config()['enabled']) {
                json_out(['error' => 'Master password is not enabled.'], 400);
            }
            require_master_password(req_string($req, 'current_password'));
            $password = req_string($req, 'password');
            require_valid_new_password($password);
            if (!master_set_password($password)) {
                json_out(['error' => 'Could not save the master password.'], 500);
            }
            master_mark_authenticated();
            json_out(['success' => true]);
            break;

        case 'master_disable':
            if (!master_config()['enabled']) {
                json_out(['success' => true]);
            }
            require_master_password(req_string($req, 'current_password'));
            if (!master_disable()) {
                json_out(['error' => 'Could not save the setting.'], 500);
            }
            unset($_SESSION['master']);
            json_out(['success' => true]);
            break;

        case 'set_show_gated_links':
            if (!set_show_gated_vault_links(!empty($req['show']))) {
                json_out(['error' => 'Could not save the setting.'], 500);
            }
            json_out(['success' => true]);
            break;

        case 'status':
            $initialized = is_vault_initialized($slug);
            $is_gated = is_vault_gated($slug);
            $key = get_vault_auth_key($slug);
            $authenticated = ($key !== null);

            json_out([
                'slug' => $slug,
                'initialized' => $initialized,
                'is_gated' => $is_gated,
                'authenticated' => $authenticated,
                'ungated_vaults' => get_ungated_vaults(),
            ]);
            break;

        case 'get_ungated_vaults':
            json_out([
                'vaults' => get_ungated_vaults()
            ]);
            break;

        case 'setup':
            if (is_reserved_vault_slug($slug)) {
                json_out(['error' => 'That vault name is reserved.'], 400);
            }
            if (is_vault_initialized($slug)) {
                json_out(['error' => 'Vault already exists.'], 400);
            }
            $is_gated = !empty($req['is_gated']);
            if ($is_gated) {
                $password = req_string($req, 'password');
                require_valid_new_password($password);
                if (!initialize_gated_vault($slug, $password)) {
                    json_out(['error' => 'Failed to initialize encrypted vault.'], 500);
                }
                store_vault_key($slug, verify_vault_password($slug, $password));
            } else {
                if (!initialize_ungated_vault($slug)) {
                    json_out(['error' => 'Failed to initialize open vault.'], 500);
                }
            }
            json_out(['success' => true]);
            break;

        case 'login':
            if (!is_vault_initialized($slug)) {
                json_out(['error' => 'Vault does not exist.'], 404);
            }
            if (!is_vault_gated($slug)) {
                json_out(['success' => true]);
            }
            $bucket = 'vault:' . $slug;
            require_attempt_allowed($bucket);
            $key = verify_vault_password($slug, req_string($req, 'password'));
            if ($key === null) {
                rate_limit_record_failure($bucket);
                json_out(['error' => 'Incorrect password.'], 401);
            }
            rate_limit_clear($bucket);
            store_vault_key($slug, $key);
            json_out(['success' => true]);
            break;

        case 'logout':
            clear_vault_key($slug);
            json_out(['success' => true]);
            break;

        case 'make_gated':
            // Encrypt an ungated vault
            if (!is_vault_initialized($slug)) {
                json_out(['error' => 'Vault does not exist.'], 404);
            }
            if (is_vault_gated($slug)) {
                json_out(['error' => 'Vault is already encrypted.'], 400);
            }
            $password = req_string($req, 'password');
            require_valid_new_password($password);
            if (!convert_to_gated($slug, $password)) {
                json_out(['error' => 'Failed to convert to encrypted vault.'], 500);
            }
            store_vault_key($slug, verify_vault_password($slug, $password));
            json_out(['success' => true]);
            break;

        case 'get_notes':
            $key = get_vault_auth_key($slug);
            if ($key === null) {
                json_out(['error' => 'Locked. Authentication required.', 'locked' => true], 401);
            }
            $is_gated = is_vault_gated($slug);
            $db = get_vault_db($slug);
            $stmt = $db->query("SELECT id, title_cipher, body_cipher, color, is_pinned, updated_at FROM notes ORDER BY is_pinned DESC, updated_at DESC");
            $rows = $stmt->fetchAll();

            $notes = [];
            foreach ($rows as $row) {
                if ($is_gated) {
                    $title = decrypt_data($row['title_cipher'], $key) ?? '';
                    $body = decrypt_data($row['body_cipher'], $key) ?? '';
                } else {
                    $title = $row['title_cipher'];
                    $body = $row['body_cipher'];
                }
                $notes[] = [
                    'id' => (int)$row['id'],
                    'title' => $title,
                    'body' => $body,
                    'color' => $row['color'],
                    'is_pinned' => (bool)$row['is_pinned'],
                    'updated_at' => $row['updated_at'],
                ];
            }
            json_out([
                'notes' => $notes,
                'slug' => $slug,
                'is_gated' => $is_gated,
            ]);
            break;

        case 'save_note':
            $key = get_vault_auth_key($slug);
            if ($key === null) {
                json_out(['error' => 'Locked. Authentication required.'], 401);
            }
            $is_gated = is_vault_gated($slug);
            $id = isset($req['id']) && $req['id'] !== '' ? (int)$req['id'] : null;
            $title = req_string($req, 'title');
            $body = req_string($req, 'body');
            $color = req_string($req, 'color', '#ffffff');
            $is_pinned = !empty($req['is_pinned']) ? 1 : 0;

            if (trim($title) === '' && trim($body) === '') {
                json_out(['error' => 'Note cannot be completely empty.'], 400);
            }

            if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
                $color = '#ffffff';
            }

            if ($is_gated) {
                $title_cipher = encrypt_data($title, $key);
                $body_cipher = encrypt_data($body, $key);
            } else {
                $title_cipher = $title;
                $body_cipher = $body;
            }

            $db = get_vault_db($slug);
            if ($id !== null && $id > 0) {
                $stmt = $db->prepare("
                    UPDATE notes
                    SET title_cipher = :title, body_cipher = :body, color = :color, is_pinned = :pinned, updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id
                ");
                $stmt->execute([
                    ':title' => $title_cipher,
                    ':body' => $body_cipher,
                    ':color' => $color,
                    ':pinned' => $is_pinned,
                    ':id' => $id,
                ]);
            } else {
                $stmt = $db->prepare("
                    INSERT INTO notes (title_cipher, body_cipher, color, is_pinned, created_at, updated_at)
                    VALUES (:title, :body, :color, :pinned, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ");
                $stmt->execute([
                    ':title' => $title_cipher,
                    ':body' => $body_cipher,
                    ':color' => $color,
                    ':pinned' => $is_pinned,
                ]);
                $id = (int)$db->lastInsertId();
            }

            json_out([
                'success' => true,
                'note' => [
                    'id' => $id,
                    'title' => $title,
                    'body' => $body,
                    'color' => $color,
                    'is_pinned' => (bool)$is_pinned,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]
            ]);
            break;

        case 'delete_note':
            $key = get_vault_auth_key($slug);
            if ($key === null) {
                json_out(['error' => 'Locked.'], 401);
            }
            $id = (int)($req['id'] ?? 0);
            if ($id <= 0) {
                json_out(['error' => 'Invalid note ID.'], 400);
            }
            $db = get_vault_db($slug);
            $stmt = $db->prepare("DELETE FROM notes WHERE id = :id");
            $stmt->execute([':id' => $id]);
            json_out(['success' => true]);
            break;

        case 'toggle_pin':
            $key = get_vault_auth_key($slug);
            if ($key === null) {
                json_out(['error' => 'Locked.'], 401);
            }
            $id = (int)($req['id'] ?? 0);
            if ($id <= 0) {
                json_out(['error' => 'Invalid note ID.'], 400);
            }
            $db = get_vault_db($slug);
            $stmt = $db->prepare("UPDATE notes SET is_pinned = 1 - is_pinned, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
            $stmt->execute([':id' => $id]);
            json_out(['success' => true]);
            break;

        default:
            json_out(['error' => 'Unknown action.'], 404);
    }
} catch (Throwable $e) {
    error_log('keep-secured: ' . $e);
    json_out(['error' => 'Server error.'], 500);
}
