<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';

start_request();

if (!master_is_authenticated()) {
    render_master_login();
}

$rawSlug = $_GET['vault'] ?? '';
$slug = sanitize_vault_slug(is_string($rawSlug) ? $rawSlug : '');

// Ensure default vault is initialized and ungated
if ($slug === 'default' && !is_vault_initialized('default')) {
    initialize_ungated_vault('default');
}

$initialized = is_vault_initialized($slug);
$is_gated = $initialized ? is_vault_gated($slug) : false;
$authenticated = $initialized && get_vault_auth_key($slug) !== null;

$nav_vaults = list_vaults(show_gated_vault_links());

render_page_head($slug === 'default' ? 'Keep Secured' : $slug . ' — Keep Secured');
?>
<body data-vault="<?= htmlspecialchars($slug) ?>" data-gated="<?= $is_gated ? '1' : '0' ?>">

<!-- Top Header Navigation Bar (Common across views) -->
<header class="app-header">
  <div class="header-left">
    <a href="<?= htmlspecialchars(app_url('/')) ?>" class="app-brand">
      <span>📝</span>
      <span>Keep Secured</span>
    </a>

    <!-- Vault Navigation (encrypted vaults appear only if enabled in Settings) -->
    <nav class="vault-nav-bar" aria-label="Vaults">
      <?php foreach ($nav_vaults as $uv): ?>
        <a href="<?= htmlspecialchars(app_url($uv['url'])) ?>"
           class="vault-link <?= ($uv['slug'] === $slug) ? 'active' : '' ?>">
          <?= $uv['slug'] === 'default' ? '🏠 Default' : ($uv['is_gated'] ? '🔒 ' : '📁 ') . htmlspecialchars($uv['name']) ?>
        </a>
      <?php endforeach; ?>
      <button id="newVaultBtn" type="button" class="btn-new-vault" title="Create or open a vault by name">+ New Vault</button>
    </nav>
  </div>

  <?php if ($initialized && $authenticated): ?>
    <div class="search-bar-wrap">
      <span class="search-icon">🔍</span>
      <input type="search" id="searchInput" class="search-input" placeholder="Search notes in <?= htmlspecialchars($slug) ?>...">
    </div>

    <div class="header-actions">
      <span class="vault-badge <?= $is_gated ? 'gated' : 'open' ?>">
        <?= $is_gated ? '🔒 Encrypted' : '🔓 Open' ?>
      </span>
      <?php if ($is_gated): ?>
        <button id="logoutBtn" class="btn-icon" title="Lock this vault" aria-label="Lock this vault">🔒</button>
      <?php else: ?>
        <button id="encryptVaultBtn" class="btn-icon" title="Protect this vault with a password" aria-label="Protect this vault with a password">🛡️</button>
      <?php endif; ?>
      <a href="<?= htmlspecialchars(app_url('/settings')) ?>" class="btn-icon" title="Settings" aria-label="Settings">⚙️</a>
    </div>
  <?php else: ?>
    <div class="header-actions">
      <span class="vault-badge <?= $is_gated ? 'gated' : 'open' ?>">
        <?= $slug === 'default' ? 'Default' : '/' . htmlspecialchars($slug) ?>
      </span>
      <a href="<?= htmlspecialchars(app_url('/settings')) ?>" class="btn-icon" title="Settings" aria-label="Settings">⚙️</a>
    </div>
  <?php endif; ?>
</header>

<?php if (!$initialized): ?>
  <!-- Vault Setup Screen (New / Custom Vault) -->
  <div class="auth-container">
    <div class="auth-card" style="max-width: 480px;">
      <div class="auth-icon">📂</div>
      <h1 class="auth-title">Initialize Vault: /<?= htmlspecialchars($slug) ?></h1>
      <p class="auth-subtitle">Decide whether this vault should be open or gated behind encryption.</p>

      <div id="setupError" class="auth-error" role="alert"></div>

      <form id="setupVaultForm">
        <div class="radio-choice-group">
          <label class="choice-card selected" id="choiceUngated">
            <input type="radio" name="vaultType" value="ungated" checked>
            <div>
              <strong>🔓 Open Vault (Ungated)</strong>
              <div style="font-size: 12px; color: var(--text-secondary);">No password needed. A quick link will appear in the navigation bar.</div>
            </div>
          </label>

          <label class="choice-card" id="choiceGated">
            <input type="radio" name="vaultType" value="gated">
            <div>
              <strong>🔒 Encrypted Vault (Gated)</strong>
              <div style="font-size: 12px; color: var(--text-secondary);">Protected with AES-256-GCM. Auto-locks after 2 minutes. <strong>Hidden from navigation unless enabled in Settings.</strong></div>
            </div>
          </label>
        </div>

        <div id="passwordFields" style="display: none; text-align: left; margin-bottom: 16px;">
          <div class="auth-input-group" style="margin-bottom: 12px;">
            <label for="vaultPassword">Vault Password</label>
            <input type="password" id="vaultPassword" class="auth-input" autocomplete="new-password" placeholder="At least 8 characters">
          </div>
          <div class="auth-input-group">
            <label for="confirmVaultPassword">Confirm Password</label>
            <input type="password" id="confirmVaultPassword" class="auth-input" autocomplete="new-password" placeholder="Re-enter password">
          </div>
        </div>

        <button type="submit" class="btn-primary" style="width: 100%;">Create /<?= htmlspecialchars($slug) ?></button>
      </form>
    </div>
  </div>

<?php elseif (!$authenticated): ?>
  <!-- Gated Vault Locked Screen -->
  <div class="auth-container">
    <div class="auth-card">
      <div class="auth-icon">🔒</div>
      <h1 class="auth-title">Vault Locked: /<?= htmlspecialchars($slug) ?></h1>
      <p class="auth-subtitle">This vault is encrypted. Enter your password to unlock your notes.</p>

      <div id="loginError" class="auth-error" role="alert"></div>

      <form id="loginForm" class="auth-form">
        <div class="auth-input-group">
          <label for="vaultLoginPassword">Vault Password</label>
          <input type="password" id="vaultLoginPassword" class="auth-input" required autofocus autocomplete="current-password" placeholder="Enter password">
        </div>
        <button type="submit" class="btn-primary">Unlock Notes</button>
      </form>
    </div>
  </div>

<?php else: ?>
  <!-- Authenticated Notes App Screen -->
  <div id="notesApp">
    <!-- Main Content Area -->
    <main class="main-content">
      <!-- Note Creator -->
      <div class="creator-container">
        <div id="creatorCard" class="creator-card">
          <!-- Collapsed View -->
          <div id="creatorCollapsed" class="creator-collapsed">
            Take a note in <?= htmlspecialchars($slug === 'default' ? 'Default Vault' : '/' . $slug) ?>...
          </div>

          <!-- Expanded View -->
          <div id="creatorExpanded" style="display: none;">
            <div class="creator-title-row">
              <input type="text" id="creatorTitle" class="creator-title" placeholder="Title">
              <button id="creatorPinBtn" class="pin-btn" title="Pin note" aria-label="Pin note">📍</button>
            </div>
            <textarea id="creatorBody" class="creator-body" rows="3" placeholder="Take a note..."></textarea>

            <div class="creator-actions">
              <div id="creatorPalette" class="color-palette"></div>
              <div class="action-buttons">
                <button id="creatorCloseBtn" class="btn-secondary">Close</button>
                <button id="creatorSaveBtn" class="btn-primary btn-compact">Save</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Pinned Notes Section -->
      <div id="pinnedSection" style="display: none;">
        <h2 class="section-heading">Pinned</h2>
        <div id="pinnedGrid" class="notes-grid"></div>
      </div>

      <!-- Other Notes Section -->
      <div id="othersSection" style="display: none;">
        <h2 class="section-heading">Notes</h2>
        <div id="othersGrid" class="notes-grid"></div>
      </div>

      <!-- Empty State -->
      <div id="emptyState" class="empty-state" style="display: none;">
        <div class="empty-state-icon">💡</div>
        <p>No notes in this vault. Notes you add appear here!</p>
      </div>
    </main>

    <!-- Edit Note Modal -->
    <div id="editModal" class="modal-overlay">
      <div class="modal-card">
        <div class="modal-title-row">
          <input type="text" id="modalTitle" class="modal-title" placeholder="Title">
          <button id="modalPinBtn" class="pin-btn" title="Pin note" aria-label="Pin note">📍</button>
        </div>
        <textarea id="modalBody" class="modal-body" placeholder="Note content..."></textarea>

        <div class="modal-actions">
          <div id="modalPalette" class="color-palette"></div>
          <div class="action-buttons">
            <button id="modalDeleteBtn" class="btn-icon" title="Delete note" aria-label="Delete note" style="color: var(--danger-color);">🗑️</button>
            <button id="modalCloseBtn" class="btn-primary btn-compact">Done</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Encrypt Open Vault Modal -->
    <?php if (!$is_gated): ?>
    <div id="encryptModal" class="modal-overlay">
      <div class="modal-card" style="max-width: 440px;">
        <h3 style="font-size: 18px; margin-bottom: 8px;">🔒 Encrypt Vault: /<?= htmlspecialchars($slug) ?></h3>
        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
          Set a vault password. All existing and future notes in this vault will be encrypted with AES-256-GCM.
          It will be <strong>hidden from the navigation links</strong> unless you enable them in Settings.
        </p>
        <div class="auth-input-group" style="margin-bottom: 12px;">
          <label for="encPass">Vault Password</label>
          <input type="password" id="encPass" class="auth-input" autocomplete="new-password" placeholder="At least 8 characters">
        </div>
        <div class="auth-input-group" style="margin-bottom: 16px;">
          <label for="encPass2">Confirm Password</label>
          <input type="password" id="encPass2" class="auth-input" autocomplete="new-password" placeholder="Confirm password">
        </div>
        <div class="dialog-buttons">
          <button id="btnCancelEncrypt" class="btn-secondary">Cancel</button>
          <button id="btnSubmitEncrypt" class="btn-primary">Encrypt Vault</button>
        </div>
      </div>
    </div>
    <?php endif; ?>
  </div>
<?php endif; ?>

<!-- New Vault Modal (Available everywhere) -->
<div id="newVaultModal" class="modal-overlay">
  <div class="modal-card" style="max-width: 420px;">
    <h3 style="font-size: 18px; margin-bottom: 6px;">📂 Open or Create Vault</h3>
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      Enter the name/slug for the vault (e.g. <code>work</code>, <code>personal</code>, <code>xyz</code>).
    </p>
    <form id="newVaultForm">
      <div class="auth-input-group" style="margin-bottom: 16px;">
        <label for="newVaultSlugInput">Vault Slug</label>
        <input type="text" id="newVaultSlugInput" class="auth-input" placeholder="e.g. project-x" autocapitalize="none" autocorrect="off" required>
      </div>
      <div class="dialog-buttons">
        <button id="newVaultCancel" type="button" class="btn-secondary">Cancel</button>
        <button type="submit" class="btn-primary">Go to Vault</button>
      </div>
    </form>
  </div>
</div>

<div id="toast" class="toast" role="status"></div>

</body>
</html>
