<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';

start_request();

if (!master_is_authenticated()) {
    render_master_login();
}

$enabled = master_config()['enabled'];
$showGatedLinks = show_gated_vault_links();
render_page_head('Settings — Keep Secured');
?>
<body>

<header class="app-header">
  <a href="https://github.com/usmanahmed/keep-secured" class="app-brand">
    <span>📝</span>
    <span>Keep Secured</span>
  </a>
  <div class="header-actions">
    <a href="<?= htmlspecialchars(app_url('/')) ?>" class="btn-secondary">← Back to notes</a>
  </div>
</header>

<main class="settings-page">
  <h1 class="settings-title">Settings</h1>

  <section class="settings-card">
    <div class="settings-card-head">
      <h2>Master password</h2>
      <span class="vault-badge <?= $enabled ? 'open' : 'gated' ?>"><?= $enabled ? 'Enabled' : 'Disabled' ?></span>
    </div>
    <p class="settings-help">
      One password, with no username, that protects the whole site.
      Encrypted vaults keep their own separate passwords.
    </p>

    <?php if (!$enabled): ?>
      <p class="settings-warning">
        The site is unprotected. Anyone who can reach it can read open vaults and set this password.
      </p>
      <form id="masterEnableForm" class="auth-form">
        <div class="auth-error" role="alert"></div>
        <div class="auth-input-group">
          <label for="enablePassword">New master password</label>
          <input type="password" id="enablePassword" name="password" class="auth-input" required autocomplete="new-password" placeholder="At least 8 characters">
        </div>
        <div class="auth-input-group">
          <label for="enableConfirm">Confirm password</label>
          <input type="password" id="enableConfirm" name="confirm" class="auth-input" required autocomplete="new-password" placeholder="Re-enter password">
        </div>
        <button type="submit" class="btn-primary">Enable master password</button>
      </form>
    <?php endif; ?>
  </section>

  <section class="settings-card settings-row">
    <div>
      <h2><label for="showGatedLinks">Show encrypted vault links</label></h2>
      <p class="settings-help">
        Lists encrypted vaults in the navigation bar. Their names become visible to anyone who can open the site; their notes stay locked.
      </p>
    </div>
    <input type="checkbox" id="showGatedLinks" class="toggle" role="switch" <?= $showGatedLinks ? 'checked' : '' ?>>
  </section>

  <?php if ($enabled): ?>
    <section class="settings-card">
      <h2>Change master password</h2>
      <p class="settings-help">Other devices will be signed out.</p>
      <form id="masterChangeForm" class="auth-form">
        <div class="auth-error" role="alert"></div>
        <div class="auth-input-group">
          <label for="changeCurrent">Current password</label>
          <input type="password" id="changeCurrent" name="current_password" class="auth-input" required autocomplete="current-password">
        </div>
        <div class="auth-input-group">
          <label for="changeNew">New password</label>
          <input type="password" id="changeNew" name="password" class="auth-input" required autocomplete="new-password" placeholder="At least 8 characters">
        </div>
        <div class="auth-input-group">
          <label for="changeConfirm">Confirm new password</label>
          <input type="password" id="changeConfirm" name="confirm" class="auth-input" required autocomplete="new-password">
        </div>
        <button type="submit" class="btn-primary">Change password</button>
      </form>
    </section>

    <section class="settings-card">
      <h2>Disable master password</h2>
      <p class="settings-help">The site will open without a password. Encrypted vaults stay encrypted.</p>
      <form id="masterDisableForm" class="auth-form">
        <div class="auth-error" role="alert"></div>
        <div class="auth-input-group">
          <label for="disableCurrent">Current password</label>
          <input type="password" id="disableCurrent" name="current_password" class="auth-input" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn-danger">Disable master password</button>
      </form>
    </section>

    <section class="settings-card settings-row">
      <div>
        <h2>Lock this device</h2>
        <p class="settings-help">Sign out here and lock any open encrypted vaults.</p>
      </div>
      <button id="masterLogoutBtn" type="button" class="btn-secondary btn-outline">Lock now</button>
    </section>
  <?php endif; ?>
</main>

<div id="toast" class="toast" role="status"></div>

</body>
</html>
