document.addEventListener('DOMContentLoaded', () => {
  const currentVault = document.body.dataset.vault || 'default';
  const isVaultGated = document.body.dataset.gated === '1';
  const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
  const basePath = document.querySelector('meta[name="base-path"]').content;
  const MIN_PASSWORD_LENGTH = 8;
  const canHover = window.matchMedia('(hover: hover)').matches;

  const COLORS = [
    '#ffffff', // Default White
    '#f28b82', // Red/Coral
    '#fbbc04', // Orange
    '#fff475', // Yellow
    '#ccff90', // Green
    '#a7ffeb', // Teal
    '#cbf0f8', // Sky Blue
    '#aecbfa', // Periwinkle Blue
    '#d7aefb', // Lavender
    '#fdcfe8', // Pink
    '#e6c9a8', // Sand
    '#e8eaed'  // Gray
  ];

  let notes = [];
  let currentCreatorColor = '#ffffff';
  let isCreatorPinned = false;
  let activeModalNoteId = null;
  let currentModalColor = '#ffffff';

  // Elements
  const pinnedSection = document.getElementById('pinnedSection');
  const pinnedGrid = document.getElementById('pinnedGrid');
  const othersSection = document.getElementById('othersSection');
  const othersGrid = document.getElementById('othersGrid');
  const emptyState = document.getElementById('emptyState');
  const searchInput = document.getElementById('searchInput');
  const logoutBtn = document.getElementById('logoutBtn');
  const encryptVaultBtn = document.getElementById('encryptVaultBtn');
  const encryptModal = document.getElementById('encryptModal');
  const btnSubmitEncrypt = document.getElementById('btnSubmitEncrypt');
  const toastEl = document.getElementById('toast');

  // Creator Elements
  const creatorCard = document.getElementById('creatorCard');
  const creatorCollapsed = document.getElementById('creatorCollapsed');
  const creatorExpanded = document.getElementById('creatorExpanded');
  const creatorTitle = document.getElementById('creatorTitle');
  const creatorBody = document.getElementById('creatorBody');
  const creatorPalette = document.getElementById('creatorPalette');
  const creatorPinBtn = document.getElementById('creatorPinBtn');
  const creatorSaveBtn = document.getElementById('creatorSaveBtn');
  const creatorCloseBtn = document.getElementById('creatorCloseBtn');

  // Modal Elements
  const editModal = document.getElementById('editModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalPalette = document.getElementById('modalPalette');
  const modalSaveBtn = document.getElementById('modalSaveBtn');
  const modalDeleteBtn = document.getElementById('modalDeleteBtn');
  const modalCloseBtn = document.getElementById('modalCloseBtn');
  const modalPinBtn = document.getElementById('modalPinBtn');
  let isModalPinned = false;

  function showToast(message) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.classList.add('visible');
    setTimeout(() => {
      toastEl.classList.remove('visible');
    }, 2500);
  }

  function getApiUrl(action) {
    return `${basePath}/api.php?action=${encodeURIComponent(action)}&vault=${encodeURIComponent(currentVault)}`;
  }

  async function postApi(action, payload = {}) {
    const res = await fetch(getApiUrl(action), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.master_locked || data.csrf_failed) {
      window.location.reload();
    }
    return data;
  }

  function showFormError(el, message) {
    if (!el) return;
    el.textContent = message;
    el.style.display = message ? 'block' : 'none';
  }

  // Returns an error message for a new password, or '' when it is acceptable.
  function newPasswordProblem(password, confirmation) {
    if (password !== confirmation) return 'Passwords do not match.';
    if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
    return '';
  }

  function renderPalettes() {
    if (creatorPalette) {
      creatorPalette.innerHTML = '';
      COLORS.forEach(c => {
        const dot = document.createElement('div');
        dot.className = `color-dot ${c === currentCreatorColor ? 'active' : ''}`;
        dot.style.backgroundColor = c;
        dot.title = c;
        dot.onclick = () => {
          currentCreatorColor = c;
          creatorCard.style.backgroundColor = c;
          renderPalettes();
        };
        creatorPalette.appendChild(dot);
      });
    }

    if (modalPalette) {
      modalPalette.innerHTML = '';
      COLORS.forEach(c => {
        const dot = document.createElement('div');
        dot.className = `color-dot ${c === currentModalColor ? 'active' : ''}`;
        dot.style.backgroundColor = c;
        dot.title = c;
        dot.onclick = () => {
          currentModalColor = c;
          document.querySelector('.modal-card').style.backgroundColor = c;
          renderPalettes();
        };
        modalPalette.appendChild(dot);
      });
    }
  }

  async function fetchNotes() {
    try {
      const res = await fetch(getApiUrl('get_notes'));
      if (res.status === 401) {
        window.location.reload();
        return;
      }
      const data = await res.json();
      if (data.notes) {
        notes = data.notes;
        renderNotes();
      }
    } catch (err) {
      showToast('Error loading notes');
    }
  }

  function renderNotes() {
    const query = (searchInput ? searchInput.value.toLowerCase().trim() : '');
    const filtered = notes.filter(n => {
      if (!query) return true;
      return (n.title && n.title.toLowerCase().includes(query)) ||
             (n.body && n.body.toLowerCase().includes(query));
    });

    const pinned = filtered.filter(n => n.is_pinned);
    const others = filtered.filter(n => !n.is_pinned);

    if (pinnedGrid && othersGrid && pinnedSection && othersSection && emptyState) {
      pinnedGrid.innerHTML = '';
      othersGrid.innerHTML = '';

      if (filtered.length === 0) {
        emptyState.style.display = 'block';
        pinnedSection.style.display = 'none';
        othersSection.style.display = 'none';
        return;
      }

      emptyState.style.display = 'none';

      if (pinned.length > 0) {
        pinnedSection.style.display = 'block';
        pinned.forEach(n => pinnedGrid.appendChild(createNoteCard(n)));
      } else {
        pinnedSection.style.display = 'none';
      }

      if (others.length > 0) {
        othersSection.style.display = 'block';
        others.forEach(n => othersGrid.appendChild(createNoteCard(n)));
      } else {
        othersSection.style.display = 'none';
      }
    }
  }

  function createNoteCard(note) {
    const card = document.createElement('div');
    card.className = 'note-card';
    card.style.backgroundColor = note.color || '#ffffff';

    const header = document.createElement('div');
    header.className = 'note-header';

    const titleEl = document.createElement('div');
    titleEl.className = 'note-title';
    titleEl.textContent = note.title || '';

    const pinBtn = document.createElement('button');
    pinBtn.className = `pin-btn ${note.is_pinned ? 'pinned' : ''}`;
    pinBtn.title = note.is_pinned ? 'Unpin note' : 'Pin note';
    pinBtn.innerHTML = note.is_pinned ? '📌' : '📍';
    pinBtn.onclick = (e) => {
      e.stopPropagation();
      togglePin(note.id);
    };

    header.appendChild(titleEl);
    header.appendChild(pinBtn);
    card.appendChild(header);

    if (note.body) {
      const bodyEl = document.createElement('div');
      bodyEl.className = 'note-body';
      bodyEl.textContent = note.body;
      card.appendChild(bodyEl);
    }

    const footer = document.createElement('div');
    footer.className = 'note-footer';

    const dateSpan = document.createElement('span');
    const d = new Date(note.updated_at || Date.now());
    dateSpan.textContent = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

    const actions = document.createElement('div');
    actions.className = 'note-actions';

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'action-icon delete';
    deleteBtn.title = 'Delete note';
    deleteBtn.innerHTML = '🗑️';
    deleteBtn.onclick = (e) => {
      e.stopPropagation();
      deleteNote(note.id);
    };

    actions.appendChild(deleteBtn);
    footer.appendChild(dateSpan);
    footer.appendChild(actions);
    card.appendChild(footer);

    card.onclick = () => openEditModal(note);

    return card;
  }

  // Creator Handlers
  function expandCreator() {
    creatorCollapsed.style.display = 'none';
    creatorExpanded.style.display = 'block';
    creatorCard.classList.add('focused');
    creatorBody.focus();
    renderPalettes();
  }

  function collapseCreator(saveIfNotEmpty = true) {
    if (saveIfNotEmpty) {
      saveNewNote();
    }
    creatorTitle.value = '';
    creatorBody.value = '';
    currentCreatorColor = '#ffffff';
    isCreatorPinned = false;
    creatorCard.style.backgroundColor = '#ffffff';
    if (creatorPinBtn) creatorPinBtn.innerHTML = '📍';
    creatorCollapsed.style.display = 'block';
    creatorExpanded.style.display = 'none';
    creatorCard.classList.remove('focused');
  }

  async function saveNewNote() {
    const title = creatorTitle.value.trim();
    const body = creatorBody.value.trim();
    if (!title && !body) return;

    try {
      const data = await postApi('save_note', {
        title,
        body,
        color: currentCreatorColor,
        is_pinned: isCreatorPinned ? 1 : 0
        });
      if (data.success && data.note) {
        notes.unshift(data.note);
        renderNotes();
        showToast('Note saved');
      } else if (data.error) {
        showToast(data.error);
      }
    } catch (err) {
      showToast('Failed to save note');
    }
  }

  if (creatorCollapsed) {
    creatorCollapsed.onclick = expandCreator;
  }

  if (creatorCloseBtn) {
    creatorCloseBtn.onclick = () => collapseCreator(true);
  }

  if (creatorSaveBtn) {
    creatorSaveBtn.onclick = () => collapseCreator(true);
  }

  if (creatorPinBtn) {
    creatorPinBtn.onclick = () => {
      isCreatorPinned = !isCreatorPinned;
      creatorPinBtn.innerHTML = isCreatorPinned ? '📌' : '📍';
    };
  }

  // Modal Handlers
  function openEditModal(note) {
    activeModalNoteId = note.id;
    currentModalColor = note.color || '#ffffff';
    isModalPinned = !!note.is_pinned;

    modalTitle.value = note.title || '';
    modalBody.value = note.body || '';
    document.querySelector('.modal-card').style.backgroundColor = currentModalColor;
    if (modalPinBtn) modalPinBtn.innerHTML = isModalPinned ? '📌' : '📍';

    renderPalettes();
    editModal.style.display = 'flex';
    if (canHover) modalBody.focus();
  }

  function closeEditModal() {
    editModal.style.display = 'none';
    activeModalNoteId = null;
  }

  async function saveModalNote() {
    if (!activeModalNoteId) return;
    const title = modalTitle.value.trim();
    const body = modalBody.value.trim();

    if (!title && !body) {
      deleteNote(activeModalNoteId);
      closeEditModal();
      return;
    }

    try {
      const data = await postApi('save_note', {
        id: activeModalNoteId,
        title,
        body,
        color: currentModalColor,
        is_pinned: isModalPinned ? 1 : 0
        });
      if (data.success && data.note) {
        const idx = notes.findIndex(n => n.id === activeModalNoteId);
        if (idx !== -1) {
          notes[idx] = data.note;
        }
        renderNotes();
        closeEditModal();
        showToast('Note updated');
      }
    } catch (err) {
      showToast('Error updating note');
    }
  }

  if (modalCloseBtn) modalCloseBtn.onclick = saveModalNote;
  if (modalSaveBtn) modalSaveBtn.onclick = saveModalNote;

  if (modalPinBtn) {
    modalPinBtn.onclick = () => {
      isModalPinned = !isModalPinned;
      modalPinBtn.innerHTML = isModalPinned ? '📌' : '📍';
    };
  }

  if (modalDeleteBtn) {
    modalDeleteBtn.onclick = () => {
      if (activeModalNoteId) {
        deleteNote(activeModalNoteId);
        closeEditModal();
      }
    };
  }

  if (editModal) {
    editModal.onclick = (e) => {
      if (e.target === editModal) {
        saveModalNote();
      }
    };
  }

  // Pin / Delete / Search
  async function togglePin(id) {
    try {
      const data = await postApi('toggle_pin', { id });
      if (data.success) {
        const note = notes.find(n => n.id === id);
        if (note) {
          note.is_pinned = !note.is_pinned;
          renderNotes();
        }
      }
    } catch (err) {
      showToast('Failed to toggle pin');
    }
  }

  async function deleteNote(id) {
    if (!confirm('Are you sure you want to delete this note?')) return;
    try {
      const data = await postApi('delete_note', { id });
      if (data.success) {
        notes = notes.filter(n => n.id !== id);
        renderNotes();
        showToast('Note deleted');
      }
    } catch (err) {
      showToast('Failed to delete note');
    }
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderNotes();
    });
  }

  // Lock Gated Vault
  if (logoutBtn) {
    logoutBtn.onclick = async () => {
      await postApi('logout');
      window.location.reload();
    };
  }

  // Encrypt an Ungated Vault
  if (encryptVaultBtn && encryptModal) {
    encryptVaultBtn.onclick = () => {
      encryptModal.style.display = 'flex';
      document.getElementById('encPass').focus();
    };
  }

  const btnCancelEncrypt = document.getElementById('btnCancelEncrypt');
  if (btnCancelEncrypt) {
    btnCancelEncrypt.onclick = () => { encryptModal.style.display = 'none'; };
  }

  if (btnSubmitEncrypt) {
    btnSubmitEncrypt.onclick = async () => {
      const p1 = document.getElementById('encPass').value;
      const p2 = document.getElementById('encPass2').value;
      const problem = newPasswordProblem(p1, p2);
      if (problem) {
        alert(problem);
        return;
      }
      try {
        const data = await postApi('make_gated', { password: p1 });
        if (data.success) {
          window.location.reload();
        } else {
          alert(data.error || 'Failed to encrypt vault.');
        }
      } catch (e) {
        alert('Communication error.');
      }
    };
  }

  // Auto-lock after 2 minutes of inactivity ONLY for gated/encrypted vaults
  if (isVaultGated) {
    const INACTIVITY_TIMEOUT_MS = 2 * 60 * 1000;
    let inactivityTimer = null;

    function resetInactivityTimer() {
      if (inactivityTimer) {
        clearTimeout(inactivityTimer);
      }
      inactivityTimer = setTimeout(async () => {
        try {
          await postApi('logout');
        } catch (err) {}
        window.location.reload();
      }, INACTIVITY_TIMEOUT_MS);
    }

    ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
      window.addEventListener(evt, resetInactivityTimer, { passive: true });
    });
    resetInactivityTimer();
  }

  // New vault dialog
  const newVaultBtn = document.getElementById('newVaultBtn');
  const newVaultModal = document.getElementById('newVaultModal');
  const newVaultInput = document.getElementById('newVaultSlugInput');
  if (newVaultBtn && newVaultModal) {
    newVaultBtn.onclick = () => {
      newVaultModal.style.display = 'flex';
      newVaultInput.focus();
    };
    document.getElementById('newVaultCancel').onclick = () => {
      newVaultModal.style.display = 'none';
    };
    document.getElementById('newVaultForm').onsubmit = (e) => {
      e.preventDefault();
      const slug = newVaultInput.value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
      if (slug) window.location.href = `${basePath}/${slug}`;
    };
  }

  // New vault setup screen
  const setupVaultForm = document.getElementById('setupVaultForm');
  if (setupVaultForm) {
    const errBox = document.getElementById('setupError');
    const passwordField = document.getElementById('vaultPassword');

    document.querySelectorAll('input[name="vaultType"]').forEach(radio => {
      radio.addEventListener('change', () => {
        const isGated = radio.value === 'gated';
        document.getElementById('passwordFields').style.display = isGated ? 'block' : 'none';
        document.getElementById('choiceGated').classList.toggle('selected', isGated);
        document.getElementById('choiceUngated').classList.toggle('selected', !isGated);
        if (isGated) passwordField.focus();
      });
    });

    setupVaultForm.onsubmit = async (e) => {
      e.preventDefault();
      showFormError(errBox, '');
      const isGated = document.querySelector('input[name="vaultType"]:checked').value === 'gated';
      const password = isGated ? passwordField.value : '';
      if (isGated) {
        const problem = newPasswordProblem(password, document.getElementById('confirmVaultPassword').value);
        if (problem) {
          showFormError(errBox, problem);
          return;
        }
      }
      try {
        const data = await postApi('setup', { is_gated: isGated, password });
        if (data.success) {
          window.location.reload();
        } else {
          showFormError(errBox, data.error || 'Failed to create vault.');
        }
      } catch (err) {
        showFormError(errBox, 'Communication error.');
      }
    };
  }

  // Locked vault screen
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    const errBox = document.getElementById('loginError');
    loginForm.onsubmit = async (e) => {
      e.preventDefault();
      showFormError(errBox, '');
      try {
        const data = await postApi('login', { password: document.getElementById('vaultLoginPassword').value });
        if (data.success) {
          window.location.reload();
        } else {
          showFormError(errBox, data.error || 'Incorrect password.');
        }
      } catch (err) {
        showFormError(errBox, 'Network or server error.');
      }
    };
  }

  // Master password forms (lock screen and settings page)
  function bindMasterForm(formId, action, onSuccess) {
    const form = document.getElementById(formId);
    if (!form) return;
    const errBox = form.querySelector('.auth-error');
    form.onsubmit = async (e) => {
      e.preventDefault();
      showFormError(errBox, '');
      const fields = Object.fromEntries(new FormData(form));
      if ('confirm' in fields) {
        const problem = newPasswordProblem(fields.password, fields.confirm);
        if (problem) {
          showFormError(errBox, problem);
          return;
        }
      }
      const submit = form.querySelector('[type="submit"]');
      submit.disabled = true;
      try {
        const data = await postApi(action, fields);
        if (data.success) {
          onSuccess(form);
        } else {
          showFormError(errBox, data.error || 'Something went wrong.');
        }
      } catch (err) {
        showFormError(errBox, 'Network or server error.');
      } finally {
        submit.disabled = false;
      }
    };
  }

  const reloadPage = () => window.location.reload();
  bindMasterForm('masterLoginForm', 'master_login', reloadPage);
  bindMasterForm('masterEnableForm', 'master_enable', reloadPage);
  bindMasterForm('masterDisableForm', 'master_disable', reloadPage);
  bindMasterForm('masterChangeForm', 'master_change', (form) => {
    form.reset();
    showToast('Master password changed');
  });

  const showGatedLinks = document.getElementById('showGatedLinks');
  if (showGatedLinks) {
    showGatedLinks.onchange = async () => {
      const show = showGatedLinks.checked;
      showGatedLinks.disabled = true;
      try {
        const data = await postApi('set_show_gated_links', { show });
        if (!data.success) throw new Error(data.error);
        showToast(show ? 'Encrypted vault links shown' : 'Encrypted vault links hidden');
      } catch (err) {
        showGatedLinks.checked = !show;
        showToast('Could not save the setting');
      } finally {
        showGatedLinks.disabled = false;
      }
    };
  }

  const masterSkipBtn = document.getElementById('masterSkipBtn');
  if (masterSkipBtn) {
    masterSkipBtn.onclick = async () => {
      if (!confirm('Anyone who can reach this site will be able to use it. Continue?')) return;
      await postApi('master_skip');
      window.location.reload();
    };
  }

  const masterLogoutBtn = document.getElementById('masterLogoutBtn');
  if (masterLogoutBtn) {
    masterLogoutBtn.onclick = async () => {
      await postApi('master_logout');
      window.location.reload();
    };
  }

  function setInstallCheck(row, state, fixText = null) {
    row.className = `install-check is-${state}`;
    const fix = row.querySelector('.install-fix');
    if (fixText !== null) fix.textContent = fixText;
    fix.hidden = state === 'ok';
  }

  async function runDataCheck(row) {
    try {
      const res = await fetch(row.dataset.url, { cache: 'no-store' });
      const isExposed = res.ok && (await res.text()).trim() === row.dataset.token;
      setInstallCheck(row, isExposed ? 'fail' : 'ok');
      if (isExposed) {
        // Finishing now would put the password hash where anyone can download it.
        document.getElementById('installSetup').hidden = true;
        document.getElementById('installAgain').hidden = false;
      }
    } catch (err) {
      setInstallCheck(row, 'warn', `Could not run this check. After installing, confirm that ${row.dataset.url} does not open.`);
    }
  }

  async function runRewriteCheck(row) {
    try {
      const res = await fetch(row.dataset.url, { cache: 'no-store' });
      setInstallCheck(row, res.ok ? 'ok' : 'warn');
    } catch (err) {
      setInstallCheck(row, 'warn');
    }
  }

  const installCheckData = document.getElementById('installCheckData');
  if (installCheckData) {
    runDataCheck(installCheckData);
    runRewriteCheck(document.getElementById('installCheckRewrite'));
  }

  // Initialize
  if (document.getElementById('notesApp')) {
    fetchNotes();
  }
});
