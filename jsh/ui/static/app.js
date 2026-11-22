(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
  const fmt = (number) => new Intl.NumberFormat(document.documentElement.lang === "ru" ? "ru-RU" : "en-US").format(number || 0);
  const short = (value, length = 96) => value.length > length ? value.slice(0, length - 1) + "…" : value;

  const I18N = {
    ru: {
      home: "Главная", history: "История",
      pageTitle: "Найдите API, которые не видны снаружи.",
      heroTitle: "JS-Endpoints-Hunter",
      heroText: "Собирайте эндпоинты, пути, GraphQL-операции и секреты из публичных бандлов. Локально, без отправки данных наружу.",
      start: "Старт", stop: "Стоп", paste: "Вставить", pickFolder: "Выбрать папку", pickHar: "Выбрать HAR",
      modeUrl: "Ссылка на JS-файл", modeHtml: "Ссылка на страницу", modeDir: "Локальная папка",
      modeHtmlSmall: "все <script src>", modeListSmall: "построчно", modeClipboardSmall: "вставить из буфера",
      modeList: "Список URL", modeHar: "HAR-файл", modeClipboard: "Из буфера",
      results: "Результаты", progress: "Сканирование", historyTitle: "История сканов",
      historySubtitle: "SQLite, только этот компьютер",
      search: "Поиск по path, source, host...",
      urlHint: "Например: https://example.com/static/billing.js",
      htmlHint: "Страница, с которой нужно собрать <script src>",
      dirHint: "Выберите папку или укажите путь на диске",
      listHint: "По одному URL на строку. Строки с # игнорируются.",
      harHint: "Выберите .har из DevTools -> Network -> Save all as HAR",
      clipboardHint: "Вставьте JS, URL, список URL или HTML",
      phUrl: "https://example.com/static/billing.js",
      phDir: "C:\\work\\js-dump или выберите папку",
      phList: "https://example.com/a.js\nhttps://example.com/b.js\n# комментарий",
      phHar: "capture.har или выберите файл",
      phClipboard: "Вставьте JS, URL или HTML...",
      allHistory: "Все", latestScans: "Последние сканы",
      fineprint: "Только GET-запросы. Секреты маскируются. Не сканируйте чужие системы без разрешения.",
      optMaps: "Скачивать source maps", optSecrets: "Искать секреты", optResolve: "Строить полные URL",
      optVendor: "Включая vendor и node_modules", optAssets: "Не отбрасывать assets (.css/.png)",
      optShowSecrets: "Показывать секреты", optEntropy: "Эвристика для случайных строк",
      allowlistLabel: "Список исключений", proxyLabel: "Прокси",
      endpointsLabel: "Эндпоинты", secretsLabel: "Секреты", hostsLabel: "Хосты",
      preparing: "подготовка", scanning: "Сканирование", files: "файлов", processing: "обработка...",
      back: "Назад", allTypes: "Все типы", allMethods: "Все методы", severity: "Важность", selectAll: "Выбрать все",
      readonly: "только чтение · GET", tagSecrets: "секреты маскируются", tagDevtools: "снимок DevTools",
      tabEndpoints: "Эндпоинты", tabSecrets: "Секреты", tabHosts: "Хосты", tabStats: "Статистика", tabRaw: "Исходники",
      thPath: "Путь", thMethod: "Метод", thType: "Тип", thSource: "Источник", thConfidence: "Уверенность",
      thMasked: "Маска", thSeverity: "Важность", warning: "ВНИМАНИЕ",
      endpointsEmpty: "Эндпоинты пока не найдены.", secretsEmpty: "Секретов не найдено.",
      hostsEmpty: "Хостов не найдено.",
      secretNotice: "Значения замаскированы. Включите «Показывать секреты» и перезапустите скан, чтобы увидеть raw.",
      topPrefixes: "Топ префиксов", dependencies: "Зависимости и CVE", rawPrompt: "Выберите файл.",
      copy: "Копировать", rawButton: "Raw", open: "Открыть", sourceLabel: "Источник",
      contextLabel: "Контекст", jwtLabel: "JWT (подпись не проверяется)",
      refresh: "Обновить", historySearch: "Поиск по target, типу, статусу...",
      copyAll: "Копировать все", copySelected: "Копировать выбранное", copyCurl: "Копировать curl",
      copyFfuf: "Копировать ffuf", burpRequest: "Запрос для Burp", rescan: "Перезапустить", clear: "Очистить",
      secretModalTitle: "Показать raw-секреты?",
      secretModalText: "Они попадут в отчёт и SQLite на этом компьютере. Продолжайте только если понимаете риск.",
      cancel: "Отмена", secretModalConfirm: "Показать и запустить",
      palettePlaceholder: "scan URL, paste, export, history...",
      statusCompleted: "завершено", statusError: "ошибка", statusRunning: "выполняется",
      statusQueued: "в очереди", statusStopped: "остановлено",
      recentEmpty: "Здесь появятся последние сканы.", historyEmpty: "Сканов пока нет. Запустите первый анализ.",
      historyNoMatch: "Ничего не найдено.", noResults: "Нет активного результата",
      needInput: "Укажите URL, папку, файл или список", scanStarted: "Старт",
      targetPrefix: "Цель", scanDone: "Готово", scanFailed: "Ошибка скана",
      stopping: "Останавливаю...", noRaw: "Raw-файл не сохранён", rawNotFound: "Raw-файл не найден",
      valueCopied: "Значение скопировано", allCopied: "Все пути скопированы",
      selectedCopied: "Скопировано", curlCopied: "curl-команды скопированы",
      ffufCopied: "ffuf-команды скопированы", burpCopied: "Скопировано, вставьте в Burp Repeater",
      selectRows: "Сначала выберите строки", scanDeleted: "Скан удалён",
      confirmDelete: "Удалить этот скан из истории?", historyUnavailable: "История недоступна",
      bufferUnavailable: "Буфер обмена недоступен", bufferEmpty: "Буфер пуст", pasted: "Вставлено из буфера",
      uploading: "Загрузка...", uploaded: "Файлы загружены", uploadFailed: "Ошибка загрузки",
      loadFailed: "Не удалось загрузить результат", rescanUnsupported: "Этот тип входа нельзя повторить",
      copiedHost: "Хост скопирован", historyFound: "Найдено", clearResults: "Очистить",
      openScan: "Открыть", diff: "Diff", delete: "Удалить",
      cmdScan: "Сканировать URL", cmdPaste: "Вставить из буфера", cmdHistory: "История сканов",
      cmdOpenLast: "Открыть последний отчёт", cmdCopyAll: "Скопировать все пути",
      cmdCopyCurl: "Скопировать curl", cmdTheme: "Светлая или тёмная тема", cmdLang: "Сменить язык",
      themeLight: "Светлая тема", themeDark: "Тёмная тема", filesLabel: "Файлы",
      noData: "Нет данных.", noPackage: "package.json не найден.", diffNeedsCurrent: "Сначала откройте скан для сравнения",
      uploadedCount: "Загружено файлов", rawNoFiles: "Raw-файлы не сохранены.",
      noRawForSource: "Для этого источника нет raw-файла", added: "Добавлено", removed: "Удалено", common: "Общих",
      errorPrefix: "Ошибка"
    },
    en: {
      home: "Home", history: "History",
      pageTitle: "Find APIs that aren't visible from outside.",
      heroTitle: "JS-Endpoints-Hunter",
      heroText: "Collect endpoints, paths, GraphQL operations and secrets from public bundles. Locally, without sending the data anywhere.",
      start: "Start", stop: "Stop", paste: "Paste", pickFolder: "Choose folder", pickHar: "Choose HAR",
      modeUrl: "JS file URL", modeHtml: "Page URL", modeDir: "Local folder",
      modeHtmlSmall: "all <script src>", modeListSmall: "one per line", modeClipboardSmall: "paste from clipboard",
      modeList: "URL list", modeHar: "HAR file", modeClipboard: "Clipboard",
      results: "Results", progress: "Scanning", historyTitle: "Scan history",
      historySubtitle: "SQLite, stored on this computer",
      search: "Search path, source, host...",
      urlHint: "e.g. https://example.com/static/billing.js",
      htmlHint: "A page to collect <script src> from",
      dirHint: "Pick a folder or type a local path",
      listHint: "One URL per line. Lines starting with # are ignored.",
      harHint: "Pick a .har from DevTools -> Network -> Save all as HAR",
      clipboardHint: "Paste JS, a URL, a URL list or HTML",
      phUrl: "https://example.com/static/billing.js",
      phDir: "C:\\work\\js-dump or choose a folder",
      phList: "https://example.com/a.js\nhttps://example.com/b.js\n# comment",
      phHar: "capture.har or choose a file",
      phClipboard: "Paste JS, a URL or HTML...",
      allHistory: "All", latestScans: "Recent scans",
      fineprint: "GET requests only. Secrets are masked. Don't scan systems you don't own or have permission to test.",
      optMaps: "Download source maps", optSecrets: "Find secrets", optResolve: "Build full URLs",
      optVendor: "Include vendor and node_modules", optAssets: "Keep asset paths (.css/.png)",
      optShowSecrets: "Show secrets", optEntropy: "High-entropy heuristic",
      allowlistLabel: "Allowlist", proxyLabel: "Proxy",
      endpointsLabel: "Endpoints", secretsLabel: "Secrets", hostsLabel: "Hosts",
      preparing: "preparing", scanning: "Scanning", files: "files", processing: "processing...",
      back: "Back", allTypes: "All types", allMethods: "All methods", severity: "Severity", selectAll: "Select all",
      readonly: "read-only · GET", tagSecrets: "secrets masked", tagDevtools: "DevTools capture",
      tabEndpoints: "Endpoints", tabSecrets: "Secrets", tabHosts: "Hosts", tabStats: "Stats", tabRaw: "Raw",
      thPath: "Path", thMethod: "Method", thType: "Type", thSource: "Source", thConfidence: "Conf.",
      thMasked: "Masked", thSeverity: "Severity", warning: "WARNING",
      endpointsEmpty: "No endpoints yet.", secretsEmpty: "No secrets found.",
      hostsEmpty: "No hosts found.",
      secretNotice: "Values are masked. Turn on Show secrets and run the scan again to see raw values.",
      topPrefixes: "Top prefixes", dependencies: "Dependencies and CVEs", rawPrompt: "Choose a file.",
      copy: "Copy", rawButton: "Raw", open: "Open", sourceLabel: "Source",
      contextLabel: "Context", jwtLabel: "JWT (signature not verified)",
      refresh: "Refresh", historySearch: "Search target, type, status...",
      copyAll: "Copy all", copySelected: "Copy selected", copyCurl: "Copy curl",
      copyFfuf: "Copy ffuf", burpRequest: "Burp request", rescan: "Re-scan", clear: "Clear",
      secretModalTitle: "Show raw secrets?",
      secretModalText: "They will be written to the report and SQLite on this computer. Continue only if you understand the risk.",
      cancel: "Cancel", secretModalConfirm: "Show and run",
      palettePlaceholder: "scan URL, paste, export, history...",
      statusCompleted: "completed", statusError: "error", statusRunning: "running",
      statusQueued: "queued", statusStopped: "stopped",
      recentEmpty: "Recent scans will appear here.", historyEmpty: "No scans yet. Run your first scan.",
      historyNoMatch: "Nothing found.", noResults: "No active result",
      needInput: "Enter a URL, folder, file or list", scanStarted: "Started",
      targetPrefix: "Target", scanDone: "Done", scanFailed: "Scan failed",
      stopping: "Stopping...", noRaw: "Raw file was not saved", rawNotFound: "Raw file not found",
      valueCopied: "Value copied", allCopied: "All paths copied",
      selectedCopied: "Copied", curlCopied: "curl commands copied",
      ffufCopied: "ffuf commands copied", burpCopied: "Copied, paste into Burp Repeater",
      selectRows: "Select rows first", scanDeleted: "Scan deleted",
      confirmDelete: "Delete this scan from history?", historyUnavailable: "History is unavailable",
      bufferUnavailable: "Clipboard is unavailable", bufferEmpty: "Clipboard is empty", pasted: "Pasted from clipboard",
      uploading: "Uploading...", uploaded: "Files uploaded", uploadFailed: "Upload failed",
      loadFailed: "Could not load result", rescanUnsupported: "This input type cannot be re-run",
      copiedHost: "Host copied", historyFound: "Found", clearResults: "Clear",
      openScan: "Open", diff: "Diff", delete: "Delete",
      cmdScan: "Scan a URL", cmdPaste: "Paste from clipboard", cmdHistory: "Scan history",
      cmdOpenLast: "Open last report", cmdCopyAll: "Copy all paths",
      cmdCopyCurl: "Copy curl", cmdTheme: "Light or dark theme", cmdLang: "Switch language",
      themeLight: "Light theme", themeDark: "Dark theme", filesLabel: "Files",
      noData: "No data.", noPackage: "package.json not found.", diffNeedsCurrent: "Open a scan before comparing",
      uploadedCount: "Files uploaded", rawNoFiles: "No raw files saved.",
      noRawForSource: "No raw file for this source", added: "Added", removed: "Removed", common: "Common",
      errorPrefix: "Error"
    }
  };

  const MODES = {
    url: { title: "modeUrl", placeholder: "phUrl", hint: "urlHint", picker: "", multiline: false },
    html: { title: "modeHtml", placeholder: "phUrl", hint: "htmlHint", picker: "", multiline: false },
    dir: { title: "modeDir", placeholder: "phDir", hint: "dirHint", picker: "folder", multiline: false },
    list: { title: "modeList", placeholder: "phList", hint: "listHint", picker: "", multiline: true },
    har: { title: "modeHar", placeholder: "phHar", hint: "harHint", picker: "har", multiline: false },
    clipboard: { title: "modeClipboard", placeholder: "phClipboard", hint: "clipboardHint", picker: "", multiline: true }
  };

  const state = {
    mode: "url",
    drafts: {},
    lang: localStorage.getItem("jsh-lang") || document.documentElement.lang || "ru",
    theme: localStorage.getItem("jsh-theme") || document.documentElement.dataset.theme || "dark",
    scanId: null,
    scanStatus: "idle",
    eventSource: null,
    current: null,
    findings: [],
    rawFiles: [],
    hosts: [],
    filteredEndpoints: [],
    filteredSecrets: [],
    selectedFingerprint: "",
    selected: new Set(),
    activeTab: "endpoints",
    history: [],
    selectedIndex: -1,
    pendingSecrets: false,
    paletteIndex: 0
  };

  const t = (key) => (I18N[state.lang] && I18N[state.lang][key]) || I18N.ru[key] || key;

  async function api(path, options = {}) {
    const config = { ...options, headers: { ...(options.headers || {}) } };
    if (config.body && !(config.body instanceof FormData)) {
      config.headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, config);
    let data = {};
    try { data = await response.json(); } catch (_) { /* empty body */ }
    if (!response.ok) throw new Error(data.error || `${response.status} ${response.statusText}`);
    return data;
  }

  function toast(message, kind = "info") {
    const node = document.createElement("div");
    node.className = `toast ${kind}`;
    node.textContent = message;
    $("#toasts").appendChild(node);
    setTimeout(() => { node.style.opacity = "0"; setTimeout(() => node.remove(), 220); }, 3500);
  }

  function applyTheme() {
    document.documentElement.dataset.theme = state.theme;
    localStorage.setItem("jsh-theme", state.theme);
    $("#theme-toggle").textContent = state.theme === "dark" ? "◐" : "☀";
    $("#theme-toggle").title = state.theme === "dark" ? t("themeLight") : t("themeDark");
  }

  function applyLanguage() {
    document.documentElement.lang = state.lang;
    localStorage.setItem("jsh-lang", state.lang);
    $("#lang-toggle").textContent = state.lang === "ru" ? "EN" : "RU";
    $$("[data-i18n]").forEach((node) => {
      const value = t(node.dataset.i18n);
      if (value) node.textContent = value;
    });
    $$("[data-i18n-placeholder]").forEach((node) => {
      node.placeholder = t(node.dataset.i18nPlaceholder);
    });
    $$("[data-i18n-title]").forEach((node) => {
      node.title = t(node.dataset.i18nTitle);
    });
    if (currentView() === "home") $("#page-title").textContent = t("pageTitle");
    const heroText = $(".hero-copy p");
    if (heroText) heroText.textContent = t("heroText");
    $("#start").innerHTML = `${t("start")} <span class="kbd">Ctrl↵</span>`;
    $("#stop").innerHTML = `${t("stop")} <span class="kbd">Esc</span>`;
    $("#all-history").textContent = t("allHistory");
    const optionLabels = {
      "opt-maps": "optMaps", "opt-secrets": "optSecrets", "opt-resolve": "optResolve",
      "opt-vendor": "optVendor", "opt-assets": "optAssets", "opt-show-secrets": "optShowSecrets",
      "opt-entropy": "optEntropy"
    };
    for (const [id, key] of Object.entries(optionLabels)) {
      const input = document.getElementById(id);
      if (input?.nextElementSibling) input.nextElementSibling.textContent = t(key);
    }
    $("#filter-search").placeholder = t("search");
    $("#history-search").placeholder = t("historySearch");
    $("#palette-query").placeholder = t("palettePlaceholder");
    $("#theme-toggle").title = state.theme === "dark" ? t("themeLight") : t("themeDark");
    setMode(state.mode, true);
    if (state.current) renderResults();
    renderHistory();
    renderRecent();
  }

  function currentView() {
    return $(".view.is-active")?.id?.replace("view-", "") || "home";
  }

  function showView(name) {
    $$(".view").forEach((view) => view.classList.toggle("is-active", view.id === `view-${name}`));
    $$(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.view === name));
    const titles = {
      home: t("pageTitle"), progress: t("progress"), results: t("results"), history: t("historyTitle")
    };
    $("#page-title").textContent = titles[name] || t("pageTitle");
    const eyebrows = { home: "LOCAL-FIRST JS RECON", progress: "LIVE PROGRESS", results: "SCAN RESULTS", history: "LOCAL HISTORY" };
    $("#page-eyebrow").textContent = eyebrows[name] || "LOCAL-FIRST JS RECON";
    if (name === "history") loadHistory();
    if (name === "home") loadRecent();
  }

  function autoGrow() {
    const target = $("#target");
    if (state.mode === "list" || state.mode === "clipboard") {
      target.style.height = "150px";
      return;
    }
    target.style.height = "48px";
    target.style.height = `${Math.min(190, Math.max(48, target.scrollHeight))}px`;
  }

  function setMode(mode, keepValue = false) {
    if (!MODES[mode]) return;
    if (!keepValue && state.mode !== mode) state.drafts[state.mode] = $("#target").value;
    state.mode = mode;
    $$(".mode-card").forEach((card) => card.classList.toggle("is-active", card.dataset.mode === mode));
    const meta = MODES[mode];
    $("#input-label").textContent = t(meta.title);
    $("#input-hint").textContent = t(meta.hint);
    const target = $("#target");
    target.placeholder = t(meta.placeholder);
    target.rows = meta.multiline ? 7 : 1;
    if (!keepValue) target.value = state.drafts[mode] || "";
    $("#pick-folder").classList.toggle("is-hidden", meta.picker !== "folder");
    $("#pick-har").classList.toggle("is-hidden", meta.picker !== "har");
    $("#upload-note").textContent = "";
    autoGrow();
  }

  async function copyText(text, message = t("selectedCopied")) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    toast(message, "ok");
  }

  function appendLog(message, level = "info") {
    const log = $("#log");
    const line = document.createElement("div");
    line.className = `log-line ${level}`;
    const time = new Date().toLocaleTimeString("ru-RU", { hour12: false });
    line.innerHTML = `<span class="ts">${esc(time)}</span><span>${esc(message)}</span>`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  function updateProgress(event) {
    const done = Number(event.done || 0);
    const total = Math.max(Number(event.total || 1), done, 1);
    const percent = Math.min(100, Math.round((done / total) * 100));
    $("#progress-bar").style.width = `${percent}%`;
    $("#progress-count").textContent = `${done} / ${total} ${t("files")}`;
    $("#progress-pct").textContent = `${percent}%`;
    $("#progress-file").textContent = event.file || t("processing");
    if (event.endpoints !== undefined) $("#count-endpoints").textContent = fmt(event.endpoints);
    if (event.secrets !== undefined) $("#count-secrets").textContent = fmt(event.secrets);
    if (event.hosts !== undefined) $("#count-hosts").textContent = fmt(event.hosts);
  }

  function resetProgress(target) {
    $("#log").innerHTML = "";
    $("#progress-bar").style.width = "0%";
    $("#progress-count").textContent = `0 / 0 ${t("files")}`;
    $("#progress-pct").textContent = "0%";
    $("#progress-file").textContent = t("preparing");
    $("#count-endpoints").textContent = "0";
    $("#count-secrets").textContent = "0";
    $("#count-hosts").textContent = "0";
    $("#progress-title").textContent = `${t("scanning")} ${short(target, 70)}`;
    state.scanStatus = "running";
  }

  async function startScan(confirmSecrets = false) {
    const target = $("#target").value.trim();
    if (!target && state.mode !== "clipboard") {
      toast(t("needInput"), "warn");
      return;
    }
    const options = {
      download_maps: $("#opt-maps").checked,
      find_secrets: $("#opt-secrets").checked,
      show_secrets: $("#opt-show-secrets").checked,
      resolve_relative: $("#opt-resolve").checked,
      include_vendor: $("#opt-vendor").checked,
      keep_assets: $("#opt-assets").checked,
      entropy_secrets: $("#opt-entropy").checked,
      allowlist_file: $("#allowlist").value.trim(),
      proxy: $("#proxy").value.trim()
    };
    if (options.show_secrets && !confirmSecrets) {
      state.pendingSecrets = true;
      $("#secret-modal").classList.remove("is-hidden");
      return;
    }
    $("#start").disabled = true;
    state.scanId = null;
    state.current = null;
    state.selectedFingerprint = "";
    state.selected.clear();
    resetProgress(target);
    showView("progress");
    appendLog(`${t("scanStarted")}: ${target || "clipboard"} · ${state.mode}`);
    try {
      const data = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({
          input_type: state.mode,
          value: target,
          options,
          confirm_secrets: confirmSecrets
        })
      });
      state.scanId = data.scan_id;
      connectEvents(data.scan_id);
    } catch (error) {
      state.scanStatus = "error";
      $("#start").disabled = false;
      appendLog(error.message, "error");
      toast(error.message, "error");
    }
  }

  function connectEvents(scanId) {
    if (state.eventSource) state.eventSource.close();
    const source = new EventSource(`/api/scan/${scanId}/events`);
    state.eventSource = source;
    source.onmessage = (event) => {
      let payload;
      try { payload = JSON.parse(event.data); } catch (_) { return; }
      if (payload.type === "log") appendLog(payload.message || "", payload.level || "info");
      if (payload.type === "progress") updateProgress(payload);
      if (payload.type === "start") appendLog(`${t("targetPrefix")}: ${payload.target}`);
      if (payload.type === "done") {
        state.scanStatus = payload.status || "completed";
        appendLog(`${t("scanDone")}: ${state.scanStatus}`, state.scanStatus === "completed" ? "ok" : "warn");
        setTimeout(() => {
          if (state.scanId === scanId && currentView() === "progress") pollScan(scanId, 0);
        }, 600);
      }
      if (payload.type === "error") {
        state.scanStatus = "error";
        appendLog(payload.message || t("statusError"), "error");
        toast(payload.message || t("scanFailed"), "error");
      }
      if (payload.type === "saved") {
        source.close();
        state.eventSource = null;
        loadScan(scanId);
      }
    };
    source.onerror = () => {
      if (state.scanStatus === "running") {
        setTimeout(() => pollScan(scanId, 0), 1500);
      }
    };
  }

  async function fetchScan(scanId, timeout = 5000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      return await api(`/api/scan/${scanId}`, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function pollScan(scanId, attempt) {
    if (state.scanId !== scanId) return;
    try {
      const data = await fetchScan(scanId);
      if (data.scan && !["queued", "running", "stopping"].includes(data.scan.status)) {
        await finishScan(data);
        return;
      }
    } catch (_) { /* keep polling */ }
    if (attempt < 20) setTimeout(() => pollScan(scanId, attempt + 1), 1200);
  }

  async function loadScan(scanId, attempt = 0) {
    try {
      const data = await fetchScan(scanId);
      await finishScan(data);
    } catch (error) {
      if (attempt < 3) {
        setTimeout(() => loadScan(scanId, attempt + 1), 700);
        return;
      }
      toast(`${t("loadFailed")}: ${error.message}`, "error");
    }
  }

  async function finishScan(data) {
    state.current = data;
    state.scanId = data.scan.id;
    state.findings = data.findings || [];
    state.hosts = data.hosts || [];
    state.rawFiles = data.raw_files || [];
    state.scanStatus = data.scan.status;
    $("#start").disabled = false;
    state.selectedFingerprint = "";
    state.selected.clear();
    state.selectedIndex = -1;
    $("#filter-search").value = "";
    $("#filter-type").value = "";
    $("#filter-method").value = "";
    $("#filter-severity").value = "";
    renderResults();
    showView("results");
    loadHistory();
  }

  function renderResults() {
    if (!state.current) return;
    const scan = state.current.scan;
    $("#results-title").textContent = scan.target;
    $("#results-meta").textContent = `${scan.input_type} · ${scan.status} · ${scan.started_at || ""}`;
    const endpoints = state.findings.filter((item) => item.kind !== "secret");
    const secrets = state.findings.filter((item) => item.kind === "secret");
    $("#tab-count-endpoints").textContent = fmt(endpoints.length);
    $("#tab-count-secrets").textContent = fmt(secrets.length);
    $("#tab-count-hosts").textContent = fmt(state.hosts.length);
    renderActions();
    renderEndpoints();
    renderSecrets();
    renderHosts();
    renderStats();
    renderRawList();
    if (state.selectedFingerprint) {
      const finding = state.findings.find((item) => item.fingerprint === state.selectedFingerprint);
      if (finding) showDetail(finding); else hideDetail();
    }
  }

  function renderActions() {
    if (!state.current) return;
    const scan = state.current.scan;
    const artifacts = scan.artifacts || {};
    const labels = {
      "report.html": "HTML", "report.md": "MD", "report.json": "JSON",
      "report.sarif": "SARIF", "findings.jsonl": "JSONL", "endpoints.txt": "TXT",
      "endpoints.csv": "CSV", "curl-commands.sh": "curl", "ffuf-commands.sh": "ffuf",
      "nuclei-targets.txt": "nuclei", "secrets.txt": "secrets"
    };
    const links = Object.entries(labels)
      .filter(([name]) => artifacts[name])
      .map(([name, label]) => `<a class="ghost" href="/api/report/${scan.id}/${encodeURIComponent(name)}" target="_blank" rel="noreferrer">${label}</a>`)
      .join("");
    $("#result-actions").innerHTML = `
      ${links}
      <button class="ghost" data-copy="all">Copy all</button>
      <button class="ghost" data-copy="selected">Copy selected</button>
      <button class="ghost" data-copy="curl">Copy curl</button>
      <button class="ghost" data-copy="ffuf">Copy ffuf</button>
      <button class="ghost" data-copy="burp">Burp request</button>
      <button class="ghost" data-action="rescan">Re-scan</button>
      <button class="ghost danger" data-action="clear">Clear</button>`;
  }

  function endpointMatches(item) {
    const query = $("#filter-search").value.trim().toLowerCase();
    const type = $("#filter-type").value;
    const method = $("#filter-method").value;
    if (type && item.kind !== type) return false;
    if (method && (item.method || "") !== method) return false;
    if (!query) return true;
    return [item.value, item.source, item.host, item.method, item.kind]
      .some((value) => String(value || "").toLowerCase().includes(query));
  }

  function renderEndpoints() {
    const endpoints = state.findings.filter((item) => item.kind !== "secret");
    state.filteredEndpoints = endpoints.filter(endpointMatches);
    const rows = state.filteredEndpoints.map((item) => {
      const method = item.method || "-";
      return `<tr data-fingerprint="${esc(item.fingerprint)}" data-kind="endpoint">
        <td class="select-col"><input type="checkbox" class="row-select" data-fp="${esc(item.fingerprint)}" ${state.selected.has(item.fingerprint) ? "checked" : ""}></td>
        <td>${esc(item.value)}</td>
        <td><span class="badge">${esc(method)}</span></td>
        <td><span class="badge ${esc(item.kind)}">${esc(item.kind)}</span></td>
        <td>${esc(item.source)}:${item.line || 0}</td>
        <td class="num">${item.confidence || 0}</td>
      </tr>`;
    }).join("");
    $("#endpoint-rows").innerHTML = rows;
    $("#endpoint-empty").classList.toggle("show", !rows);
    syncSelection();
  }

  function syncSelection() {
    const boxes = $$("#endpoint-rows .row-select");
    boxes.forEach((box) => { box.checked = state.selected.has(box.dataset.fp); });
    const all = $("#select-all");
    if (!all) return;
    const checked = boxes.filter((box) => box.checked).length;
    all.checked = boxes.length > 0 && checked === boxes.length;
    all.indeterminate = checked > 0 && checked < boxes.length;
  }

  function secretMatches(item) {
    const query = $("#filter-search").value.trim().toLowerCase();
    const severity = $("#filter-severity").value;
    if (severity && item.severity !== severity) return false;
    if (!query) return true;
    return [item.secret_type, item.value, item.source, item.masked]
      .some((value) => String(value || "").toLowerCase().includes(query));
  }

  function renderSecrets() {
    const secrets = state.findings.filter((item) => item.kind === "secret");
    state.filteredSecrets = secrets.filter(secretMatches);
    const rows = state.filteredSecrets.map((item) => `<tr data-fingerprint="${esc(item.fingerprint)}" data-kind="secret">
      <td>${esc(item.secret_type || "secret")}</td>
      <td class="mono">${esc(item.masked || item.value)}</td>
      <td><span class="badge ${esc(item.severity)}">${esc(item.severity || "LOW")}</span></td>
      <td>${esc(item.source)}:${item.line || 0}</td>
    </tr>`).join("");
    $("#secret-rows").innerHTML = rows;
    $("#secret-empty").classList.toggle("show", !rows);
  }

  function renderHosts() {
    const hosts = state.hosts || [];
    $("#host-list").innerHTML = hosts.map((host) => `<button class="chip" data-copy-host="${esc(host)}">${esc(host)}</button>`).join("");
    $("#host-empty").classList.toggle("show", !hosts.length);
  }

  function renderStats() {
    const stats = state.current.scan.stats || {};
    const cards = [
      [t("endpointsLabel"), stats.endpoints || 0], [t("secretsLabel"), stats.secrets || 0],
      [t("hostsLabel"), stats.hosts || 0], [t("filesLabel"), stats.files || 0]
    ];
    $("#stats-grid").innerHTML = cards.map(([label, value]) => `<div class="stat-card"><span>${label}</span><b>${fmt(value)}</b></div>`).join("");
    const prefixes = stats.top_prefixes || [];
    const max = Math.max(...prefixes.map((item) => item.count), 1);
    $("#prefix-list").innerHTML = prefixes.length
      ? prefixes.map((item) => `<div class="prefix-row"><span>${esc(item.prefix)}</span><span class="mini-bar" style="width:${Math.max(4, item.count / max * 42)}%"></span><span class="count">${item.count}</span></div>`).join("")
      : `<div class="empty show">${t("noData")}</div>`;
    const dependencies = state.current.dependencies || [];
    $("#dependencies").innerHTML = dependencies.length
      ? dependencies.map((item) => `<div class="prefix-row"><span>${esc(item.name)}</span><span class="badge">${esc(item.version)}</span><a href="${esc(item.cve_search)}" target="_blank" rel="noreferrer">NVD ↗</a></div>`).join("")
      : `<div class="empty show">${t("noPackage")}</div>`;
  }

  function renderRawList() {
    const select = $("#raw-select");
    if (!state.rawFiles.length) {
      select.innerHTML = "";
      $("#raw-content").textContent = t("rawNoFiles");
      return;
    }
    select.innerHTML = state.rawFiles.map((file) => `<option value="${esc(file.name)}">${esc(file.name)} · ${esc(file.origin)}</option>`).join("");
    $("#raw-content").textContent = t("rawPrompt");
    $("#raw-size").textContent = "";
  }

  async function loadRaw(name, line = 0) {
    if (!state.current || !name) return;
    try {
      const response = await fetch(`/api/raw/${state.current.scan.id}/${encodeURIComponent(name)}`);
      if (!response.ok) throw new Error("raw file not found");
      const text = await response.text();
      const lines = text.split("\n");
      $("#raw-content").innerHTML = lines
        .map((value, index) => `<span class="raw-line ${line === index + 1 ? "is-highlighted" : ""}" data-line="${index + 1}">${esc(value) || " "}</span>`)
        .join("");
      const file = state.rawFiles.find((item) => item.name === name);
      $("#raw-size").textContent = file ? `${fmt(file.size)} B · ${file.origin}` : "";
      if (line > 0) {
        const highlighted = $("#raw-content .is-highlighted");
        highlighted?.scrollIntoView({ block: "center" });
      }
    } catch (error) {
      $("#raw-content").textContent = `${t("errorPrefix")}: ${error.message}`;
    }
  }

  function activateTab(name) {
    state.activeTab = name;
    $$(".tab").forEach((item) => item.classList.toggle("is-active", item.dataset.tab === name));
    $$(".tab-panel").forEach((panel) => panel.classList.toggle("is-active", panel.id === `tab-${name}`));
    $("#filters").classList.toggle("is-hidden", ["hosts", "stats", "raw"].includes(name));
    if (name === "raw") loadRaw($("#raw-select").value || state.rawFiles[0]?.name);
  }

  function jumpToRaw(finding) {
    const source = String(finding.source || "").split(/[\\/]/).pop();
    const candidates = state.rawFiles.filter((file) => file.name === source || source.endsWith(file.name) || file.name.endsWith(source));
    const raw = candidates[0] || state.rawFiles.find((file) => file.name.startsWith(source.replace(/\.[^.]+$/, "")));
    if (!raw) {
      toast(t("noRawForSource"), "warn");
      return;
    }
    activateTab("raw");
    $("#raw-select").value = raw.name;
    loadRaw(raw.name, finding.line || 0);
  }

  function showDetail(finding) {
    state.selectedFingerprint = finding.fingerprint;
    $("#detail").classList.remove("is-hidden");
    $("#detail-kind").textContent = finding.kind === "secret" ? `SECRET · ${finding.severity || ""}` : finding.kind.toUpperCase();
    $("#detail-title").textContent = finding.secret_type || finding.kind;
    $("#detail-value").textContent = finding.value;
    $("#detail-source").textContent = `${finding.source}:${finding.line || 0}`;
    $("#detail-snippet").textContent = finding.snippet || "-";
    const open = $("#detail-open");
    const isUrl = /^https?:\/\//i.test(finding.value);
    open.classList.toggle("is-hidden", !isUrl);
    if (isUrl) open.href = finding.value;
    const jwt = finding.meta?.jwt;
    $("#detail-jwt-block").classList.toggle("is-hidden", !jwt);
    $("#detail-jwt").textContent = jwt ? JSON.stringify(jwt, null, 2) : "";
    $("#detail-copy").onclick = () => copyText(finding.value, t("valueCopied"));
    $("#detail-raw").onclick = () => jumpToRaw(finding);
    if (finding.kind !== "secret" && finding.method) {
      $("#detail-kind").textContent = `${finding.method} · ${finding.kind.toUpperCase()}`;
    }
  }

  function hideDetail() {
    $("#detail").classList.add("is-hidden");
    state.selectedFingerprint = "";
  }

  function endpointText() {
    return state.findings.filter((item) => item.kind !== "secret").map((item) => item.value).join("\n");
  }

  function curlText() {
    const fallbackHost = state.hosts[0] || "<HOST>";
    return state.findings.filter((item) => item.kind !== "secret").map((item) => {
      let url = item.value;
      if (!/^https?:\/\//.test(url)) url = `https://${item.host || fallbackHost}${url}`;
      url = url.replace(/\{[^}]+\}/g, "<PARAM>");
      const method = item.method || "GET";
      return `# ${item.kind} ${item.source}:${item.line}\ncurl -sS -X ${method} '${url.replace(/'/g, "'\\''")}'`;
    }).join("\n\n");
  }

  function ffufText() {
    return state.hosts.map((host) => `ffuf -u 'https://${host}/FUZZ' -w wordlist.txt -mc 200,204,301,302,401,403 -rate 5`).join("\n");
  }

  async function handleCopy(kind) {
    if (kind === "all") await copyText(endpointText(), t("allCopied"));
    if (kind === "selected") {
      const selected = state.findings.filter((item) => item.kind !== "secret" && state.selected.has(item.fingerprint));
      if (!selected.length) { toast(t("selectRows"), "warn"); return; }
      await copyText(selected.map((item) => item.value).join("\n"), `${t("selectedCopied")}: ${selected.length}`);
    }
    if (kind === "curl") await copyText(curlText(), t("curlCopied"));
    if (kind === "ffuf") await copyText(ffufText(), t("ffufCopied"));
    if (kind === "burp") await copyText(curlText(), t("burpCopied"));
    if (kind === "host") { /* handled separately */ }
  }

  async function loadHistory() {
    try {
      const scans = await api("/api/scans");
      state.history = scans || [];
      $("#history-count").textContent = fmt(state.history.length);
      renderHistory();
      renderRecent();
    } catch (error) {
      toast(`${t("historyUnavailable")}: ${error.message}`, "error");
    }
  }

  function statusLabel(status) {
    const map = {
      completed: t("statusCompleted"), error: t("statusError"), running: t("statusRunning"),
      queued: t("statusQueued"), stopped: t("statusStopped")
    };
    return map[status] || status;
  }

  function historyCard(scan) {
    const stats = scan.stats || {};
    return `<div class="history-card">
      <div class="history-main">
        <b><span class="status-dot ${esc(scan.status)}"></span>${esc(scan.target)}</b>
        <small>${esc(scan.input_type)} · ${esc(scan.started_at)} · ${fmt(stats.endpoints || 0)} endpoints · ${fmt(stats.secrets || 0)} secrets</small>
      </div>
      <div class="history-actions">
        <button class="ghost" data-open-scan="${scan.id}">${esc(t("openScan"))}</button>
        <button class="ghost" data-diff-scan="${scan.id}">${esc(t("diff"))}</button>
        <button class="ghost danger" data-delete-scan="${scan.id}">${esc(t("delete"))}</button>
      </div>
    </div>`;
  }

  function historyMatches(scan) {
    const query = $("#history-search")?.value.trim().toLowerCase() || "";
    if (!query) return true;
    return [scan.target, scan.input_type, scan.status].some((value) => String(value || "").toLowerCase().includes(query));
  }

  function renderHistory() {
    const holder = $("#history-list");
    const scans = state.history.filter(historyMatches);
    if (!scans.length) {
      holder.innerHTML = `<div class="empty-state">${state.history.length ? t("historyNoMatch") : t("historyEmpty")}</div>`;
      return;
    }
    holder.innerHTML = scans.map(historyCard).join("");
  }

  function renderRecent() {
    const holder = $("#recent-scans");
    if (!state.history.length) {
      holder.innerHTML = `<div class="empty-state">${t("recentEmpty")}</div>`;
      return;
    }
    holder.innerHTML = state.history.slice(0, 3).map((scan) => {
      const stats = scan.stats || {};
      return `<button class="recent-card" data-open-scan="${scan.id}"><b>${esc(scan.target)}</b><small>${esc(scan.input_type)} · ${fmt(stats.endpoints || 0)} endpoints · ${fmt(stats.secrets || 0)} secrets</small></button>`;
    }).join("");
  }

  async function openScan(scanId) {
    await loadScan(scanId);
  }

  async function deleteScan(scanId) {
    if (!window.confirm(t("confirmDelete"))) return;
    try {
      await api(`/api/history/${scanId}`, { method: "DELETE" });
      toast(t("scanDeleted"), "ok");
      if (state.current?.scan?.id === scanId) {
        state.current = null;
        showView("home");
      }
      loadHistory();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function diffScan(scanId) {
    if (!state.current) {
      toast(t("diffNeedsCurrent"), "warn");
      return;
    }
    try {
      const diff = await api(`/api/diff/${state.current.scan.id}/${scanId}`);
      const added = diff.added || [];
      const removed = diff.removed || [];
      const holder = $("#history-list");
      const panel = document.createElement("div");
      panel.className = "panel";
      panel.style.padding = "16px";
      panel.style.marginBottom = "12px";
      panel.innerHTML = `<div class="section-head" style="margin:0 0 8px"><h3>Diff: текущий → #${scanId}</h3><button class="link-btn" data-close-diff>×</button></div>
        <p class="muted small">${esc(t("added"))}: ${added.length} · ${esc(t("removed"))}: ${removed.length} · ${esc(t("common"))}: ${diff.common || 0}</p>
        ${added.length ? `<div class="prefix-list">${added.slice(0, 20).map((item) => `<div class="prefix-row"><span>+ ${esc(item.value)}</span></div>`).join("")}</div>` : ""}
        ${removed.length ? `<div class="prefix-list" style="margin-top:8px">${removed.slice(0, 20).map((item) => `<div class="prefix-row"><span>- ${esc(item.value)}</span></div>`).join("")}</div>` : ""}`;
      holder.prepend(panel);
      panel.querySelector("[data-close-diff]").addEventListener("click", () => panel.remove());
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function openPalette() {
    $("#palette").classList.remove("is-hidden");
    $("#palette-query").value = "";
    state.paletteIndex = 0;
    renderPalette();
    setTimeout(() => $("#palette-query").focus(), 20);
  }

  function closePalette() { $("#palette").classList.add("is-hidden"); }

  function commands() {
    return [
      { label: t("cmdScan"), shortcut: "Ctrl↵", action: () => { closePalette(); showView("home"); setMode("url"); $("#target").focus(); } },
      { label: t("cmdPaste"), shortcut: "Paste", action: () => { closePalette(); pasteClipboard(); } },
      { label: t("cmdHistory"), shortcut: "H", action: () => { closePalette(); showView("history"); } },
      { label: t("cmdOpenLast"), shortcut: "R", action: () => { closePalette(); if (state.current) showView("results"); else toast(t("noResults"), "warn"); } },
      { label: t("cmdCopyAll"), shortcut: "", action: () => { closePalette(); handleCopy("all"); } },
      { label: t("cmdCopyCurl"), shortcut: "", action: () => { closePalette(); handleCopy("curl"); } },
      { label: t("cmdTheme"), shortcut: "T", action: () => { closePalette(); toggleTheme(); } },
      { label: t("cmdLang"), shortcut: "L", action: () => { closePalette(); toggleLanguage(); } }
    ];
  }

  function renderPalette() {
    const query = $("#palette-query").value.trim().toLowerCase();
    const filtered = commands().filter((item) => item.label.toLowerCase().includes(query));
    state.paletteIndex = Math.min(state.paletteIndex, Math.max(0, filtered.length - 1));
    $("#palette-list").innerHTML = filtered.map((item, index) => `<button class="palette-item ${index === state.paletteIndex ? "is-active" : ""}" data-command="${index}"><span>${esc(item.label)}</span><span class="shortcut">${esc(item.shortcut)}</span></button>`).join("");
    $$("#palette-list .palette-item").forEach((node, index) => {
      node.addEventListener("click", () => filtered[index]?.action());
    });
    $("#palette-list").onkeydown = null;
    $("#palette-list").dataset.filtered = "1";
  }

  async function pasteClipboard() {
    let text = "";
    try {
      const data = await api("/api/clipboard");
      text = data.text || "";
    } catch (_) {
      try { text = await navigator.clipboard.readText(); } catch (error) { toast(t("bufferUnavailable"), "error"); return; }
    }
    if (!text.trim()) { toast(t("bufferEmpty"), "warn"); return; }
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const allUrls = lines.length > 1 && lines.every((line) => /^https?:\/\//.test(line));
    if (/<(?:!doctype|html|script)/i.test(text)) setMode("clipboard");
    else if (allUrls) setMode("list");
    else if (lines.length === 1 && /^https?:\/\//.test(lines[0]) && /\.js(?:\?|$)/i.test(lines[0])) setMode("url");
    else if (lines.length > 1 && allUrls) setMode("list");
    $("#target").value = text;
    state.drafts[state.mode] = text;
    autoGrow();
    toast(t("pasted"), "ok");
  }

  async function uploadFiles(files, kind) {
    if (!files || !files.length) return;
    const form = new FormData();
    Array.from(files).forEach((file) => form.append("files", file, file.webkitRelativePath || file.name));
    $("#upload-note").textContent = t("uploading");
    try {
      const data = await api(`/api/upload?kind=${kind}`, { method: "POST", body: form });
      $("#target").value = data.path;
      state.drafts[state.mode] = data.path;
      $("#upload-note").textContent = `${t("uploadedCount")}: ${data.files} · ${data.path}`;
      toast(t("uploaded"), "ok");
      autoGrow();
    } catch (error) {
      $("#upload-note").textContent = "";
      toast(error.message, "error");
    }
  }

  function toggleTheme() {
    state.theme = state.theme === "dark" ? "light" : "dark";
    applyTheme();
  }

  function toggleLanguage() {
    state.lang = state.lang === "ru" ? "en" : "ru";
    applyLanguage();
  }

  function rescanCurrent() {
    if (!state.current) return;
    const scan = state.current.scan;
    if (!["url", "html", "dir", "har", "list", "clipboard"].includes(scan.input_type)) {
      toast(t("rescanUnsupported"), "warn");
      return;
    }
    setMode(scan.input_type);
    $("#target").value = scan.target;
    state.drafts[scan.input_type] = scan.target;
    $("#opt-show-secrets").checked = Boolean(scan.show_secrets);
    showView("home");
    startScan(false);
  }

  function clearResults() {
    state.current = null;
    state.findings = [];
    state.rawFiles = [];
    state.hosts = [];
    state.selected.clear();
    hideDetail();
    showView("home");
  }

  function init() {
    applyTheme();
    applyLanguage();
    setMode("url", true);
    autoGrow();

    $$(".mode-card").forEach((card) => card.addEventListener("click", () => setMode(card.dataset.mode)));
    $("#target").addEventListener("input", () => { state.drafts[state.mode] = $("#target").value; autoGrow(); });
    $("#scan-form").addEventListener("submit", (event) => { event.preventDefault(); startScan(false); });
    $("#paste-btn").addEventListener("click", pasteClipboard);
    $("#pick-folder").addEventListener("click", () => $("#folder-input").click());
    $("#pick-har").addEventListener("click", () => $("#har-input").click());
    $("#folder-input").addEventListener("change", (event) => uploadFiles(event.target.files, "dir"));
    $("#har-input").addEventListener("change", (event) => uploadFiles(event.target.files, "har"));
    $("#stop").addEventListener("click", stopScan);
    $("#back-home").addEventListener("click", () => showView("home"));
    $("#refresh-history").addEventListener("click", loadHistory);
    $("#history-search").addEventListener("input", renderHistory);
    $("#theme-toggle").addEventListener("click", toggleTheme);
    $("#lang-toggle").addEventListener("click", toggleLanguage);
    $("#open-palette").addEventListener("click", openPalette);
    $("#palette").addEventListener("click", (event) => { if (event.target === $("#palette")) closePalette(); });
    $("#palette-query").addEventListener("input", () => { state.paletteIndex = 0; renderPalette(); });
    $("#palette-query").addEventListener("keydown", (event) => {
      const items = $$("#palette-list .palette-item");
      if (event.key === "ArrowDown") { event.preventDefault(); state.paletteIndex = Math.min(items.length - 1, state.paletteIndex + 1); renderPalette(); }
      if (event.key === "ArrowUp") { event.preventDefault(); state.paletteIndex = Math.max(0, state.paletteIndex - 1); renderPalette(); }
      if (event.key === "Enter") { event.preventDefault(); items[state.paletteIndex]?.click(); }
    });
    $("#secret-cancel").addEventListener("click", () => { state.pendingSecrets = false; $("#secret-modal").classList.add("is-hidden"); });
    $("#secret-confirm").addEventListener("click", () => {
      $("#secret-modal").classList.add("is-hidden");
      state.pendingSecrets = false;
      startScan(true);
    });
    $$("[data-view]").forEach((node) => node.addEventListener("click", (event) => {
      event.preventDefault();
      showView(node.dataset.view);
    }));

    $("#filter-search").addEventListener("input", renderEndpoints);
    $("#filter-type").addEventListener("change", renderEndpoints);
    $("#filter-method").addEventListener("change", renderEndpoints);
    $("#filter-severity").addEventListener("change", renderSecrets);
    $$(".tab").forEach((tab) => tab.addEventListener("click", () => activateTab(tab.dataset.tab)));

    $("#endpoint-rows").addEventListener("click", (event) => {
      const checkbox = event.target.closest(".row-select");
      if (checkbox) {
        if (checkbox.checked) state.selected.add(checkbox.dataset.fp);
        else state.selected.delete(checkbox.dataset.fp);
        syncSelection();
        return;
      }
      const row = event.target.closest("tr[data-fingerprint]");
      if (!row) return;
      const finding = state.findings.find((item) => item.fingerprint === row.dataset.fingerprint);
      if (finding) showDetail(finding);
    });
    $("#select-all").addEventListener("change", (event) => {
      for (const item of state.filteredEndpoints) {
        if (event.target.checked) state.selected.add(item.fingerprint);
        else state.selected.delete(item.fingerprint);
      }
      syncSelection();
    });
    $("#secret-rows").addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-fingerprint]");
      if (!row) return;
      const finding = state.findings.find((item) => item.fingerprint === row.dataset.fingerprint);
      if (finding) showDetail(finding);
    });
    $("#detail-close").addEventListener("click", hideDetail);
    $("#result-actions").addEventListener("click", (event) => {
      const copy = event.target.closest("[data-copy]");
      if (copy) { handleCopy(copy.dataset.copy); return; }
      const action = event.target.closest("[data-action]");
      if (action?.dataset.action === "rescan") rescanCurrent();
      if (action?.dataset.action === "clear") clearResults();
    });
    $("#host-list").addEventListener("click", (event) => {
      const button = event.target.closest("[data-copy-host]");
      if (button) copyText(button.dataset.copyHost, t("copiedHost"));
    });
    $("#raw-select").addEventListener("change", (event) => loadRaw(event.target.value));

    $("#history-list").addEventListener("click", (event) => {
      const open = event.target.closest("[data-open-scan]");
      const diff = event.target.closest("[data-diff-scan]");
      const del = event.target.closest("[data-delete-scan]");
      if (open) openScan(Number(open.dataset.openScan));
      if (diff) diffScan(Number(diff.dataset.diffScan));
      if (del) deleteScan(Number(del.dataset.deleteScan));
    });
    $("#recent-scans").addEventListener("click", (event) => {
      const open = event.target.closest("[data-open-scan]");
      if (open) openScan(Number(open.dataset.openScan));
    });

    document.addEventListener("keydown", (event) => {
      const tag = document.activeElement?.tagName;
      const inInput = ["INPUT", "TEXTAREA", "SELECT"].includes(tag);
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); openPalette(); return; }
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); if (currentView() === "home") startScan(false); return; }
      if (event.key === "Escape") {
        if (!$("#palette").classList.contains("is-hidden")) { closePalette(); return; }
        if (!$("#secret-modal").classList.contains("is-hidden")) { $("#secret-cancel").click(); return; }
        if (currentView() === "progress") stopScan();
        hideDetail();
        return;
      }
      if (event.key === "/" && !inInput && currentView() === "results") { event.preventDefault(); $("#filter-search").focus(); }
      if ((event.key === "j" || event.key === "k") && !inInput && currentView() === "results") {
        const rows = $$("#endpoint-rows tr");
        if (!rows.length) return;
        state.selectedIndex = Math.max(0, Math.min(rows.length - 1, state.selectedIndex + (event.key === "j" ? 1 : -1)));
        rows[state.selectedIndex].scrollIntoView({ block: "nearest" });
        rows[state.selectedIndex].click();
      }
    });

    fetch("/api/health")
      .then((response) => response.json())
      .then((data) => {
        $("#health-dot").classList.add("ok");
        $("#health-text").textContent = `local · v${data.version}`;
      })
      .catch(() => {
        $("#health-dot").classList.add("bad");
        $("#health-text").textContent = "local API unavailable";
      });

    loadHistory();
    window.addEventListener("beforeunload", () => state.eventSource?.close());
  }

  async function stopScan() {
    if (!state.scanId || currentView() !== "progress") return;
    try {
      await api(`/api/scan/${state.scanId}/stop`, { method: "POST" });
      toast(t("stopping"), "warn");
    } catch (error) {
      toast(error.message, "warn");
    }
  }

  init();
})();
