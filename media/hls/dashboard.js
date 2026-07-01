/* =========================================================
   STREAMIX CONTROL ROOM — dashboard logic (vanilla JS)
   Secure HLS: temporary token + Authorization: Bearer header
   ========================================================= */
(() => {
  "use strict";

  /* ---- Config -------------------------------------------------- */
  const KEY_SERVER_URL = "https://localhost:3001";
  const HLS_URL        = "https://localhost:8443/hls/video.m3u8";
  const KEY_URL_PREFIX = KEY_SERVER_URL + "/key";
  const SESSION_ID     = "streamix-demo-session";   // sent via X-Streamix-Session
  const ADMIN_TOKEN    = "streamix-admin-logs";     // sent via X-Admin-Token
  const FAKE_TOKEN     = "fake.invalid.token";

  /* ---- In-memory state (NEVER localStorage/sessionStorage) ----- */
  let temporaryToken = null;
  let hls = null;

  const $ = (s) => document.querySelector(s);

  /* ---- Small helpers ------------------------------------------- */
  function now() {
    const d = new Date(), p = (n) => String(n).padStart(2, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function showAlert(msg) {
    // Never display an empty banner: if there is no real message, hide it.
    if (!msg || !String(msg).trim()) { hideAlert(); return; }
    $("#alert-text").textContent = msg;
    $("#alert").hidden = false;
  }
  function hideAlert() {
    $("#alert-text").textContent = "";
    $("#alert").hidden = true;
  }
  $("#alert-close").addEventListener("click", hideAlert);

  /* =============================================================
     maskToken — show a safe preview, never the full token
     ============================================================= */
  function maskToken(token) {
    if (!token) return "en attente du jeton…";
    const head = token.slice(0, 8);
    return `${head}...••••...signature`;
  }

  /* =============================================================
     setPlaybackState
     ============================================================= */
  function setPlaybackState(txt, tone = "muted") {
    const el = $("#playback-state");
    el.textContent = txt;
    el.className = "chip chip--" + tone;
  }

  /* =============================================================
     addActivityEvent — modern SaaS activity feed
     type: info | success | warning | blocked
     ============================================================= */
  function addActivityEvent(message, type = "info") {
    const list = $("#activity");
    const empty = list.querySelector(".act-empty");
    if (empty) empty.remove();
    const row = document.createElement("li");
    row.className = `act-row act-${type}`;
    row.innerHTML =
      `<span class="act-dot"></span>` +
      `<span class="act-time">${now()}</span>` +
      `<span class="act-msg"></span>`;
    row.querySelector(".act-msg").textContent = message;
    list.appendChild(row);
    list.scrollTop = list.scrollHeight;
  }

  /* =============================================================
     updateTimelineStep — status: pending|active|completed|denied
     ============================================================= */
  function updateTimelineStep(index, status) {
    const step = document.querySelector(`.tl-step[data-step="${index}"]`);
    if (!step) return;
    step.classList.remove("active", "completed", "denied");
    if (status !== "pending") step.classList.add(status);
    const label = step.querySelector("[data-status]");
    if (label) label.textContent = ({pending:"en attente",active:"en cours",completed:"terminé",denied:"refusé"})[status] || status;
  }

  /* =============================================================
     fetchTemporaryToken — GET /token with X-Streamix-Session
     Stores the token in memory only.
     ============================================================= */
  async function fetchTemporaryToken() {
    updateTimelineStep(3, "active");
    const res = await fetch(`${KEY_SERVER_URL}/token`, {
      method: "GET",
      headers: { "X-Streamix-Session": SESSION_ID },
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`token HTTP ${res.status}`);

    // Accept either JSON { token } or a raw token string.
    let token;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      const data = await res.json();
      token = data.token || data.access_token || data.jwt;
    } else {
      token = (await res.text()).trim();
    }
    if (!token) throw new Error("empty token");

    temporaryToken = token;                     // memory only
    $("#token-preview").textContent = maskToken(token);
    updateTimelineStep(3, "completed");
    addActivityEvent("Jeton temporaire délivré (300 s, en mémoire uniquement)", "success");
    return token;
  }

  /* =============================================================
     attachKeyAuthorization — hls.js xhrSetup callback.
     Adds Authorization: Bearer <token> ONLY for the key endpoint.
     ============================================================= */
  function attachKeyAuthorization(xhr, url) {
    if (url.startsWith(KEY_URL_PREFIX) && temporaryToken) {
      xhr.setRequestHeader("Authorization", `Bearer ${temporaryToken}`);
      updateTimelineStep(4, "active");
      addActivityEvent("En-tête Authorization ajouté à la requête de clé", "info");
    }
  }

  /* =============================================================
     setupHlsPlayer — configure and start hls.js
     ============================================================= */
  function setupHlsPlayer() {
    const video = $("#video");

    if (window.Hls && window.Hls.isSupported()) {
      if (hls) { try { hls.destroy(); } catch (_e) {} }
      hls = new Hls({
        enableWorker: true,
        xhrSetup: attachKeyAuthorization,   // inject Bearer token for /key
      });

      hls.attachMedia(video);
      hls.on(Hls.Events.MEDIA_ATTACHED, () => hls.loadSource(HLS_URL));

      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        updateTimelineStep(1, "completed");   // manifest loaded
        updateTimelineStep(2, "completed");   // no token exposed
        addActivityEvent("Playlist chargée avec succès", "success");
        setPlaybackState("Prêt · AES-128", "ok");
        $("#video-loader").classList.add("hidden");
      });

      hls.on(Hls.Events.KEY_LOADED, () => {
        updateTimelineStep(4, "completed");   // key requested w/ auth
        updateTimelineStep(5, "completed");   // AES key delivered
        addActivityEvent("Clé AES délivrée", "success");
      });

      video.addEventListener("playing", () => {
        updateTimelineStep(6, "completed");   // playback unlocked
        setPlaybackState("Lecture en cours", "ok");
      }, { once: true });

      hls.on(Hls.Events.ERROR, (_evt, data) => {
        if (!data.fatal) return;
        const code = data.response && data.response.code ? ` (HTTP ${data.response.code})` : "";
        addActivityEvent(`Erreur de lecture : ${data.details}${code}`, "blocked");
        if (data.type === Hls.ErrorTypes.KEY_SYSTEM_ERROR ||
            /KEY/i.test(data.details || "")) {
          showAlert("La clé de déchiffrement n'a pas pu être délivrée : l'accès a été refusé par le serveur de clés.");
        } else {
          showAlert("La vidéo n'a pas pu démarrer. Vérifiez que le serveur vidéo et le serveur de clés sont bien démarrés.");
        }
        setPlaybackState("Erreur", "bad");
        $("#video-loader-text").textContent = "La lecture a échoué — voir le message ci-dessus";
      });

    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      // Native HLS (Safari) — token cannot be injected per-request here.
      video.src = HLS_URL;
      video.addEventListener("loadedmetadata", () => {
        updateTimelineStep(1, "completed");
        updateTimelineStep(2, "completed");
        setPlaybackState("Prêt · HLS natif", "ok");
        $("#video-loader").classList.add("hidden");
      }, { once: true });
    } else {
      setPlaybackState("Non pris en charge", "bad");
      showAlert("Ce navigateur ne peut pas lire cette vidéo. Essayez avec Google Chrome.");
    }
  }

  /* =============================================================
     initSecurePlayer — orchestrates the secure flow
     ============================================================= */
  async function initSecurePlayer() {
    setPlaybackState("Initialisation", "muted");
    updateTimelineStep(0, "completed");                 // user opens player
    addActivityEvent("Tableau de bord chargé en HTTPS", "info");

    try {
      await fetchTemporaryToken();
    } catch (_e) {
      showAlert("Impossible d'obtenir l'autorisation temporaire. Vérifiez que le serveur de clés est bien démarré.");
      addActivityEvent("Échec de la demande de jeton", "blocked");
      setPlaybackState("Erreur de jeton", "bad");
      // Still start the player so hls.js surfaces its own diagnostics.
    }
    setupHlsPlayer();
  }

  /* =============================================================
     Health check — GET /health → key server badge
     ============================================================= */
  async function checkHealth() {
    const badge = $("#badge-keyserver");
    try {
      const res = await fetch(`${KEY_SERVER_URL}/health`, { cache: "no-store" });
      if (res.ok) { badge.dataset.state = "ok"; addActivityEvent("Serveur de clés opérationnel", "success"); }
      else { badge.dataset.state = "off"; }
    } catch (_e) {
      badge.dataset.state = "off";
      badge.childNodes[1].textContent = "Serveur de clés hors ligne";
      addActivityEvent("Serveur de clés injoignable", "blocked");
    }
  }

  /* =============================================================
     Test result card
     ============================================================= */
  function showTestResult(title, reason, granted) {
    const box = $("#test-result");
    box.hidden = false;
    box.className = "test-result " + (granted ? "ok" : "bad");
    $("#test-result-title").textContent = title;
    $("#test-result-reason").textContent = reason;
  }

  /* =============================================================
     simulateAuthorizedAccess — valid token → key granted
     ============================================================= */
  async function simulateAuthorizedAccess(btn) {
    btn.disabled = true;
    try {
      const token = temporaryToken || await fetchTemporaryToken();
      const res = await fetch(KEY_URL_PREFIX, {
        headers: { "Authorization": `Bearer ${token}` }, cache: "no-store",
      });
      if (res.ok) {
        showTestResult("Accès autorisé — clé AES délivrée", "200 · signature valide, portée hls:key:read", true);
        addActivityEvent("Requête de clé valide acceptée", "success");
      } else {
        showTestResult("Accès refusé", `HTTP ${res.status} · jeton rejeté`, false);
        addActivityEvent("Requête de clé (accès valide) rejetée", "warning");
      }
    } catch (_e) {
      showAlert("La clé de déchiffrement n'a pas pu être délivrée : l'accès a été refusé par le serveur de clés.");
      showTestResult("Échec de la requête", "Serveur de clés injoignable ou bloqué par CORS", false);
    } finally { btn.disabled = false; }
  }

  /* =============================================================
     simulateInvalidTokenAttack — forged token → denied
     ============================================================= */
  async function simulateInvalidTokenAttack(btn) {
    btn.disabled = true;
    try {
      const res = await fetch(KEY_URL_PREFIX, {
        headers: { "Authorization": `Bearer ${FAKE_TOKEN}` }, cache: "no-store",
      });
      const granted = res.ok;
      showTestResult(
        granted ? "Inattendu : accès autorisé" : "Accès refusé — signature invalide",
        granted ? `HTTP ${res.status}` : `HTTP ${res.status} · échec de la vérification de la signature`,
        granted
      );
      addActivityEvent("Jeton invalide rejeté", "blocked");
    } catch (_e) {
      showTestResult("Accès refusé — signature invalide", "Rejeté avant la remise de la clé", false);
      addActivityEvent("Jeton invalide rejeté", "blocked");
    } finally { btn.disabled = false; }
  }

  /* =============================================================
     simulateMissingToken — no Authorization header → denied
     ============================================================= */
  async function simulateMissingToken(btn) {
    btn.disabled = true;
    try {
      const res = await fetch(KEY_URL_PREFIX, { cache: "no-store" }); // no Authorization
      const granted = res.ok;
      showTestResult(
        granted ? "Inattendu : accès autorisé" : "Accès refusé — jeton absent",
        granted ? `HTTP ${res.status}` : `HTTP ${res.status} · aucun en-tête Authorization`,
        granted
      );
      addActivityEvent("Jeton absent rejeté", "blocked");
    } catch (_e) {
      showTestResult("Accès refusé — jeton absent", "Aucun en-tête Authorization fourni", false);
      addActivityEvent("Jeton absent rejeté", "blocked");
    } finally { btn.disabled = false; }
  }

  /* =============================================================
     refreshAccessLogs — GET /logs with X-Admin-Token → table
     ============================================================= */
  async function refreshAccessLogs(btn) {
    btn.disabled = true;
    const body = $("#log-body");
    try {
      const res = await fetch(`${KEY_SERVER_URL}/logs`, {
        headers: { "X-Admin-Token": ADMIN_TOKEN }, cache: "no-store",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const rows = Array.isArray(data) ? data : (data.logs || data.entries || []);

      if (!rows.length) {
        body.innerHTML = `<tr class="log-empty"><td colspan="7">Aucune entrée de journal pour l’instant.</td></tr>`;
        return;
      }

      let granted = 0, denied = 0;
      body.innerHTML = "";
      rows.slice(-50).forEach((e) => {
        const access = String(e.access || e.decision || "").toLowerCase();
        const isGranted = /grant|allow|200|ok/.test(access);
        isGranted ? granted++ : denied++;
        const tr = document.createElement("tr");
        tr.innerHTML =
          `<td class="mono">${esc(e.time || e.timestamp || "")}</td>` +
          `<td>${esc(e.route || "/key")}</td>` +
          `<td>${esc(e.user || "—")}</td>` +
          `<td>${esc(e.video || "—")}</td>` +
          `<td class="${isGranted ? "access-granted" : "access-denied"}">${isGranted ? "autorisé" : "refusé"}</td>` +
          `<td>${esc(e.reason || "—")}</td>` +
          `<td class="mono">${esc(e.requestId || e.request_id || e.id || "—")}</td>`;
        body.appendChild(tr);
      });
      $("#count-granted").textContent = granted;
      $("#count-denied").textContent = denied;
      addActivityEvent(`Journaux d’accès actualisés (${rows.length} entrées)`, "info");
    } catch (_e) {
      body.innerHTML = `<tr class="log-empty"><td colspan="7">Impossible de charger les journaux — vérifiez <code>X-Admin-Token</code>, le serveur ou CORS.</td></tr>`;
      addActivityEvent("Échec de l’actualisation des journaux", "warning");
    } finally { btn.disabled = false; }
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
  }

  /* =============================================================
     Wiring
     ============================================================= */
  $("#btn-valid").addEventListener("click", (e)   => simulateAuthorizedAccess(e.currentTarget));
  $("#btn-invalid").addEventListener("click", (e) => simulateInvalidTokenAttack(e.currentTarget));
  $("#btn-missing").addEventListener("click", (e) => simulateMissingToken(e.currentTarget));
  $("#btn-refresh-logs").addEventListener("click", (e) => refreshAccessLogs(e.currentTarget));
  $("#btn-retry").addEventListener("click", () => {
    $("#video-loader").classList.remove("hidden");
    $("#video-loader-text").textContent = "Nouvelle tentative de lecture sécurisée…";
    $("#alert").hidden = true;
    initSecurePlayer();
  });
  $("#btn-clear-activity").addEventListener("click", () => {
    $("#activity").innerHTML = `<li class="act-empty">Aucune activité pour le moment.</li>`;
  });

  /* ---- Reveal-on-scroll ---------------------------------------- */
  const io = new IntersectionObserver((entries) => {
    entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
  }, { threshold: 0.08 });
  document.querySelectorAll(".reveal").forEach((el) => io.observe(el));

  /* ---- Boot ---------------------------------------------------- */
  addActivityEvent("Tableau de bord initialisé", "info");
  checkHealth();
  initSecurePlayer();
})();