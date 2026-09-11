/* Farewell-PIF controller UI — fingerprint profile + optional keybox, with a PIF-Detector style audit. */
"use strict";

let config = null;

const $ = (id) => document.getElementById(id);

function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { element.hidden = true; }, 2400);
}

function b64EncodeUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

function defaultConfig() {
  return {
    v: 1, en: 0, fl: 3, md: "auto", dbg: 0,
    pf: {}, tg: ["com.google.android.gms:com.google.android.gms.unstable", "com.android.vending"],
    nb: [], kb: [], kbi: -1, ft: {}, ap: {}
  };
}

/* ------------------------------------------------------------------ state */

function loadState() {
  try {
    const state = JSON.parse(fsp.getState());
    if (state.error) { toast("State error: " + state.error); return; }
    config = state.config || defaultConfig();
    $("deviceLine").textContent = state.model + " · Android " + state.android
      + " (SDK " + state.sdk + ") · patch " + (state.patch || "-");
    render(state);
  } catch (error) {
    toast("Failed to read state: " + error);
  }
}

function saveConfig() {
  try {
    fsp.saveConfig(JSON.stringify(config));
  } catch (error) {
    toast("Save failed: " + error);
  }
}

/* --------------------------------------------------------------- rendering */

function render(state) {
  const flags = Number(config.fl) || 0;
  const enabled = Number(config.en) === 1;
  const keyboxes = config.kb || [];
  const validBoxes = (state.keyboxes || []).filter((box) => box.valid);
  const hook = state.hook || {};
  const profile = config.pf || {};
  const hasProfile = !!profile.FINGERPRINT;

  const pill = $("statusPill");
  if (enabled && hook.installed) { pill.textContent = "ACTIVE"; pill.className = "pill on"; }
  else if (enabled) { pill.textContent = "ENABLED"; pill.className = "pill warn"; }
  else { pill.textContent = "OFF"; pill.className = "pill off"; }

  const primary = $("btnPrimary");
  primary.disabled = false;
  if (!hasProfile) {
    $("heroState").textContent = "🧩";
    $("heroText").textContent = "Import a Pif-props.json";
    $("heroSub").textContent = "A profile is required; keybox is optional";
    primary.textContent = "IMPORT PROFILE";
    primary.className = "primary import";
  } else if (enabled && hook.installed) {
    $("heroState").textContent = "✅";
    const anchored = (state.keyboxes || []).some((box) => box.valid && box.anchored);
    $("heroText").textContent = (flags & 2) && anchored ? "Protected" : "Profile active";
    $("heroSub").textContent = (flags & 2) && anchored
      ? validBoxes.length + " keybox anchored · " + (profile.MODEL || "profile")
      : "PIF profile only (no keybox attestation)";
    primary.textContent = "RE-APPLY";
    primary.className = "primary";
  } else {
    $("heroState").textContent = "⚡";
    $("heroText").textContent = "Ready";
    $("heroSub").textContent = (profile.MODEL || "profile") + " · "
      + (validBoxes.length ? validBoxes.length + " keybox" : "no keybox");
    primary.textContent = "APPLY";
    primary.className = "primary";
  }

  $("fpModel").textContent = hasProfile
    ? (profile.MODEL || profile.DEVICE || "custom") : "none";
  $("fpValue").textContent = hasProfile ? profile.FINGERPRINT : "-";
  $("spoofMode").value = (flags & 64) ? "store" : (flags & 32) ? "global" : "pif";

  const first = keyboxes.length ? (state.keyboxes || [])[0] : null;
  $("kbState").textContent = keyboxes.length
    ? (validBoxes.length + "/" + keyboxes.length + " valid") : "none";
  $("kbSerial").textContent = first && first.serial ? first.serial : "-";
  $("kbRoot").textContent = first
    ? (first.valid ? (first.anchored ? "current (" + (first.rootName || "Google") + ")"
      : "retired/unknown — STRONG rejected") : "invalid")
    : "-";
  $("keyboxToggle").checked = (flags & 2) !== 0;
}

/* --------------------------------------------------------------- callbacks */

window.__cb = function (event, dataJson) {
  let data;
  try { data = JSON.parse(dataJson); } catch (error) { data = { ok: false, error: dataJson }; }

  if (event === "quick_fix") {
    if (data.progress) { toast(data.progress); return; }
    if (data.ok) {
      toast(data.keyboxWarning ? "Applied — " + data.keyboxWarning
        : data.keybox ? "Applied — keybox attestation on"
        : "Applied — PIF profile mode (no keybox)");
      loadState();
    } else {
      toast("Apply failed: " + (data.error || "unknown"));
    }
    return;
  }
  if (event === "audit") {
    if (data.lines) showDiag(data.lines.join("\n"));
    else showDiag(JSON.stringify(data, null, 2));
    toast(data.verdict === "PASS" ? "Security audit: PASS"
      : "Security audit: " + (data.verdict || "see output"));
    return;
  }
  if (event === "update_profile") {
    if (data.ok) {
      toast("Profile updated: " + (data.model || data.fingerprint));
      loadState();
    } else {
      toast("Update failed: " + (data.error || "unknown"));
    }
    return;
  }
  if (event === "import_keybox") {
    toast(data.ok ? "Keybox imported" : "Import failed: " + data.error);
    if (data.ok) loadState();
    return;
  }
  if (event === "saved" || event === "kill_gms") {
    if (!data.ok) toast("Task failed: " + data.error);
  }
};

/* ----------------------------------------------------------------- wiring */

function wire() {
  $("btnPrimary").addEventListener("click", () => {
    if (!(config.pf && config.pf.FINGERPRINT)) pickFile("profile");
    else fsp.runTask("quick_fix", "");
  });

  $("btnImportProfile").addEventListener("click", () => pickFile("profile"));
  $("btnClearProfile").addEventListener("click", () => {
    config.pf = {};
    saveConfig();
    render(JSON.parse(fsp.getState()));
    toast("Profile cleared");
  });

  $("spoofMode").addEventListener("change", () => {
    let flags = Number(config.fl) || 0;
    flags |= 1;
    flags &= ~(32 | 64);
    const mode = $("spoofMode").value;
    if (mode === "store") flags |= 64;
    if (mode === "global") flags |= 32;
    config.fl = flags;
    saveConfig();
    toast(mode === "pif" ? "PIF mode" : mode === "store"
      ? "Store mode: Play Store sees the spoofed device" : "Global mode");
  });

  $("btnImportKeybox").addEventListener("click", () => pickFile("keybox"));
  $("btnRemoveKeybox").addEventListener("click", () => {
    config.kb = [];
    let flags = Number(config.fl) || 0;
    config.fl = flags & ~2;
    saveConfig();
    render(JSON.parse(fsp.getState()));
    toast("Keybox removed");
  });
  $("keyboxToggle").addEventListener("change", () => {
    const on = $("keyboxToggle").checked;
    if (on && !(config.kb || []).length) {
      $("keyboxToggle").checked = false;
      toast("Import a keybox first");
      return;
    }
    let flags = Number(config.fl) || 0;
    config.fl = on ? (flags | 2) : (flags & ~2);
    saveConfig();
  });

  $("btnAudit").addEventListener("click", () => {
    showDiag("Running security audit…");
    fsp.runTask("audit", "");
  });
  $("btnUpdateProfile").addEventListener("click", () => {
    showDiag("Fetching the latest reference profile…");
    fsp.runTask("update_profile", "");
  });
  $("btnDiagnose").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.selfTest());
      const lines = [
        "enabled=" + result.enabled + "  mode=" + result.mode + "  tee=" + result.tee,
        "attestation=" + result.attestationVersion + "  keymaster=" + result.keymasterVersion,
        "target=" + result.target + "  stats=" + JSON.stringify(result.stats)];
      if (result.hint) lines.push("hint=" + result.hint);
      if (result.error) lines.push("error=" + result.error);
      showDiag(lines.join("\n"));
      toast("Diagnostics done");
    } catch (error) {
      toast("Diagnostics failed: " + error);
    }
  });
  $("btnRestart").addEventListener("click", () => fsp.runTask("kill_gms", "clear"));
  $("btnRemoveHook").addEventListener("click", () => {
    fsp.removeHookNow();
    toast("Hook removed");
    setTimeout(loadState, 600);
  });
  $("btnExportBundle").addEventListener("click", () => {
    const path = fsp.exportDebugBundle();
    showDiag(path);
    toast(path.startsWith("export failed") ? path : "Bundle exported");
  });
}

function showDiag(text) {
  const out = $("diagOut");
  out.textContent = text;
  out.hidden = false;
}

/* -------------------------------------------------------------- file pick */

let fileKind = null;
const fileInput = document.createElement("input");
fileInput.type = "file";
fileInput.style.display = "none";
document.body.appendChild(fileInput);
fileInput.addEventListener("change", () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || "");
    if (fileKind === "keybox") {
      if (!text.includes("<Keybox") || !text.includes("<Key")) { toast("Not a keybox XML"); return; }
      fsp.runTask("import_keybox", b64EncodeUtf8(text));
    } else {
      try {
        config.pf = parseProfile(text);
        saveConfig();
        render(JSON.parse(fsp.getState()));
        toast("Profile imported");
      } catch (error) {
        toast("Invalid profile: " + error);
      }
    }
  };
  reader.readAsText(file);
});

/** Accepts Pif-props.json and PIF-style "KEY=VALUE" prop files. */
function parseProfile(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  const profile = {};
  trimmed.split(/\r?\n/).forEach((line) => {
    const clean = line.trim();
    if (!clean || clean.startsWith("#") || clean.startsWith("//")) return;
    const eq = clean.indexOf("=");
    if (eq <= 0) return;
    const key = clean.substring(0, eq).trim();
    const value = clean.substring(eq + 1).trim();
    if (key && value) profile[key] = value;
  });
  if (!profile.FINGERPRINT) throw new Error("no FINGERPRINT entry");
  return profile;
}

function pickFile(kind) {
  fileKind = kind;
  fileInput.value = "";
  fileInput.click();
}

/* ------------------------------------------------------------------ start */

wire();
loadState();
setInterval(loadState, 20000);
