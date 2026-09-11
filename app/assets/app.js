/* Farewell-PIF controller UI — simple first, everything else under Advanced. */
"use strict";

let config = null;
let apps = null;

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
    renderAll(state);
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

function targets() {
  if (!Array.isArray(config.tg)) config.tg = [];
  return config.tg;
}

function blacklist() {
  if (!Array.isArray(config.nb)) config.nb = [];
  return config.nb;
}

/* --------------------------------------------------------------- rendering */

function renderAll(state) {
  const enabled = Number(config.en) === 1;
  const keyboxes = config.kb || [];
  const validBoxes = (state.keyboxes || []).filter((box) => box.valid);
  const hook = state.hook || {};
  const profile = config.pf || {};

  const pill = $("statusPill");
  if (enabled && hook.installed) { pill.textContent = "PROTECTED"; pill.className = "pill on"; }
  else if (enabled) { pill.textContent = "ENABLED"; pill.className = "pill warn"; }
  else { pill.textContent = "DISABLED"; pill.className = "pill off"; }

  const primary = $("btnPrimary");
  primary.disabled = false;
  if (!keyboxes.length) {
    $("heroState").textContent = "🗝️";
    $("heroText").textContent = "Keybox required";
    $("heroSub").textContent = "Import your keybox.xml to get started";
    primary.textContent = "IMPORT KEYBOX";
    primary.className = "primary import";
  } else if (enabled && hook.installed) {
    $("heroState").textContent = "✅";
    $("heroText").textContent = "Protected";
    $("heroSub").textContent = "Hook " + String(hook.meta || "").substring(0, 12)
      + " · " + validBoxes.length + "/" + keyboxes.length + " keybox valid";
    primary.textContent = "RE-APPLY";
    primary.className = "primary";
  } else {
    $("heroState").textContent = "⚡";
    $("heroText").textContent = "Ready to fix";
    $("heroSub").textContent = validBoxes.length
      ? "Tap to enable, install the hook and restart Play"
      : "Keybox present but invalid — import a working one";
    primary.textContent = "FIX INTEGRITY";
    primary.className = "primary";
  }
  $("heroHint").textContent = enabled && hook.installed
    ? "No reboot needed. Re-apply after changing the profile or keybox."
    : "One tap: enable, apply profile, install hook and restart Play.";

  $("stHook").textContent = hook.installed
    ? (hook.upToDate ? "installed · up to date" : "installed · outdated")
    : "not installed";
  $("stKeybox").textContent = keyboxes.length
    ? validBoxes.length + " valid / " + keyboxes.length
    : "none";
  $("stProfile").textContent = profile.FINGERPRINT
    ? (profile.MODEL || "custom") + " · " + (profile.SECURITY_PATCH || "?")
    : "none";
  $("stTargets").textContent = targets().length + " rule(s)";

  $("enableSwitch").checked = enabled;
  document.querySelectorAll(".flag").forEach((box) => {
    box.checked = ((config.fl || 0) & Number(box.dataset.flag)) !== 0;
  });
  $("modeSelect").value = config.md || "auto";
  $("debugToggle").checked = Number(config.dbg) === 1;

  const profileField = $("profileText");
  if (document.activeElement !== profileField) {
    profileField.value = JSON.stringify(profile, null, 2);
  }
  renderKeyboxes();
  renderRules();
}

function renderKeyboxes() {
  const container = $("keyboxList");
  const list = config.kb || [];
  if (!list.length) {
    container.innerHTML = '<div class="muted">No keybox installed.</div>';
    return;
  }
  container.innerHTML = list.map((item, index) =>
    '<div class="kb-row"><div>#' + (index + 1)
    + ' <span class="kb-serial">' + (item ? item.length : 0) + ' b64 chars</span></div>'
    + '<button class="mini" data-remove-kb="' + index + '">Remove</button></div>').join("");
  container.querySelectorAll("[data-remove-kb]").forEach((button) => {
    button.addEventListener("click", () => {
      config.kb.splice(Number(button.dataset.removeKb), 1);
      saveConfig();
      renderKeyboxes();
      toast("Keybox removed");
    });
  });
}

function renderRules() {
  const container = $("ruleChips");
  const rules = targets().concat(blacklist().map((item) => "!" + item));
  if (!rules.length) {
    container.innerHTML = '<span class="muted">No target rules.</span>';
    return;
  }
  container.innerHTML = rules.map((rule, index) =>
    '<span class="chip">' + rule
    + '<button data-rule-index="' + index + '">×</button></span>').join("");
  container.querySelectorAll("[data-rule-index]").forEach((button) => {
    button.addEventListener("click", () => {
      const index = Number(button.dataset.ruleIndex);
      const total = targets().length;
      if (index < total) targets().splice(index, 1);
      else blacklist().splice(index - total, 1);
      saveConfig();
      renderRules();
    });
  });
}

function renderApps() {
  const container = $("appList");
  const query = ($("appSearch").value || "").toLowerCase();
  const list = (apps || []).filter((app) =>
    !query || app.label.toLowerCase().includes(query) || app.pkg.toLowerCase().includes(query));
  container.innerHTML = list.slice(0, 400).map((app) =>
    '<label class="app-row"><input type="checkbox" data-pkg="' + app.pkg + '"'
    + (app.target ? " checked" : "") + '>'
    + '<span class="label">' + app.label + '<span class="pkg">' + app.pkg + '</span></span>'
    + (app.sys ? '<span class="sys">system</span>' : '') + '</label>').join("");
  container.querySelectorAll("input[data-pkg]").forEach((box) => {
    box.addEventListener("change", () => {
      const pkg = box.dataset.pkg;
      const rules = targets();
      const existing = rules.findIndex((rule) => rule === pkg || rule.startsWith(pkg + ":"));
      if (box.checked && existing < 0) rules.push(pkg);
      if (!box.checked && existing >= 0) rules.splice(existing, 1);
    });
  });
}

/* --------------------------------------------------------------- callbacks */

window.__cb = function (event, dataJson) {
  let data;
  try { data = JSON.parse(dataJson); } catch (error) { data = { ok: false, error: dataJson }; }

  if (event === "quick_fix") {
    if (data.progress) { toast(data.progress); return; }
    if (data.ok) {
      toast("Integrity fixed — Play restarted");
      loadState();
    } else {
      toast("Fix failed: " + (data.error || "import a valid keybox first"));
    }
    return;
  }
  if (event === "import_keybox") {
    toast(data.ok ? "Keybox imported" : "Import failed: " + data.error);
    if (data.ok) loadState();
    return;
  }
  if (event === "validate_keybox") {
    if (!data.ok) { toast("Check failed: " + data.error); return; }
    const lines = (data.keyboxes || []).map((box) =>
      "#" + (box.index + 1) + " serial " + (box.serial || "-") + " — "
      + (box.revoked ? "REVOKED" : box.valid ? "valid" : "invalid")
      + (box.error ? " (" + box.error + ")" : ""));
    showDiag(lines.length ? lines.join("\n") : "No keybox installed.");
    toast("Keybox check finished");
    return;
  }
  if (event === "update_patch") {
    if (data.ok) {
      config.pf = config.pf || {};
      config.pf.SECURITY_PATCH = data.patch;
      saveConfig();
      renderAll(JSON.parse(fsp.getState()));
      toast("Security patch set to " + data.patch);
    }
    return;
  }
  if (event === "default_profile") {
    if (data.ok) { toast("Bundled profile loaded"); loadState(); }
    else toast("Profile load failed: " + data.error);
    return;
  }
  if (event === "saved" || event === "kill_gms" || event === "set_adb") {
    if (!data.ok) toast("Task failed: " + data.error);
    return;
  }
  if (event === "photos") {
    if (data.ok) { toast(data.enabled ? "Photos unlimited on" : "Photos unlimited off"); loadState(); }
    else toast("Photos preset failed: " + data.error);
  }
};

/* ---------------------------------------------------------------- helpers */

function showDiag(text) {
  const out = $("diagOut");
  out.textContent = text;
  out.hidden = false;
}

function refreshDebug() {
  try {
    const state = JSON.parse(fsp.getDebugState());
    const hook = state.hook || {};
    $("debugState").textContent = "adb=" + state.adb + " · development=" + state.development
      + " · debug=" + state.debug + "\nhook=" + (hook.installed
        ? (hook.upToDate ? "up-to-date " : "outdated ") + String(hook.meta || "").substring(0, 16)
        : "not installed") + "\n" + (state.dir || "");
    const events = JSON.parse(fsp.getEvents());
    const list = $("eventsList");
    list.textContent = events.length ? events.slice(-20).join("\n") : "no framework events yet";
    list.hidden = !events.length;
  } catch (error) {
    $("debugState").textContent = "debug state unavailable: " + error;
  }
}

function runDiagnostics() {
  try {
    const result = JSON.parse(fsp.selfTest());
    const lines = [];
    lines.push("enabled=" + result.enabled + "  flags=" + result.flags
      + "  mode=" + result.mode + "  tee=" + result.tee);
    lines.push("attestation=" + result.attestationVersion
      + "  keymaster=" + result.keymasterVersion);
    lines.push("process=" + (result.package || "-") + ":" + (result.process || "-")
      + "  target=" + result.target);
    if (result.stats) lines.push("stats=" + JSON.stringify(result.stats));
    (result.keyboxes || []).forEach((box) => {
      lines.push("keybox #" + (box.index + 1) + " " + box.algorithm + " — "
        + (box.problem ? box.problem : "ok"));
    });
    showDiag(lines.join("\n"));
    $("stTee").textContent = result.tee || "unknown";
    toast("Diagnostics done");
  } catch (error) {
    toast("Diagnostics failed: " + error);
  }
}

/* ----------------------------------------------------------------- wiring */

function wire() {
  $("btnPrimary").addEventListener("click", () => {
    if (!(config.kb || []).length) pickFile("keybox");
    else fsp.runTask("quick_fix", "");
  });
  $("btnImportQuick").addEventListener("click", () => pickFile("keybox"));
  $("btnDiagnose").addEventListener("click", runDiagnostics);

  $("enableSwitch").addEventListener("change", () => {
    config.en = $("enableSwitch").checked ? 1 : 0;
    saveConfig();
    renderAll(JSON.parse(fsp.getState()));
  });
  document.querySelectorAll(".flag").forEach((box) => {
    box.addEventListener("change", () => {
      const bit = Number(box.dataset.flag);
      if (box.checked) config.fl |= bit; else config.fl &= ~bit;
      saveConfig();
    });
  });
  $("modeSelect").addEventListener("change", () => {
    config.md = $("modeSelect").value;
    saveConfig();
  });
  $("debugToggle").addEventListener("change", () => {
    config.dbg = $("debugToggle").checked ? 1 : 0;
    saveConfig();
  });

  $("btnImportKeybox").addEventListener("click", () => pickFile("keybox"));
  $("btnValidateKeybox").addEventListener("click", () => fsp.runTask("validate_keybox", ""));
  $("btnInstallHook").addEventListener("click", () => {
    const result = JSON.parse(fsp.installHookNow());
    toast(result.ok ? "Hook installed (" + String(result.sha || "").substring(0, 12) + ")"
                    : "Hook install failed: " + result.error);
    loadState();
    refreshDebug();
  });
  $("btnRemoveHook").addEventListener("click", () => {
    fsp.removeHookNow();
    toast("Hook removed");
    setTimeout(loadState, 600);
  });
  $("btnRestart").addEventListener("click", () => fsp.runTask("kill_gms", ""));
  $("btnKillPlay").addEventListener("click", () => fsp.runTask("kill_gms", "clear"));
  $("adbToggle").addEventListener("change", () => {
    fsp.runTask("set_adb", $("adbToggle").checked ? "1" : "0");
    toast($("adbToggle").checked ? "ADB disabled" : "ADB enabled");
  });

  $("btnProfileApply").addEventListener("click", () => {
    try {
      config.pf = JSON.parse($("profileText").value);
      saveConfig();
      toast("Profile applied");
    } catch (error) {
      toast("Invalid JSON: " + error);
    }
  });
  $("btnDefaultProfile").addEventListener("click", () => fsp.runTask("default_profile", ""));
  $("btnProfilePatch").addEventListener("click", () => fsp.runTask("update_patch", ""));
  $("btnProfileImport").addEventListener("click", () => pickFile("profile"));

  $("btnAddRule").addEventListener("click", () => {
    const value = ($("ruleInput").value || "").trim();
    if (!value) return;
    if (value.startsWith("!")) blacklist().push(value.substring(1));
    else targets().push(value);
    $("ruleInput").value = "";
    saveConfig();
    renderRules();
  });
  $("appSearch").addEventListener("input", renderApps);
  $("btnSaveTargets").addEventListener("click", () => {
    saveConfig();
    apps = JSON.parse(fsp.listApps());
    renderApps();
    renderRules();
    toast("Targets saved");
  });

  $("btnSelfTest").addEventListener("click", runDiagnostics);
  $("btnHookTest").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.verifyHook());
      const lines = ["ok=" + result.ok + "  forged=" + result.forged
        + "  chain=" + result.chainLength + "  keygen=" + result.keygen,
        "issuer=" + (result.issuer || "-")];
      if (result.stats) lines.push("stats=" + JSON.stringify(result.stats));
      if (result.hint) lines.push("hint=" + result.hint);
      if (result.error) lines.push("error=" + result.error);
      showDiag(lines.join("\n"));
      toast(result.ok ? "Hook live test PASSED" : "Hook live test FAILED");
    } catch (error) {
      toast("Hook live test failed: " + error);
    }
  });
  $("btnCheckRomSignature").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.checkRomSignature());
      if (result.error) { toast("Check failed: " + result.error); return; }
      showDiag("otacerts: " + (result.names || []).join(", ") + "\n"
        + (result.testkey ? "TESTKEY ROM — enable the signature flag"
                          : "Release-signed ROM — signature spoof not needed"));
    } catch (error) {
      toast("Check failed: " + error);
    }
  });
  $("btnCollectLogs").addEventListener("click", () => {
    const text = fsp.getLogcat(2000);
    $("ioText").value = text;
    toast("logcat collected (" + text.length + " chars)");
  });
  $("btnExportBundle").addEventListener("click", () => {
    const path = fsp.exportDebugBundle();
    $("ioText").value = path;
    toast(path.startsWith("export failed") ? path : "Bundle: " + path);
    refreshDebug();
  });

  $("btnExport").addEventListener("click", () => {
    $("ioText").value = JSON.stringify(config, null, 2);
    toast("Configuration exported");
  });
  $("btnImport").addEventListener("click", () => {
    try {
      const parsed = JSON.parse($("ioText").value);
      parsed.v = 1;
      config = parsed;
      saveConfig();
      loadState();
      toast("Configuration imported");
    } catch (error) {
      toast("Invalid JSON: " + error);
    }
  });

  $("advanced").addEventListener("toggle", () => {
    if ($("advanced").open) {
      if (apps === null) { apps = JSON.parse(fsp.listApps()); renderApps(); }
      refreshDebug();
    }
  });
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
        config.pf = JSON.parse(text);
        saveConfig();
        renderAll(JSON.parse(fsp.getState()));
        toast("Profile imported");
      } catch (error) {
        toast("Invalid profile JSON: " + error);
      }
    }
  };
  reader.readAsText(file);
});

function pickFile(kind) {
  fileKind = kind;
  fileInput.value = "";
  fileInput.click();
}

/* ------------------------------------------------------------------ start */

wire();
loadState();
setInterval(loadState, 20000);
