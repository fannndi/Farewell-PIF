/* Farewell-PIF controller UI */
"use strict";

let config = null;
let apps = null;
let pendingTab = "home";

const $ = (id) => document.getElementById(id);

function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.classList.remove("hidden");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => element.classList.add("hidden"), 2200);
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

function loadState() {
  try {
    const state = JSON.parse(fsp.getState());
    if (state.error) { toast("State error: " + state.error); return; }
    config = state.config || defaultConfig();
    $("deviceLine").textContent = state.model + " | Android " + state.android
      + " (" + state.sdk + ") | patch " + (state.patch || "-");
    renderAll();
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

/* ---------------------------------------------------------------- rendering */

function renderAll() {
  const enabled = Number(config.en) === 1;
  $("enableSwitch").checked = enabled;
  const pill = $("statusPill");
  pill.textContent = enabled ? "enabled" : "disabled";
  pill.className = "pill " + (enabled ? "on" : "off");

  $("chipMode").textContent = "mode " + (config.md || "auto");
  $("chipFlags").textContent = "flags " + (config.fl || 0);
  const keyboxCount = (config.kb || []).length;
  $("chipKeybox").textContent = "keyboxes " + keyboxCount;
  $("chipTargets").textContent = "targets " + targets().length;

  document.querySelectorAll(".flag").forEach((box) => {
    box.checked = ((config.fl || 0) & Number(box.dataset.flag)) !== 0;
  });
  $("modeSelect").value = config.md || "auto";
  $("debugToggle").checked = Number(config.dbg) === 1;

  const profileField = $("profileText");
  if (document.activeElement !== profileField) {
    profileField.value = JSON.stringify(config.pf || {}, null, 2);
  }
  renderKeyboxes();
  renderRules();
}

function renderKeyboxes() {
  const container = $("keyboxList");
  const list = config.kb || [];
  if (!list.length) {
    container.innerHTML = '<div class="kb-row muted">No keybox installed.</div>';
    return;
  }
  container.innerHTML = list.map((item, index) => {
    return '<div class="kb-row">'
      + '<div>#' + (index + 1) + ' <span class="kb-serial">' + (item ? item.length : 0)
      + ' base64 chars</span></div>'
      + '<button class="mini" data-remove-kb="' + index + '">Remove</button>'
      + '</div>';
  }).join("");
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
  container.innerHTML = rules.map((rule, index) => {
    return '<span class="chip">' + rule
      + '<button data-rule-index="' + index + '">x</button></span>';
  }).join("");
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
  container.innerHTML = list.slice(0, 400).map((app) => {
    return '<label class="app-row">'
      + '<input type="checkbox" data-pkg="' + app.pkg + '"' + (app.target ? " checked" : "") + '>'
      + '<span class="label">' + app.label + '<span class="pkg">' + app.pkg + '</span></span>'
      + (app.sys ? '<span class="sys">system</span>' : '')
      + '</label>';
  }).join("");
  container.querySelectorAll("input[data-pkg]").forEach((box) => {
    box.addEventListener("change", () => {
      const pkg = box.dataset.pkg;
      const rules = targets();
      const existing = rules.findIndex((rule) =>
        rule === pkg || rule.startsWith(pkg + ":"));
      if (box.checked && existing < 0) rules.push(pkg);
      if (!box.checked && existing >= 0) rules.splice(existing, 1);
    });
  });
}

/* ---------------------------------------------------------------- callbacks */

window.__cb = function (event, dataJson) {
  let data;
  try { data = JSON.parse(dataJson); } catch (error) { data = { ok: false, error: dataJson }; }

  if (event === "quick_fix") {
    if (data.progress) { toast(data.progress); return; }
    if (data.ok) {
      toast("Integrity fixed — GMS restarted");
      loadState();
    } else {
      toast("Fix failed: " + (data.error || "no valid keybox, import one"));
    }
    return;
  }
  if (event === "fetch_keybox") {
    if (data.progress) { toast(data.progress); return; }
    if (data.ok) { toast("Keybox installed from " + data.source); loadState(); }
    else toast("Keybox failed: " + data.error);
    return;
  }
  if (event === "import_keybox") {
    toast(data.ok ? "Keybox imported" : "Import failed: " + data.error);
    if (data.ok) loadState();
    return;
  }
  if (event === "fetch_profile") {
    if (data.ok) {
      config.pf = data.profile;
      saveConfig();
      renderAll();
      toast("Profile updated");
    } else toast("Profile fetch failed");
    return;
  }
  if (event === "update_patch") {
    if (data.ok) {
      config.pf = config.pf || {};
      config.pf.SECURITY_PATCH = data.patch;
      saveConfig();
      renderAll();
      toast("Security patch set to " + data.patch);
    }
    return;
  }
  if (event === "check_revocation" || event === "validate_keybox") {
    if (!data.ok) { toast("Check failed: " + data.error); return; }
    const lines = (data.keyboxes || []).map((box) => {
      const status = box.revoked ? "REVOKED" : box.valid ? "valid" : "invalid";
      return "#" + (box.index + 1) + " serial " + (box.serial || "-") + " — " + status
        + (box.error ? " (" + box.error + ")" : "");
    });
    $("homeResult").innerHTML = '<div class="card-title">Keybox status</div>'
      + (lines.length ? lines.map((line) => '<div class="muted">' + line + '</div>').join("")
                      : '<div class="muted">No keybox installed.</div>');
    toast("Keybox check finished");
    return;
  }
  if (event === "photos") {
    if (data.ok) {
      toast(data.enabled ? "Photos unlimited enabled" : "Photos unlimited disabled");
      loadState();
    } else {
      toast("Photos preset failed: " + data.error);
    }
    return;
  }
  if (event === "default_profile") {
    if (data.ok) { toast("Bundled profile loaded"); loadState(); }
    else toast("Profile load failed: " + data.error);
    return;
  }
  if (event === "saved") {
    if (!data.ok) toast("Save failed: " + data.error);
    return;
  }
  if (event === "kill_gms" || event === "set_adb") {
    if (!data.ok) toast("Task failed: " + data.error);
    return;
  }
};

/* ---------------------------------------------------------------- wiring */

function refreshDebugState() {
  try {
    const state = JSON.parse(fsp.getDebugState());
    const hook = state.hook || {};
    const hookText = hook.installed
      ? (hook.upToDate ? "up-to-date " : "outdated ") + String(hook.meta || "").substring(0, 16)
      : "not installed";
    $("debugState").textContent = "adb=" + state.adb + "  development=" + state.development
      + "  debug=" + state.debug + "\nhook=" + hookText + "\n" + (state.dir || "");
    const events = JSON.parse(fsp.getEvents());
    $("eventsList").textContent = events.length
      ? events.slice(-20).join("\n")
      : "no framework events yet";
  } catch (error) {
    $("debugState").textContent = "debug state unavailable: " + error;
  }
}

function installHookNow() {
  try {
    const result = JSON.parse(fsp.installHookNow());
    toast(result.ok
      ? "Hook installed: " + String(result.sha || "").substring(0, 12)
        + " (" + (result.chunks || 0) + " chunks, " + (result.size || 0) + " bytes)"
      : "Hook install failed: " + result.error);
    refreshDebugState();
  } catch (error) {
    toast("Hook install failed: " + error);
  }
}

function switchTab(tab) {
  pendingTab = tab;
  document.querySelectorAll("#nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tab);
  });
  ["home", "integrity", "target", "tools"].forEach((name) => {
    $("tab-" + name).classList.toggle("hidden", name !== tab);
  });
  if (tab === "target" && apps === null) {
    apps = JSON.parse(fsp.listApps());
    renderApps();
  }
  if (tab === "tools") {
    refreshDebugState();
  }
}

function wire() {
  document.querySelectorAll("#nav button").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.tab));
  });

  $("enableSwitch").addEventListener("change", () => {
    config.en = $("enableSwitch").checked ? 1 : 0;
    saveConfig();
    renderAll();
  });

  document.querySelectorAll(".flag").forEach((box) => {
    box.addEventListener("change", () => {
      const bit = Number(box.dataset.flag);
      config.fl = (config.fl || 0) ^ bit;
      if (box.checked) config.fl |= bit; else config.fl &= ~bit;
      saveConfig();
      renderAll();
    });
  });

  $("modeSelect").addEventListener("change", () => {
    config.md = $("modeSelect").value;
    saveConfig();
    renderAll();
  });

  $("debugToggle").addEventListener("change", () => {
    config.dbg = $("debugToggle").checked ? 1 : 0;
    saveConfig();
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

  $("btnQuickFix").addEventListener("click", () => fsp.runTask("quick_fix", ""));
  $("btnImportKeyboxHome").addEventListener("click", () => pickFile("keybox"));
  $("btnImportKeybox").addEventListener("click", () => pickFile("keybox"));
  $("btnPhotos").addEventListener("click", () => {
    const enabled = config.ap && config.ap["com.google.android.apps.photos"];
    fsp.runTask("photos", enabled ? "off" : "on");
  });
  $("btnValidateKeybox").addEventListener("click", () => fsp.runTask("validate_keybox", ""));
  $("btnInstallHook").addEventListener("click", installHookNow);
  $("btnInstallHookHome").addEventListener("click", installHookNow);
  $("btnValidateHome").addEventListener("click", () => fsp.runTask("validate_keybox", ""));
  $("btnPatchHome").addEventListener("click", () => fsp.runTask("update_patch", ""));

  $("btnRestart").addEventListener("click", () => fsp.runTask("kill_gms", ""));
  $("btnKillGms").addEventListener("click", () => fsp.runTask("kill_gms", ""));
  $("btnKillPlay").addEventListener("click", () => fsp.runTask("kill_gms", "clear"));

  $("adbToggle").addEventListener("change", () => {
    fsp.runTask("set_adb", $("adbToggle").checked ? "1" : "0");
    toast($("adbToggle").checked ? "ADB disabled" : "ADB enabled");
  });

  $("btnEnableAdb").addEventListener("click", () => {
    fsp.runTask("set_adb", "0");
    toast("ADB + developer options enabled");
    setTimeout(refreshDebugState, 600);
  });
  $("btnDisableAdb").addEventListener("click", () => {
    fsp.runTask("set_adb", "1");
    toast("ADB + developer options disabled");
    setTimeout(refreshDebugState, 600);
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
    refreshDebugState();
  });
  $("btnRemoveHook").addEventListener("click", () => {
    fsp.removeHookNow();
    toast("Hook removed — reinstall after enabling");
    setTimeout(() => { loadState(); refreshDebugState(); }, 800);
  });

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

  $("btnExport").addEventListener("click", () => {
    $("ioText").value = JSON.stringify(config, null, 2);
    toast("Configuration exported to the box");
  });
  $("btnImport").addEventListener("click", () => {
    try {
      const parsed = JSON.parse($("ioText").value);
      parsed.v = 1;
      config = parsed;
      saveConfig();
      renderAll();
      toast("Configuration imported");
    } catch (error) {
      toast("Invalid JSON: " + error);
    }
  });

  $("btnSelfTest").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.selfTest());
      const lines = [];
      lines.push("enabled=" + result.enabled + "  flags=" + result.flags
        + "  mode=" + result.mode + "  tee=" + result.tee);
      lines.push("attestation=" + result.attestationVersion
        + "  keymaster=" + result.keymasterVersion);
      lines.push("process=" + (result.package || "-") + ":" + (result.process || "-")
        + "  target=" + result.target);
      lines.push("fingerprint=" + (result.fingerprint || "none"));
      (result.keyboxes || []).forEach((box) => {
        lines.push("keybox #" + (box.index + 1) + " " + box.algorithm + " — "
          + (box.problem ? box.problem : "ok"));
      });
      $("selfTestResult").textContent = lines.join("\n");
      toast("Self-test done");
    } catch (error) {
      toast("Self-test failed: " + error);
    }
  });

  $("btnHookTest").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.verifyHook());
      const lines = [];
      lines.push("ok=" + result.ok + "  forged=" + result.forged
        + "  chain=" + result.chainLength + "  keygen=" + result.keygen);
      lines.push("issuer=" + (result.issuer || "-"));
      if (result.stats) lines.push("stats=" + JSON.stringify(result.stats));
      if (result.hint) lines.push("hint=" + result.hint);
      if (result.error) lines.push("error=" + result.error);
      $("selfTestResult").textContent = lines.join("\n");
      toast(result.ok ? "Hook live test PASSED" : "Hook live test FAILED — see details");
    } catch (error) {
      toast("Hook live test failed: " + error);
    }
  });

  $("btnCheckRomSignature").addEventListener("click", () => {
    try {
      const result = JSON.parse(fsp.checkRomSignature());
      if (result.error) { toast("check failed: " + result.error); return; }
      const names = (result.names || []).join(", ");
      $("selfTestResult").textContent = "otacerts: " + names + "\n"
        + (result.testkey
          ? "ROM signed with TESTKEY — enable the Signature flag (bit 8)"
          : "ROM signed with release keys — signature spoof not needed");
      toast(result.testkey ? "Testkey ROM detected" : "Release-signed ROM");
    } catch (error) {
      toast("check failed: " + error);
    }
  });


  $("modalCancel").addEventListener("click", () => $("modal").classList.add("hidden"));
}

/* ---------------------------------------------------------------- file pick */

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
        renderAll();
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

/* ---------------------------------------------------------------- start */

wire();
loadState();
setInterval(loadState, 15000);
