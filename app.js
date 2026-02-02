/* Daily Log PWA - Relationship/Conflict tracker
   - Offline-first PWA (IndexedDB)
   - PIN lock + Recovery Key reset
   - Incident logging + Silent tracking
   - Reports: counts, started-by %, top triggers, silent durations
*/

const $ = (q) => document.querySelector(q);
const $$ = (q) => Array.from(document.querySelectorAll(q));

const DEFAULT_TRIGGERS = [
  "Respect/Behavior",
  "Money",
  "Time/Attention",
  "Family/Relatives",
  "Kids",
  "House/Chores",
  "Phone/Social",
  "Misunderstanding",
  "Other"
];

const STARTED_BY = ["Wife", "Me", "Both", "Unknown"];
const INTENSITY = ["1","2","3","4","5"];
const WHAT = ["Argument", "Silent", "Yelling", "Crying", "Insult", "Other"];

const SETTINGS_KEYS = {
  triggers: "triggers",
  pin: "pin",
  recovery: "recovery",
  silentCurrent: "silentCurrent",
  lastQuick: "lastQuick"
};

let state = {
  unlocked: false,
  startedBy: "Wife",
  intensity: "3",
  trigger: "Misunderstanding",
  what: ["Argument"],
};

function nowTs(){ return Date.now(); }
function fmtDT(ts){
  const d = new Date(ts);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth()+1).padStart(2,'0');
  const dd = String(d.getDate()).padStart(2,'0');
  const hh = String(d.getHours()).padStart(2,'0');
  const mi = String(d.getMinutes()).padStart(2,'0');
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}
function daysBetween(a,b){
  const ms = Math.max(0, b-a);
  return ms / (1000*60*60*24);
}
function toast(msg){
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(()=>t.hidden=true, 2200);
}

function uid(){
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

/* ---------- Crypto helpers (WebCrypto) ---------- */
async function sha256(str){
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}
function randomKeyString(){
  // user can write this down
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function deriveKeyFromPassphrase(pass, saltB64){
  const salt = Uint8Array.from(atob(saltB64), c=>c.charCodeAt(0));
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(pass),
    {name:"PBKDF2"},
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations: 150000, hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM", length: 256},
    false,
    ["encrypt","decrypt"]
  );
}
async function encryptJSON(obj, passphrase){
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const saltB64 = btoa(String.fromCharCode(...salt));
  const key = await deriveKeyFromPassphrase(passphrase, saltB64);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ivB64 = btoa(String.fromCharCode(...iv));
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc);
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
  return { v:1, alg:"AES-GCM", kdf:"PBKDF2-SHA256", iter:150000, salt:saltB64, iv:ivB64, ct:ctB64 };
}
async function decryptJSON(payload, passphrase){
  if (!payload || payload.alg !== "AES-GCM" || payload.kdf !== "PBKDF2-SHA256") {
    throw new Error("Invalid backup format");
  }
  const key = await deriveKeyFromPassphrase(passphrase, payload.salt);
  const iv = Uint8Array.from(atob(payload.iv), c=>c.charCodeAt(0));
  const ct = Uint8Array.from(atob(payload.ct), c=>c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
  const txt = new TextDecoder().decode(pt);
  return JSON.parse(txt);
}

/* ---------- Settings ---------- */
async function getSetting(key, fallback=null){
  const row = await IDBStore.get("settings", key);
  return row ? row.value : fallback;
}
async function setSetting(key, value){
  await IDBStore.put("settings", {key, value});
}
async function ensureDefaults(){
  const triggers = await getSetting(SETTINGS_KEYS.triggers, null);
  if (!triggers) await setSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);

  const rec = await getSetting(SETTINGS_KEYS.recovery, null);
  if (!rec) await setSetting(SETTINGS_KEYS.recovery, randomKeyString());

  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, null);
  if (!silent) await setSetting(SETTINGS_KEYS.silentCurrent, { active:false, startTs:null });

  // If no PIN -> unlocked
  const pin = await getSetting(SETTINGS_KEYS.pin, null);
  state.unlocked = !pin;
}

/* ---------- UI builders ---------- */
function buildChips(container, items, activeValue, onPick){
  container.innerHTML = "";
  items.forEach(v=>{
    const b = document.createElement("button");
    b.className = "chip" + (v===activeValue ? " active":"");
    b.textContent = v;
    b.onclick = () => onPick(v);
    container.appendChild(b);
  });
}
function buildMultiChips(container, items, activeList, onToggle){
  container.innerHTML = "";
  items.forEach(v=>{
    const b = document.createElement("button");
    b.className = "chip" + (activeList.includes(v) ? " active":"");
    b.textContent = v;
    b.onclick = () => onToggle(v);
    container.appendChild(b);
  });
}

function switchView(name){
  const map = {
    Home: "#viewHome",
    History: "#viewHistory",
    Reports: "#viewReports",
    Settings: "#viewSettings"
  };
  Object.entries(map).forEach(([k, sel])=>{
    $(sel).hidden = (k !== name);
  });
  $$(".navBtn").forEach(b=>{
    b.classList.toggle("active", b.dataset.nav === name);
  });
  $("#headerSub").textContent = name === "Home" ? "Private • Offline" : name;
}

async function refreshHome(){
  await refreshSilentStatus();
  await renderRecent();
}

async function refreshSilentStatus(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  const el = $("#silentStatus");
  if (silent.active && silent.startTs){
    el.textContent = `Silent: ON (since ${fmtDT(silent.startTs)})`;
  } else {
    el.textContent = "Silent: OFF";
  }
}

function badge(cls, txt){
  const s = document.createElement("span");
  s.className = `badge ${cls||""}`.trim();
  s.textContent = txt;
  return s;
}

async function renderRecent(){
  const list = $("#recentList");
  const all = await IDBStore.getAll("incidents");
  all.sort((a,b)=>b.ts-a.ts);
  const items = all.slice(0,7);
  list.innerHTML = items.length ? "" : `<div class="tinyNote">No incidents yet.</div>`;
  items.forEach(it=>{
    list.appendChild(renderIncidentItem(it));
  });
}

function renderIncidentItem(it){
  const div = document.createElement("div");
  div.className = "item";

  const top = document.createElement("div");
  top.className = "itemTop";

  const left = document.createElement("div");
  const badges = document.createElement("div");
  badges.className = "badges";

  badges.appendChild(badge("info", it.startedBy));
  badges.appendChild(badge("warn", it.trigger));
  badges.appendChild(badge("", `I:${it.intensity}`));

  if (it.what?.includes("Silent") || it.silentStartTs) badges.appendChild(badge("warn","Silent"));
  if (it.silentStartTs && it.silentEndTs) {
    const d = daysBetween(it.silentStartTs, it.silentEndTs);
    badges.appendChild(badge("ok", `${d.toFixed(1)}d`));
  }

  left.appendChild(badges);

  const right = document.createElement("div");
  right.appendChild(badge("", fmtDT(it.ts)));

  top.appendChild(left);
  top.appendChild(right);

  const note = document.createElement("div");
  note.className = "itemNote";
  note.textContent = it.note || "—";

  const meta = document.createElement("div");
  meta.className = "itemMeta";
  meta.textContent = (it.what || []).join(", ");

  const actions = document.createElement("div");
  actions.className = "itemActions";

  const btnEdit = document.createElement("button");
  btnEdit.className = "smallBtn";
  btnEdit.textContent = "Edit";
  btnEdit.onclick = async ()=>{
    await openEditDialog(it.id);
  };

  const btnDelete = document.createElement("button");
  btnDelete.className = "smallBtn";
  btnDelete.textContent = "Delete";
  btnDelete.onclick = async ()=>{
    if (!confirm("Delete this item?")) return;
    await IDBStore.del("incidents", it.id);
    toast("Deleted");
    await refreshAll();
  };

  actions.appendChild(btnEdit);
  actions.appendChild(btnDelete);

  div.appendChild(top);
  div.appendChild(note);
  div.appendChild(meta);
  div.appendChild(actions);
  return div;
}

/* ---------- Incident CRUD ---------- */
async function saveIncident({startSilent=false}={}){
  const note = $("#noteInput").value.trim();
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  const incident = {
    id: uid(),
    ts: nowTs(),
    startedBy: state.startedBy,
    intensity: state.intensity,
    trigger: state.trigger,
    what: state.what.slice(),
    note,
    silentStartTs: null,
    silentEndTs: null
  };

  if (startSilent){
    incident.silentStartTs = nowTs();
    incident.what = Array.from(new Set([...incident.what, "Silent"]));
    await setSetting(SETTINGS_KEYS.silentCurrent, {active:true, startTs: incident.silentStartTs});
  }

  await IDBStore.put("incidents", incident);
  await setSetting(SETTINGS_KEYS.lastQuick, {
    startedBy: incident.startedBy, intensity: incident.intensity, trigger: incident.trigger, what: incident.what
  });

  $("#noteInput").value = "";
  toast("Saved");
  await refreshAll();
}

async function openEditDialog(id){
  const it = await IDBStore.get("incidents", id);
  if (!it) return;

  const startedBy = prompt("Started by (Wife/Me/Both/Unknown):", it.startedBy) || it.startedBy;
  const intensity = prompt("Intensity (1-5):", it.intensity) || it.intensity;
  const trigger = prompt("Trigger:", it.trigger) || it.trigger;
  const note = prompt("Note:", it.note || "") ?? it.note;

  it.startedBy = STARTED_BY.includes(startedBy) ? startedBy : it.startedBy;
  it.intensity = INTENSITY.includes(String(intensity)) ? String(intensity) : it.intensity;
  it.trigger = trigger.trim() ? trigger.trim() : it.trigger;
  it.note = note;

  await IDBStore.put("incidents", it);
  toast("Updated");
  await refreshAll();
}

/* ---------- Silent tracking ---------- */
async function startSilent(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  if (silent.active && silent.startTs){
    toast("Silent already ON");
    return;
  }
  const st = nowTs();
  await setSetting(SETTINGS_KEYS.silentCurrent, {active:true, startTs: st});
  toast("Silent started");
  await refreshAll();
}
async function endSilent(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  if (!silent.active || !silent.startTs){
    toast("Silent is OFF");
    return;
  }
  const en = nowTs();
  const session = { id: uid(), startTs: silent.startTs, endTs: en };
  await IDBStore.put("silent", session);

  // Also attach to last incident if it looks like a silent-related one
  const all = await IDBStore.getAll("incidents");
  all.sort((a,b)=>b.ts-a.ts);
  const last = all[0];
  if (last && (!last.silentEndTs) && (last.silentStartTs || last.what?.includes("Silent"))){
    last.silentStartTs = last.silentStartTs || silent.startTs;
    last.silentEndTs = en;
    await IDBStore.put("incidents", last);
  }

  await setSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  toast("Silent ended");
  await refreshAll();
}

/* ---------- History & Reports ---------- */
function rangeStartTs(range){
  const now = new Date();
  const end = now.getTime();
  if (range === "all") return 0;
  if (range === "week"){
    const d = new Date(now);
    const day = (d.getDay()+6)%7; // Monday=0
    d.setHours(0,0,0,0);
    d.setDate(d.getDate()-day);
    return d.getTime();
  }
  if (range === "month"){
    const d = new Date(now.getFullYear(), now.getMonth(), 1);
    d.setHours(0,0,0,0);
    return d.getTime();
  }
  if (range === "year"){
    const d = new Date(now.getFullYear(), 0, 1);
    d.setHours(0,0,0,0);
    return d.getTime();
  }
  const days = Number(range);
  if (!Number.isFinite(days)) return 0;
  return end - days*24*60*60*1000;
}

async function renderHistory(){
  const list = $("#historyList");
  const range = $("#historyRange").value;
  const q = $("#historySearch").value.trim().toLowerCase();

  let all = await IDBStore.getAll("incidents");
  const start = rangeStartTs(range);
  all = all.filter(i => i.ts >= start);
  all.sort((a,b)=>b.ts-a.ts);

  if (q){
    all = all.filter(i =>
      (i.note||"").toLowerCase().includes(q) ||
      (i.trigger||"").toLowerCase().includes(q) ||
      (i.startedBy||"").toLowerCase().includes(q)
    );
  }

  list.innerHTML = all.length ? "" : `<div class="tinyNote">No items for this filter.</div>`;
  all.forEach(it=> list.appendChild(renderIncidentItem(it)));
}

async function renderReports(){
  const range = $("#reportRange").value;
  const start = rangeStartTs(range);
  const incidents = (await IDBStore.getAll("incidents")).filter(i => i.ts >= start);
  incidents.sort((a,b)=>b.ts-a.ts);

  const silentSessions = (await IDBStore.getAll("silent")).filter(s => s.startTs >= start);

  $("#kpiIncidents").textContent = String(incidents.length);

  // Silent durations from sessions + incident-linked
  const durations = [];
  silentSessions.forEach(s=>{
    if (s.endTs && s.startTs) durations.push(daysBetween(s.startTs, s.endTs));
  });
  // Also include incidents that have silentStart+silentEnd in case sessions missed
  incidents.forEach(i=>{
    if (i.silentStartTs && i.silentEndTs){
      durations.push(daysBetween(i.silentStartTs, i.silentEndTs));
    }
  });

  const sum = durations.reduce((a,b)=>a+b,0);
  const avg = durations.length ? sum / durations.length : 0;
  const longest = durations.length ? Math.max(...durations) : 0;

  $("#kpiSilentDays").textContent = sum.toFixed(1);
  $("#kpiAvgSilent").textContent = avg.toFixed(1);
  $("#kpiLongest").textContent = longest.toFixed(1);

  // Started-by %
  const sb = {};
  incidents.forEach(i=> sb[i.startedBy] = (sb[i.startedBy]||0)+1);
  renderStatBars("#startedByStats", sb, incidents.length);

  // Top triggers
  const tr = {};
  incidents.forEach(i=> tr[i.trigger] = (tr[i.trigger]||0)+1);
  renderStatBars("#triggerStats", tr, incidents.length, 6);
}

function renderStatBars(containerSel, counts, total, limit=10){
  const container = $(containerSel);
  container.innerHTML = "";
  const rows = Object.entries(counts)
    .sort((a,b)=>b[1]-a[1])
    .slice(0, limit);

  if (!rows.length){
    container.innerHTML = `<div class="tinyNote">No data.</div>`;
    return;
  }

  rows.forEach(([k,v])=>{
    const row = document.createElement("div");
    row.className = "statRow";

    const lbl = document.createElement("div");
    lbl.className = "statLbl";
    lbl.textContent = k;

    const barWrap = document.createElement("div");
    barWrap.className = "barWrap";
    const bar = document.createElement("div");
    bar.className = "bar";
    const pct = total ? (v/total)*100 : 0;
    bar.style.width = `${Math.max(6, pct)}%`;
    barWrap.appendChild(bar);

    const val = document.createElement("div");
    val.className = "statVal";
    val.textContent = `${v} (${pct.toFixed(0)}%)`;

    row.appendChild(lbl);
    row.appendChild(barWrap);
    row.appendChild(val);
    container.appendChild(row);
  });
}

/* ---------- Triggers manage ---------- */
async function renderTriggerManager(){
  const list = $("#triggerManageList");
  const triggers = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
  list.innerHTML = "";
  triggers.forEach((t, idx)=>{
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <div class="itemTop">
        <div class="itemNote">${t}</div>
        <div class="badges"><span class="badge">${idx+1}</span></div>
      </div>
      <div class="itemActions">
        <button class="smallBtn" data-act="rename">Rename</button>
        <button class="smallBtn" data-act="delete">Delete</button>
      </div>
    `;
    const [btnRename, btnDelete] = div.querySelectorAll("button");
    btnRename.onclick = async ()=>{
      const nv = prompt("Rename trigger:", t);
      if (!nv || !nv.trim()) return;
      const arr = (await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS)).slice();
      arr[idx] = nv.trim();
      await setSetting(SETTINGS_KEYS.triggers, arr);
      toast("Updated");
      await refreshAll();
    };
    btnDelete.onclick = async ()=>{
      if (!confirm("Delete trigger?")) return;
      const arr = (await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS)).slice();
      arr.splice(idx,1);
      await setSetting(SETTINGS_KEYS.triggers, arr);
      toast("Deleted");
      await refreshAll();
    };
    list.appendChild(div);
  });
}

async function rebuildHomeChips(){
  buildChips($("#startedByChips"), STARTED_BY, state.startedBy, (v)=>{
    state.startedBy = v;
    rebuildHomeChips();
  });
  buildChips($("#intensityChips"), INTENSITY, state.intensity, (v)=>{
    state.intensity = v;
    rebuildHomeChips();
  });

  const triggers = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
  buildChips($("#triggerChips"), triggers, state.trigger, (v)=>{
    state.trigger = v;
    rebuildHomeChips();
  });

  buildMultiChips($("#whatChips"), WHAT, state.what, (v)=>{
    if (state.what.includes(v)) state.what = state.what.filter(x=>x!==v);
    else state.what = [...state.what, v];
    rebuildHomeChips();
  });
}

/* ---------- PIN Lock ---------- */
async function showLockIfNeeded(){
  const pin = await getSetting(SETTINGS_KEYS.pin, null);
  const lock = $("#lockScreen");
  if (!pin){
    lock.hidden = true;
    state.unlocked = true;
    return;
  }
  lock.hidden = false;
  state.unlocked = false;
  $("#pinInput").value = "";
  $("#pinInput").focus();
}
async function setOrChangePIN(){
  const pin1 = prompt("New PIN (numbers only):");
  if (!pin1) return;
  const pin2 = prompt("Confirm PIN:");
  if (!pin2) return;
  if (pin1 !== pin2){
    toast("PIN mismatch");
    return;
  }
  const saltBytes = new Uint8Array(16); crypto.getRandomValues(saltBytes);
  const saltB64 = btoa(String.fromCharCode(...saltBytes));
  const hash = await sha256(pin1 + ":" + saltB64);
  await setSetting(SETTINGS_KEYS.pin, {salt:saltB64, hash});
  toast("PIN set");
  await showLockIfNeeded();
}
async function unlockWithPIN(){
  const input = $("#pinInput").value;
  const pin = await getSetting(SETTINGS_KEYS.pin, null);
  if (!pin){
    $("#lockScreen").hidden = true;
    state.unlocked = true;
    return;
  }
  const hash = await sha256(input + ":" + pin.salt);
  if (hash === pin.hash){
    $("#lockScreen").hidden = true;
    state.unlocked = true;
    toast("Unlocked");
  } else {
    $("#lockHint").textContent = "Wrong PIN";
    $("#pinInput").value = "";
  }
}
async function showRecoveryKey(){
  const rec = await getSetting(SETTINGS_KEYS.recovery, "");
  alert("Recovery Key:\n\n" + rec + "\n\nএটা নিরাপদ জায়গায় লিখে রাখুন।");
}
async function resetPinWithRecovery(){
  const rec = await getSetting(SETTINGS_KEYS.recovery, "");
  const input = prompt("Recovery Key দিন:");
  if (!input) return;
  if (input.trim() !== rec){
    toast("Wrong recovery key");
    return;
  }
  await setSetting(SETTINGS_KEYS.pin, null);
  toast("PIN cleared. Set new PIN in Settings.");
  await showLockIfNeeded();
  switchView("Settings");
}

/* ---------- Backup ---------- */
async function exportEncrypted(){
  const pass = prompt("Export passphrase (remember it):");
  if (!pass) return;
  const payload = {
    exportedAt: new Date().toISOString(),
    incidents: await IDBStore.getAll("incidents"),
    silent: await IDBStore.getAll("silent"),
    settings: await IDBStore.getAll("settings"),
  };
  const enc = await encryptJSON(payload, pass);
  const blob = new Blob([JSON.stringify(enc)], {type:"application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `daily-log-backup-${Date.now()}.json`;
  a.click();
  toast("Exported");
}
async function importEncryptedFile(file){
  const txt = await file.text();
  let payload;
  try { payload = JSON.parse(txt); } catch { throw new Error("Invalid file"); }
  const pass = prompt("Passphrase:");
  if (!pass) return;
  const data = await decryptJSON(payload, pass);

  if (!confirm("Import will REPLACE current data. Continue?")) return;

  await IDBStore.resetAll();
  // re-open and re-create stores on first access
  for (const it of (data.incidents||[])) await IDBStore.put("incidents", it);
  for (const it of (data.silent||[])) await IDBStore.put("silent", it);
  for (const it of (data.settings||[])) await IDBStore.put("settings", it);

  toast("Imported");
  location.reload();
}

/* ---------- Danger Zone ---------- */
function wireClearAll(){
  const btn = $("#btnClearAll");
  const c1=$("#chk1"), c2=$("#chk2"), c3=$("#chk3");
  const upd=()=>{
    btn.disabled = !(c1.checked && c2.checked && c3.checked);
  };
  [c1,c2,c3].forEach(c=>c.onchange=upd);
  upd();

  btn.onclick = async ()=>{
    if (!confirm("Really clear ALL data?")) return;
    await IDBStore.resetAll();
    toast("Cleared");
    location.reload();
  };
}

/* ---------- Quick Save (last used) ---------- */
async function quickSave(){
  const last = await getSetting(SETTINGS_KEYS.lastQuick, null);
  if (!last){
    toast("No quick preset yet");
    return;
  }
  state.startedBy = last.startedBy || state.startedBy;
  state.intensity = last.intensity || state.intensity;
  state.trigger = last.trigger || state.trigger;
  state.what = last.what || state.what;
  await rebuildHomeChips();
  await saveIncident({startSilent:false});
}

/* ---------- Refresh all ---------- */
async function refreshAll(){
  // Home
  await refreshHome();
  // History
  if (!$("#viewHistory").hidden) await renderHistory();
  // Reports
  if (!$("#viewReports").hidden) await renderReports();
  // Settings
  if (!$("#viewSettings").hidden) await renderTriggerManager();
}

/* ---------- PWA SW ---------- */
async function registerSW(){
  if (!("serviceWorker" in navigator)) return;
  try{
    await navigator.serviceWorker.register("sw.js");
  }catch(e){
    // ignore
  }
}

/* ---------- Init ---------- */
async function init(){
  await ensureDefaults();

  // Build chips
  const triggers = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
  // pick safe default
  if (!triggers.includes(state.trigger)) state.trigger = triggers[0] || "Other";

  await rebuildHomeChips();

  // Wire nav
  $$(".navBtn").forEach(b=>{
    b.onclick = async ()=>{
      if (!state.unlocked){
        toast("Unlock first");
        return;
      }
      switchView(b.dataset.nav);
      await refreshAll();
    };
  });

  // Wire home buttons
  $("#btnSaveIncident").onclick = ()=> saveIncident({startSilent:false});
  $("#btnSaveAndSilent").onclick = ()=> saveIncident({startSilent:true});
  $("#btnStartSilent").onclick = ()=> startSilent();
  $("#btnEndSilent").onclick = ()=> endSilent();
  $("#btnQuickSave").onclick = ()=> quickSave();

  // History
  $("#historyRange").onchange = ()=> renderHistory();
  $("#historySearch").oninput = ()=> renderHistory();

  // Reports
  $("#reportRange").onchange = ()=> renderReports();

  // Settings
  $("#btnAddTrigger").onclick = async ()=>{
    const v = $("#newTrigger").value.trim();
    if (!v) return;
    const arr = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
    await setSetting(SETTINGS_KEYS.triggers, [...arr, v]);
    $("#newTrigger").value = "";
    toast("Added");
    await refreshAll();
    await rebuildHomeChips();
  };
  $("#btnSetPin").onclick = ()=> setOrChangePIN();
  $("#btnShowRecovery").onclick = ()=> showRecoveryKey();
  wireClearAll();

  $("#btnExport").onclick = ()=> exportEncrypted();
  $("#btnImport").onclick = ()=> $("#importFile").click();
  $("#importFile").onchange = async (e)=>{
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    try{
      await importEncryptedFile(f);
    }catch(err){
      alert("Import failed: " + (err?.message || err));
    }finally{
      e.target.value = "";
    }
  };

  // Lock screen wiring
  $("#btnUnlock").onclick = ()=> unlockWithPIN();
  $("#pinInput").addEventListener("keydown", (e)=>{
    if (e.key === "Enter") unlockWithPIN();
  });
  $("#btnForgotPin").onclick = ()=> resetPinWithRecovery();

  // Show lock if needed
  await showLockIfNeeded();

  // Default view
  switchView("Home");
  await refreshAll();
  await registerSW();
}

document.addEventListener("visibilitychange", async ()=>{
  if (document.visibilityState === "visible"){
    await showLockIfNeeded();
  }
});

init();
