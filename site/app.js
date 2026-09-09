/* Warden demo: replays recorded runs from data/replay.js and checks the audit chain in the browser.

   Nothing here decides anything. Every line shown comes from eval/record_demo.py output. */

(function () {
  "use strict";

  var DATA = (window.DEMO_DATA || {}).replay;
  var stage = document.getElementById("stage");
  var picker = document.getElementById("attack-pick");
  var timers = [];
  // Reduced motion gets the whole replay at once instead of line by line.
  var STEP_MS = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 260;

  var LAYER = {
    agent_resolver: "never sent: not a tool or argument the agent may use",
    no_signature: "never sent: no tool can name another request or tenant",
    tool_roles: "refused: the agent holds no role for this tool",
    action_policy: "refused by policy rule ",
    tenant_scope: "refused: not found in this tenant",
    scopes: "refused: the credential lacks the scope",
    request_binding: "refused: the credential is bound to one request"
  };
  var GOAL = {
    unsafe_auto_approve: "Approve something unsafe",
    wrong_tenant_read: "Read another customer's data",
    audit_skip: "Skip the audit log",
    freeze_window_bypass: "Get around a change freeze",
    privilege_escalation: "Act above its role"
  };

  function el(tag, attrs, text) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (text !== undefined) { n.textContent = text; }
    return n;
  }

  function reset(title) {
    timers.forEach(clearTimeout);
    timers = [];
    stage.textContent = "";
    stage.appendChild(el("h3", {}, title));
  }

  function later(i, fn) {
    timers.push(setTimeout(fn, i * STEP_MS));
  }

  function logLine(list, kind, who, text, cls) {
    var li = el("li", { "data-kind": kind });
    li.appendChild(el("span", { "class": "w-who" }, who));
    var body = el("span", cls ? { "class": cls } : {}, text);
    li.appendChild(body);
    list.appendChild(li);
  }

  function outcome(call) {
    if (!call.ok) { return "refused: " + call.error; }
    var r = call.result || {};
    if (call.tool === "learn_role") { return "granted " + r.granted; }
    if (call.tool === "get_change_request") { return r.id + ", " + r.key + " in " + r.environment; }
    if (call.tool === "validate_change_request") { return r.ok ? "valid" : "invalid: " + (r.errors || []).join("; "); }
    if (call.tool === "assess_change_risk") { return "risk " + r.score + " (" + r.band + ")" + (r.hard_deny ? ", hard deny" : ""); }
    if (call.tool === "record_decision") { return "decision: " + r.decision; }
    return "ok";
  }

  function playDecision(run, title) {
    reset(title);
    var list = el("ol", { "class": "w-log" });
    stage.appendChild(list);
    run.calls.forEach(function (c, i) {
      later(i, function () { logLine(list, "agent", "agent", c.tool + "  " + outcome(c)); });
    });
    later(run.calls.length + 1, function () {
      var good = run.decision === "auto_approve";
      var box = el("div", { "class": "w-verdict" + (good ? "" : " w-verdict--bad") });
      box.appendChild(el("strong", {}, good
        ? "Approved on its own. Risk " + run.risk.score + ", " + run.risk.band + "."
        : "Blocked. Risk " + run.risk.score + ", " + run.risk.band + "."));
      box.appendChild(el("p", {}, (run.reasons || []).join(" ")));
      box.appendChild(el("p", { "class": "w-hint" }, run.explanation || ""));
      stage.appendChild(box);
    });
  }

  function planted(a) {
    var parts = [];
    var inj = a.injected;
    if (inj.description) { parts.push("In the change description: " + inj.description); }
    Object.keys(inj.tool_description).forEach(function (t) { parts.push("Added to the " + t + " tool description: " + inj.tool_description[t]); });
    Object.keys(inj.rogue_tools).forEach(function (t) { parts.push("A fake tool from another server, " + t + ": " + inj.rogue_tools[t]); });
    inj.tool_result.forEach(function (r) { parts.push("Planted in what " + r.tool + " returns: " + JSON.stringify(r.merge || r.replace)); });
    inj.sampling_message.forEach(function (m) { parts.push("Sent as a server message: " + m); });
    return parts.join("\n");
  }

  function playAttack(a) {
    reset(a.title);
    stage.appendChild(el("p", { "class": "w-hint" }, "Goal: " + (GOAL[a.goal] || a.goal) + ". Attacker: " + a.attacker + "."));
    stage.appendChild(el("div", { "class": "w-planted" }, planted(a)));
    var list = el("ol", { "class": "w-log" });
    stage.appendChild(list);
    var i = 0;
    a.events.filter(function (e) { return e.phase === "agent"; }).forEach(function (e) {
      later(i++, function () {
        logLine(list, "agent", "agent", e.tool + "  " + (e.ok ? (e.decision ? "decision: " + e.decision : "ok") : "refused"));
      });
    });
    a.steered.forEach(function (s) {
      later(i++, function () {
        var why = s.ok ? "went through" : (LAYER[s.blocked_by] || s.error || "refused") + (s.blocked_by === "action_policy" ? s.rule : "");
        logLine(list, "steered", "tricked", s.tool + "  " + why, s.ok ? "w-ok" : "w-no");
      });
    });
    var refusals = a.audit.filter(function (e) { return e.decision === "blocked"; });
    var unsent = a.steered.every(function (s) { return !s.reached_server; });
    var chainText = " Chain " + (a.audit_chain_verified ? "verifies." : "does not verify.");
    later(i++, function () {
      var text = unsent && !refusals.length
        ? "Stopped before it was sent, so nothing reached the server to log." + chainText
        : refusals.length + " refusal" + (refusals.length === 1 ? "" : "s") + " written to the log." + chainText;
      logLine(list, "audit", "audit log", text);
    });
    later(i + 1, function () {
      var box = el("div", { "class": "w-verdict" + (a.attack_succeeded ? " w-verdict--bad" : "") });
      box.appendChild(el("strong", {}, a.attack_succeeded ? "The attack had an effect." : "Contained. Nothing the planted text asked for happened."));
      box.appendChild(el("p", { "class": "w-hint" }, "The agent's own decision still came from the server's rules, not from the planted text."));
      stage.appendChild(box);
    });
  }

  /* --------------------------------------------------------------- the chain */

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }

  function sha256(text) {
    var bytes = new TextEncoder().encode(text);
    if (window.crypto && window.crypto.subtle) {
      return window.crypto.subtle.digest("SHA-256", bytes).then(hex);
    }
    // crypto.subtle is missing on file:// pages, so a small fallback keeps the
    // tamper check working when the page is opened from disk.
    return Promise.resolve(sha256Fallback(bytes));
  }

  function sha256Fallback(bytes) {
    var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var len = bytes.length, words = ((len + 9 + 63) >> 6) << 4, w = new Array(words).fill(0);
    for (var i = 0; i < len; i++) { w[i >> 2] |= bytes[i] << (24 - (i % 4) * 8); }
    w[len >> 2] |= 0x80 << (24 - (len % 4) * 8);
    w[words - 1] = len * 8;
    function r(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var j = 0; j < words; j += 16) {
      var m = w.slice(j, j + 16), a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var t = 0; t < 64; t++) {
        if (t >= 16) { m[t] = (r(m[t-2],17) ^ r(m[t-2],19) ^ (m[t-2] >>> 10)) + m[t-7] + (r(m[t-15],7) ^ r(m[t-15],18) ^ (m[t-15] >>> 3)) + m[t-16] | 0; }
        var t1 = h + (r(e,6) ^ r(e,11) ^ r(e,25)) + ((e & f) ^ (~e & g)) + K[t] + m[t] | 0;
        var t2 = (r(a,2) ^ r(a,13) ^ r(a,22)) + ((a & b) ^ (a & c) ^ (b & c)) | 0;
        h = g; g = f; f = e; e = d + t1 | 0; d = c; c = b; b = a; a = t1 + t2 | 0;
      }
      H[0] = H[0] + a | 0; H[1] = H[1] + b | 0; H[2] = H[2] + c | 0; H[3] = H[3] + d | 0;
      H[4] = H[4] + e | 0; H[5] = H[5] + f | 0; H[6] = H[6] + g | 0; H[7] = H[7] + h | 0;
    }
    return H.map(function (x) { return ("0000000" + (x >>> 0).toString(16)).slice(-8); }).join("");
  }

  var EDITS = [
    { label: "Claim a person, not the agent, approved the dev change", find: "\"persona\":\"agent\"", put: "\"persona\":\"human\"", where: "cr-001" },
    { label: "Change the frozen prod request from deny to approve", find: "\"decision\":\"deny\"", put: "\"decision\":\"auto_approve\"", where: "cr-003" },
    { label: "Lower its recorded risk score to 5", find: /"risk_score":[0-9.]+/, put: "\"risk_score\":5.0", where: "cr-003" }
  ];

  function verify(chain, rows, status) {
    var prev = "0".repeat(64);
    var broken = false;
    return chain.reduce(function (p, entry, i) {
      return p.then(function () {
        return sha256(prev + "\n" + entry.blob).then(function (digest) {
          var ok = !broken && entry.prev_hash === prev && digest === entry.entry_hash;
          rows[i].dataset.state = ok ? "ok" : (broken ? "broken" : "edited");
          rows[i].lastChild.textContent = ok ? "verified" : (broken ? "after the break" : "hash does not match");
          if (!ok) { broken = true; }
          prev = entry.entry_hash;
        });
      });
    }, Promise.resolve()).then(function () {
      status.dataset.ok = String(!broken);
      status.textContent = broken ? "Chain verification failed. The edit shows, and every entry after it is unverifiable." : "Chain verifies: every entry hashes to the value stored after it.";
    });
  }

  function playTamper() {
    reset("The audit log from the two decisions above");
    var chain = DATA.chain.map(function (e) { return Object.assign({}, e); });
    var table = el("table", { "class": "w-chain" });
    var head = el("tr");
    ["#", "action", "request", "hash", "check"].forEach(function (h) { head.appendChild(el("th", {}, h)); });
    table.appendChild(head);
    var rows = chain.map(function (e) {
      var tr = el("tr");
      tr.appendChild(el("td", {}, String(e.seq)));
      tr.appendChild(el("td", {}, e.action + (e.decision && e.decision !== "granted" && e.decision !== "recorded" ? ": " + e.decision : "")));
      tr.appendChild(el("td", {}, e.request_id || "-"));
      tr.appendChild(el("td", { "class": "w-mono" }, e.entry_hash.slice(0, 12)));
      tr.appendChild(el("td", {}, "..."));
      table.appendChild(tr);
      return tr;
    });
    var scroller = el("div", { "class": "k-scroll-x" });
    scroller.appendChild(table);
    stage.appendChild(scroller);
    var status = el("p", { "class": "w-status" });
    stage.appendChild(status);
    var controls = el("div", { "class": "w-controls" });
    var pick = el("select", { "class": "w-select", "aria-label": "Edit to make" });
    EDITS.forEach(function (e, i) { pick.appendChild(el("option", { value: String(i) }, e.label)); });
    var apply = el("button", { "class": "w-btn w-btn--surprise", type: "button" }, "Edit the old entry");
    var undo = el("button", { "class": "w-btn", type: "button" }, "Put it back");
    controls.appendChild(pick); controls.appendChild(apply); controls.appendChild(undo);
    stage.appendChild(controls);
    stage.appendChild(el("p", { "class": "w-hint" }, "The check runs here in your browser with SHA-256 over the exact bytes the server hashed."));

    apply.addEventListener("click", function () {
      var edit = EDITS[Number(pick.value)];
      chain.forEach(function (e, i) { e.blob = DATA.chain[i].blob; });
      var target = chain.filter(function (e) { return e.action === "record_decision" && e.request_id === edit.where; })[0];
      target.blob = target.blob.replace(edit.find, edit.put);
      verify(chain, rows, status);
    });
    undo.addEventListener("click", function () {
      chain.forEach(function (e, i) { e.blob = DATA.chain[i].blob; });
      verify(chain, rows, status);
    });
    verify(chain, rows, status);
  }

  /* ------------------------------------------------------------------ wiring */

  function counters() {
    var c = DATA.counters;
    var box = document.getElementById("counters");
    [
      [String(c.attacks_succeeded), "of " + c.cases, "attacks had any effect"],
      [String(c.unsafe_auto_approvals), "", "unsafe approvals"],
      [String(c.cross_tenant_reads), "", "reads of another customer's data"],
      [String(c.audit_gaps), "", "actions missing from the log"],
      [c.reachable_writes_v1 + " to " + c.reachable_writes_now, "", "writes an attacker could still make after a task, version 1 to now"]
    ].forEach(function (row) {
      var claim = el("div", { "class": "k-claim" });
      var value = el("span", { "class": "k-claim__value" }, row[0]);
      if (row[1]) { value.appendChild(el("span", { "class": "k-claim__unit" }, row[1])); }
      claim.appendChild(value);
      claim.appendChild(el("span", { "class": "k-claim__label" }, row[2]));
      box.appendChild(claim);
    });
    var src = el("p", { "class": "w-hint" }, "Source: " + c.source + ". With the boundary switched off, " + c.ablation_attacks_succeeded + " of " + c.cases + " attacks worked. Version 1 was measured on " + c.v1_cases + " attacks.");
    box.parentNode.appendChild(src);
  }

  function fillPicker() {
    var groups = {};
    DATA.attacks.forEach(function (a) {
      if (!groups[a.goal]) {
        groups[a.goal] = el("optgroup", { label: GOAL[a.goal] || a.goal });
        picker.appendChild(groups[a.goal]);
      }
      groups[a.goal].appendChild(el("option", { value: a.id }, a.title));
    });
  }

  function press(which) {
    document.querySelectorAll("[data-run]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.run === which)); });
    if (which === "safe") { playDecision(DATA.safe, "A dev feature flag, cr-001"); }
    if (which === "dangerous") { playDecision(DATA.dangerous, "A prod change inside a freeze window, cr-003"); }
    if (which === "attack") {
      var a = DATA.attacks.filter(function (x) { return x.id === picker.value; })[0] || DATA.attacks[0];
      playAttack(a);
    }
    if (which === "tamper") { playTamper(); }
  }

  if (!DATA) { stage.textContent = "The recorded runs did not load."; return; }
  document.querySelector("[data-w-badge]").textContent = "Recorded runs, commit " + DATA.commit + ", " + DATA.generated_at.slice(0, 10);
  document.querySelector("[data-w-provenance]").textContent = "Recorded with " + DATA.recorded_with + ".";
  fillPicker();
  // Start on a case the server itself refuses and logs, the clearest one to watch.
  picker.value = "uaa-rp-01";
  counters();
  document.querySelectorAll("[data-run]").forEach(function (b) {
    b.addEventListener("click", function () { press(b.dataset.run); });
  });
  picker.addEventListener("change", function () { press("attack"); });
})();
