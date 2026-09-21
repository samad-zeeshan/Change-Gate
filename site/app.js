/* Warden demo: replays recorded runs from data/replay.js and checks the audit chain in the browser.

   Nothing here decides anything. Every line shown comes from eval/record_demo.py output. */

(function () {
  "use strict";

  var DATA = (window.DEMO_DATA || {}).replay;
  var stage = document.getElementById("stage");
  var picker = document.getElementById("attack-pick");
  var announce = document.getElementById("announce");
  var motionQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  // Every run gets a token. A newer press bumps it, and anything still printing for the old run stops.
  var runToken = 0;

  function reduced() { return !!(motionQuery && motionQuery.matches); }

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

  function wait(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, reduced() ? 0 : ms); });
  }

  /* ------------------------------------------------------------ spring values */

  // A critically damped spring (Apple's damping 1.0). It starts from whatever value is on screen
  // and keeps its velocity, so a second change mid-flight retargets instead of jumping.
  var springs = new WeakMap();

  function spring(key, to, apply, opts) {
    opts = opts || {};
    var s = springs.get(key);
    if (!s) { s = { x: opts.from !== undefined ? opts.from : to, v: 0, raf: 0 }; springs.set(key, s); }
    s.to = to;
    if (reduced()) { cancelAnimationFrame(s.raf); s.raf = 0; s.x = to; s.v = 0; apply(to); return; }
    var omega = 2 * Math.PI / (opts.response || 0.45);
    var eps = opts.eps || 0.01;
    var last = 0;
    cancelAnimationFrame(s.raf);
    function step(now) {
      var dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
      last = now;
      // Four substeps keep the integration stable on 30 Hz frames.
      for (var i = 0; i < 4; i++) {
        var h = dt / 4;
        var a = -omega * omega * (s.x - s.to) - 2 * omega * s.v;
        s.v += a * h;
        s.x += s.v * h;
      }
      if (Math.abs(s.x - s.to) < eps && Math.abs(s.v) < eps * 10) {
        s.x = s.to; s.v = 0; s.raf = 0; apply(s.to); return;
      }
      apply(s.x);
      s.raf = requestAnimationFrame(step);
    }
    s.raf = requestAnimationFrame(step);
  }

  function countTo(node, to, decimals, from) {
    spring(node, to, function (x) { node.textContent = x.toFixed(decimals || 0); },
      { from: from, response: 0.9, eps: decimals ? 0.005 : 0.3 });
  }

  /* ------------------------------------------------------------------ buttons */

  function setBusy(which, busy) {
    document.querySelectorAll("[data-run]").forEach(function (b) {
      var on = busy && b.dataset.run === which;
      if (on) { b.setAttribute("aria-busy", "true"); } else { b.removeAttribute("aria-busy"); }
      if (!on) { b.querySelector(".btn__progress").style.transform = "scaleX(0)"; }
    });
  }

  function setProgress(which, fraction) {
    var b = document.querySelector('[data-run="' + which + '"] .btn__progress');
    if (b) { b.style.transform = "scaleX(" + Math.max(0, Math.min(1, fraction)).toFixed(3) + ")"; }
  }

  /* -------------------------------------------------------------------- stage */

  function reset(title, meta) {
    stage.textContent = "";
    var head = el("div", { "class": "stage__head" });
    head.appendChild(el("h3", {}, title));
    if (meta) { head.appendChild(el("span", { "class": "stage__meta" }, meta)); }
    stage.appendChild(head);
    var body = el("div", { "class": "stage__body" });
    stage.appendChild(body);
    return body;
  }

  // Types one line like a teletype. Screen readers get the whole line at once from a hidden copy.
  function printLine(list, token, n, kind, who, text, cls) {
    var li = el("li", { "data-kind": kind });
    li.appendChild(el("span", { "class": "tape__n", "aria-hidden": "true" }, String(n)));
    li.appendChild(el("span", { "class": "tape__who" }, who));
    var body = el("span", { "class": "tape__text" + (cls ? " " + cls : "") });
    var shown = el("span", { "aria-hidden": "true" });
    body.appendChild(shown);
    body.appendChild(el("span", { "class": "sr-only" }, text));
    li.appendChild(body);
    list.appendChild(li);
    if (reduced()) { shown.textContent = text; return Promise.resolve(); }
    var caret = el("span", { "class": "tape__caret", "aria-hidden": "true" });
    body.insertBefore(caret, shown.nextSibling);
    // About 11 ms a character, but no line takes longer than 420 ms, so long lines do not stall the run.
    var total = Math.min(420, Math.max(120, text.length * 11));
    return new Promise(function (resolve) {
      var start = 0;
      function frame(now) {
        if (token !== runToken) { resolve(); return; }
        if (!start) { start = now; }
        var k = Math.min(1, (now - start) / total);
        shown.textContent = text.slice(0, Math.ceil(text.length * k));
        if (k < 1) { requestAnimationFrame(frame); return; }
        caret.remove();
        resolve();
      }
      requestAnimationFrame(frame);
    });
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

  async function playLines(which, token, list, lines) {
    for (var i = 0; i < lines.length; i++) {
      if (token !== runToken) { return false; }
      var l = lines[i];
      await printLine(list, token, i + 1, l.kind, l.who, l.text, l.cls);
      setProgress(which, (i + 1) / (lines.length + 1));
      await wait(70);
    }
    return token === runToken;
  }

  function verdict(body, good, headline, score, rest) {
    var box = el("div", { "class": "verdict" + (good ? "" : " verdict--deny") });
    var strong = el("strong", {});
    strong.appendChild(document.createTextNode(headline));
    if (score !== undefined) {
      strong.appendChild(document.createTextNode(" Risk "));
      var n = el("span", { "class": "num" }, "0.0");
      strong.appendChild(n);
      strong.appendChild(document.createTextNode(rest));
      countTo(n, score, 1, 0);
    }
    box.appendChild(strong);
    body.appendChild(box);
    return box;
  }

  async function playDecision(which, run, title, meta) {
    var token = ++runToken;
    setBusy(which, true);
    var body = reset(title, meta);
    var list = el("ol", { "class": "tape", "aria-label": "Tool calls", translate: "no" });
    body.appendChild(list);
    var lines = run.calls.map(function (c) { return { kind: "agent", who: "agent", text: c.tool + "  " + outcome(c) }; });
    if (!(await playLines(which, token, list, lines))) { return; }
    await wait(160);
    if (token !== runToken) { return; }
    var good = run.decision === "auto_approve";
    var box = verdict(body, good, good ? "Approved on its own." : "Blocked.", run.risk.score, ", " + run.risk.band + ".");
    box.appendChild(el("p", {}, (run.reasons || []).join(" ")));
    box.appendChild(el("p", { "class": "verdict__aside" }, run.explanation || ""));
    announce.textContent = (good ? "Approved on its own. " : "Blocked. ") + "Risk " + run.risk.score + ", " + run.risk.band + ".";
    setBusy(which, false);
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

  async function playAttack(a) {
    var token = ++runToken;
    setBusy("attack", true);
    var body = reset(a.title, a.id);
    body.appendChild(el("p", { "class": "goal" }, "Goal: " + (GOAL[a.goal] || a.goal) + ". Attacker: " + a.attacker + "."));
    var box = el("div", { "class": "planted" });
    box.appendChild(el("span", { "class": "planted__label" }, "What the attacker planted"));
    box.appendChild(el("p", { "class": "planted__text" }, planted(a)));
    body.appendChild(box);
    var list = el("ol", { "class": "tape", "aria-label": "Tool calls", translate: "no" });
    body.appendChild(list);

    var lines = a.events.filter(function (e) { return e.phase === "agent"; }).map(function (e) {
      return { kind: "agent", who: "agent", text: e.tool + "  " + (e.ok ? (e.decision ? "decision: " + e.decision : "ok") : "refused") };
    });
    a.steered.forEach(function (s) {
      var why = s.ok ? "went through" : (LAYER[s.blocked_by] || s.error || "refused") + (s.blocked_by === "action_policy" ? s.rule : "");
      lines.push({ kind: "steered", who: "tricked", text: s.tool + "  " + why, cls: s.ok ? "is-ok" : "is-no" });
    });
    var refusals = a.audit.filter(function (e) { return e.decision === "blocked"; });
    var unsent = a.steered.every(function (s) { return !s.reached_server; });
    var chainText = " Chain " + (a.audit_chain_verified ? "verifies." : "does not verify.");
    lines.push({
      kind: "audit", who: "audit log",
      text: unsent && !refusals.length
        ? "Stopped before it was sent, so nothing reached the server to log." + chainText
        : refusals.length + " refusal" + (refusals.length === 1 ? "" : "s") + " written to the log." + chainText
    });
    if (!(await playLines("attack", token, list, lines))) { return; }
    await wait(160);
    if (token !== runToken) { return; }
    var head = a.attack_succeeded ? "The attack had an effect." : "Contained. Nothing the planted text asked for happened.";
    var v = verdict(body, !a.attack_succeeded, head);
    v.appendChild(el("p", { "class": "verdict__aside" }, "The agent's own decision still came from the server's rules, not from the planted text."));
    announce.textContent = head;
    setBusy("attack", false);
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

  // Walks the chain top to bottom, one row at a time, so the break shows where it starts and
  // how it runs through every entry after it.
  async function verify(ctx) {
    var token = ++ctx.pass;
    var prev = "0".repeat(64);
    var broken = false;
    var good = 0;
    ctx.apply.disabled = true;
    ctx.undo.disabled = true;
    ctx.status.dataset.ok = "";
    ctx.text.textContent = "of " + ctx.chain.length + " verified so far.";
    ctx.rows.forEach(function (r) { r.dataset.state = "pending"; r.cells[5].textContent = "…"; });
    for (var i = 0; i < ctx.chain.length; i++) {
      var entry = ctx.chain[i];
      var digest = await sha256(prev + "\n" + entry.blob);
      if (token !== ctx.pass || ctx.token !== runToken) { return; }
      var ok = !broken && entry.prev_hash === prev && digest === entry.entry_hash;
      var row = ctx.rows[i];
      var hashCell = row.cells[4];
      hashCell.textContent = "";
      if (!ok && !broken) {
        hashCell.appendChild(el("s", { title: "stored hash" }, entry.entry_hash.slice(0, 12)));
        hashCell.appendChild(document.createTextNode(" "));
        hashCell.appendChild(el("span", { "class": "got", title: "hash of the edited entry" }, digest.slice(0, 12)));
      } else {
        hashCell.textContent = entry.entry_hash.slice(0, 12);
      }
      row.dataset.state = ok ? "ok" : (broken ? "broken" : "edited");
      row.cells[5].textContent = ok ? "verified" : (broken ? "after the break" : "hash does not match");
      if (!ok) { broken = true; } else { good += 1; }
      // Rows from the edit down slide right together, like a strip of paper torn at that line.
      // The offset goes straight onto the five cells, not through an inherited custom property.
      var tear = broken && !reduced() ? 10 : 0;
      (function (cells, t) {
        spring(cells[0], t, function (x) {
          var v = x > 0.01 ? "translateX(" + x.toFixed(2) + "px)" : "";
          for (var j = 1; j < cells.length; j++) { cells[j].style.transform = v; }
        }, { from: 0, response: 0.4 });
      })(row.cells, tear);
      countTo(ctx.count, good);
      prev = entry.entry_hash;
      setProgress("tamper", (i + 1) / ctx.chain.length);
      await wait(broken ? 170 : 90);
    }
    if (token !== ctx.pass) { return; }
    countTo(ctx.count, good);
    ctx.status.dataset.ok = String(!broken);
    ctx.text.textContent = broken
      ? "of " + ctx.chain.length + " entries verify. The edit shows, and every entry after it can no longer be trusted."
      : "of " + ctx.chain.length + " entries verify. Every entry hashes to the value stored after it.";
    announce.textContent = good + " " + ctx.text.textContent;
    ctx.apply.disabled = false;
    ctx.undo.disabled = !broken;
    setBusy("tamper", false);
  }

  function playTamper() {
    var token = ++runToken;
    setBusy("tamper", true);
    var body = reset("The audit log from the two decisions above", DATA.chain.length + " entries, SHA-256 chained");
    var chain = DATA.chain.map(function (e) { return Object.assign({}, e); });
    var table = el("table", { "class": "chain", translate: "no" });
    var thead = el("thead");
    var head = el("tr");
    ["", "#", "action", "request", "hash", "check"].forEach(function (h, i) {
      head.appendChild(el("th", { scope: "col" }, h));
      if (i === 0) { head.lastChild.appendChild(el("span", { "class": "sr-only" }, "chain link")); }
    });
    thead.appendChild(head);
    table.appendChild(thead);
    var tbody = el("tbody");
    var rows = chain.map(function (e) {
      var tr = el("tr", { "data-state": "pending" });
      tr.appendChild(el("td", { "class": "link", "aria-hidden": "true" }));
      tr.appendChild(el("td", { "class": "c-seq" }, String(e.seq)));
      tr.appendChild(el("td", {}, e.action + (e.decision && e.decision !== "granted" && e.decision !== "recorded" ? ": " + e.decision : "")));
      tr.appendChild(el("td", {}, e.request_id || "-"));
      tr.appendChild(el("td", { "class": "c-hash" }, e.entry_hash.slice(0, 12)));
      tr.appendChild(el("td", { "class": "c-check" }, "…"));
      tbody.appendChild(tr);
      return tr;
    });
    table.appendChild(tbody);
    var scroller = el("div", { "class": "chain-scroll", tabindex: "0", role: "region", "aria-label": "Audit chain" });
    scroller.appendChild(table);
    body.appendChild(scroller);

    var status = el("p", { "class": "chain-status" });
    var count = el("span", { "class": "chain-status__count" }, "0");
    status.appendChild(count);
    status.appendChild(document.createTextNode(" "));
    var text = el("span", { "class": "chain-status__text" });
    status.appendChild(text);
    body.appendChild(status);

    var controls = el("div", { "class": "tamper-controls" });
    var field = el("div", { "class": "field" });
    field.appendChild(el("label", { "for": "edit-pick" }, "Edit to make"));
    var pick = el("select", { "class": "select", id: "edit-pick" });
    EDITS.forEach(function (e, i) { pick.appendChild(el("option", { value: String(i) }, e.label)); });
    field.appendChild(pick);
    var apply = el("button", { "class": "btn btn--small btn--deny", type: "button" }, "Edit the old entry");
    var undo = el("button", { "class": "btn btn--small", type: "button", disabled: "" }, "Put it back");
    controls.appendChild(field); controls.appendChild(apply); controls.appendChild(undo);
    body.appendChild(controls);
    body.appendChild(el("p", { "class": "hint" }, "The check runs here in your browser with SHA-256 over the exact bytes the server hashed."));

    var ctx = { chain: chain, rows: rows, status: status, text: text, count: count, apply: apply, undo: undo, pass: 0, token: token };
    apply.addEventListener("click", function () {
      var edit = EDITS[Number(pick.value)];
      chain.forEach(function (e, i) { e.blob = DATA.chain[i].blob; });
      var target = chain.filter(function (e) { return e.action === "record_decision" && e.request_id === edit.where; })[0];
      target.blob = target.blob.replace(edit.find, edit.put);
      setBusy("tamper", true);
      verify(ctx);
    });
    undo.addEventListener("click", function () {
      chain.forEach(function (e, i) { e.blob = DATA.chain[i].blob; });
      undo.disabled = true;
      setBusy("tamper", true);
      verify(ctx).then(function () { apply.focus(); });
    });
    verify(ctx);
  }

  /* ------------------------------------------------------------------ totals */

  function counters() {
    var c = DATA.counters;
    var box = document.getElementById("counters");
    var rows = [
      { value: c.attacks_succeeded, unit: "of " + c.cases, label: "attacks had any effect" },
      { value: c.unsafe_auto_approvals, label: "unsafe approvals" },
      { value: c.cross_tenant_reads, label: "reads of another customer's data" },
      { value: c.audit_gaps, label: "actions missing from the log" },
      { value: c.reachable_writes_now, from: c.reachable_writes_v1, label: "writes an attacker could still make after a task",
        note: c.reachable_writes_v1 + " in version 1, " + c.reachable_writes_now + " now" }
    ];
    var animated = [];
    rows.forEach(function (r) {
      var li = el("li");
      var label = el("span", { "class": "totals__label" }, r.label);
      if (r.note) { label.appendChild(el("small", {}, r.note)); }
      li.appendChild(label);
      var value = el("span", { "class": "totals__value" + (r.value === 0 ? " is-zero" : "") });
      var n = el("span", {}, String(r.from !== undefined ? r.from : r.value));
      value.appendChild(n);
      if (r.unit) { value.appendChild(el("small", {}, r.unit)); }
      li.appendChild(value);
      box.appendChild(li);
      if (r.from !== undefined) { animated.push({ node: n, from: r.from, to: r.value }); }
    });
    var src = el("p", { "class": "source" }, "Source: " + c.source + ". With the boundary switched off, " + c.ablation_attacks_succeeded + " of " + c.cases + " attacks worked. Version 1 was measured on " + c.v1_cases + " attacks.");
    box.parentNode.appendChild(src);

    // The version 1 figure counts down to today's once the row is on screen, so the drop is seen, not just read.
    function run() { animated.forEach(function (a) { countTo(a.node, a.to, 0, a.from); }); }
    if (!("IntersectionObserver" in window) || reduced()) { run(); return; }
    var io = new IntersectionObserver(function (entries) {
      if (entries.some(function (e) { return e.isIntersecting; })) { io.disconnect(); setTimeout(run, 250); }
    }, { threshold: 0.6 });
    io.observe(box.lastChild);
  }

  /* ------------------------------------------------------------------ wiring */

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
    announce.textContent = "";
    if (which === "safe") { playDecision("safe", DATA.safe, "A dev feature flag", DATA.safe.request_id); }
    if (which === "dangerous") { playDecision("dangerous", DATA.dangerous, "A prod change inside a freeze window", DATA.dangerous.request_id); }
    if (which === "attack") {
      var a = DATA.attacks.filter(function (x) { return x.id === picker.value; })[0] || DATA.attacks[0];
      playAttack(a);
    }
    if (which === "tamper") { playTamper(); }
  }

  if (!DATA) {
    stage.textContent = "";
    stage.appendChild(el("div", { "class": "stage__empty" }, "The recorded runs did not load. The raw data is in data/replay.json."));
    document.querySelectorAll("[data-run]").forEach(function (b) { b.disabled = true; });
    picker.disabled = true;
    return;
  }
  document.querySelector("[data-w-badge]").textContent = "commit " + DATA.commit + ", " + DATA.generated_at.slice(0, 10);
  document.querySelector("[data-w-provenance]").textContent = "Recorded with " + DATA.recorded_with + ".";
  document.querySelector("[data-w-attack-count]").textContent = "one of " + DATA.attacks.length + " recorded";
  fillPicker();
  // Start on a case the server itself refuses and logs, the clearest one to watch.
  picker.value = "uaa-rp-01";
  counters();
  document.querySelectorAll("[data-run]").forEach(function (b) {
    b.addEventListener("click", function () { press(b.dataset.run); });
  });
  picker.addEventListener("change", function () { press("attack"); });
})();
