/* ==========================================================================
   demo-kit / kit.js

   CLASSIC SCRIPT. Not an ES module. There is no `import` and no `export`
   anywhere in this file, on purpose: ES modules are blocked under file://
   (the origin is null), and every demo page must survive a double-click on
   docs/index.html as well as being served from a GitHub Pages subpath.

   Load it exactly like this, with a relative path:
       <script src="kit.js" defer></script>

   It attaches one global, `window.Kit`, and touches nothing else.
   No network request is ever made except the optional same-origin
   fetch() of your own data JSON inside Kit.loadData, which falls back to an
   inlined copy when it cannot run.
   ========================================================================== */

(function (window, document) {
  "use strict";

  if (window.Kit) { return; }

  var Kit = {};
  Kit.version = "1.0.0";

  /* ------------------------------------------------------------------
     Small helpers
     ------------------------------------------------------------------ */

  function isEl(x) {
    return !!x && typeof x === "object" && x.nodeType === 1;
  }

  function resolve(root, sel) {
    if (!isEl(root)) { return null; }
    return root.querySelector(sel);
  }

  function warn(msg) {
    if (window.console && window.console.warn) {
      window.console.warn("[Kit] " + msg);
    }
  }

  /* Escape text destined for innerHTML. Exposed because the demo pages
     interpolate values out of their data files. */
  Kit.escapeHtml = function (value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  };

  /* ------------------------------------------------------------------
     Kit.loadData(name, jsonPath) -> Promise<object>

     One code path, two environments.

       1. If the page is on file:, or fetch is missing, or no jsonPath was
          given, read window.DEMO_DATA[name] straight away.
       2. Otherwise try fetch(jsonPath). Any failure at all (network, bad
          status, unparseable JSON) falls back to window.DEMO_DATA[name].
       3. If neither source has the data, reject with a message that names
          the exact fix.

     The caller gets the same object either way.
     ------------------------------------------------------------------ */

  function readInline(name) {
    var bag = window.DEMO_DATA;
    if (bag && Object.prototype.hasOwnProperty.call(bag, name)) {
      return bag[name];
    }
    return undefined;
  }

  Kit.loadData = function (name, jsonPath) {
    return new Promise(function (resolveP, rejectP) {
      function fallback(reason) {
        var inline = readInline(name);
        if (inline !== undefined) {
          resolveP(inline);
          return;
        }
        rejectP(new Error(
          'Kit.loadData: no data for "' + name + '". ' +
          "Tried " + (jsonPath ? jsonPath : "(no json path)") +
          (reason ? " (" + reason + ")" : "") +
          ', then window.DEMO_DATA["' + name + '"]. ' +
          "Load data/" + name + ".js with a plain <script> tag before kit.js runs."
        ));
      }

      if (typeof name !== "string" || !name) {
        rejectP(new Error("Kit.loadData: name must be a non-empty string."));
        return;
      }

      if (typeof jsonPath === "string" && jsonPath.charAt(0) === "/") {
        warn(
          "loadData was given an absolute path (" + jsonPath + "). " +
          "These pages are served from a subpath, use a relative path such as " +
          "data/" + name + ".json"
        );
      }

      var onFile = false;
      try { onFile = window.location.protocol === "file:"; } catch (e) { onFile = true; }

      if (onFile || typeof window.fetch !== "function" || !jsonPath) {
        fallback(onFile ? "file: protocol" : "fetch unavailable or no path");
        return;
      }

      var req;
      try {
        req = window.fetch(jsonPath, { credentials: "same-origin" });
      } catch (e) {
        fallback("fetch threw");
        return;
      }

      req.then(function (res) {
        if (!res || !res.ok) {
          throw new Error("HTTP " + (res ? res.status : "?"));
        }
        return res.json();
      }).then(function (obj) {
        resolveP(obj);
      })["catch"](function (err) {
        fallback(err && err.message ? err.message : "fetch failed");
      });
    });
  };

  /* ------------------------------------------------------------------
     Kit.stepPlayer(rootEl, options) -> controller

     options:
       steps      Array, required. Each entry may be a string, or an object
                  { html | text, caption, label }.
       onRender   function(step, index, ctx). Optional. Fills the stage.
                  ctx = { stage, caption, total, root }.
                  The kit always writes the caption itself from step.caption,
                  so a caption can never be forgotten.
       autoplayMs Number, default 2600. Dwell time per step while playing.
       startIndex Number, default 0.
       label      String for the aria-label on the stage region.

     controller: play, pause, toggle, next, prev, goTo, destroy,
                 index (getter fn), length, isPlaying (getter fn).

     Behaviour that is not negotiable here:
       - Backward stepping is available at every index above 0.
       - Autoplay stops at the last step. It never loops and never wraps.
       - Every step change is announced through an aria-live polite region.
       - Left and Right arrows work whenever focus is inside the player.
     ------------------------------------------------------------------ */

  var playerSeq = 0;

  Kit.stepPlayer = function (rootEl, options) {
    options = options || {};

    if (!isEl(rootEl)) {
      warn("stepPlayer: root element missing, nothing mounted.");
      return null;
    }

    var steps = options.steps;
    if (!steps || !steps.length) {
      warn("stepPlayer: no steps supplied, nothing mounted.");
      return null;
    }

    var total = steps.length;
    var dwell = typeof options.autoplayMs === "number" ? options.autoplayMs : 2600;

    var stage     = resolve(rootEl, "[data-k-stage]");
    var caption   = resolve(rootEl, "[data-k-caption]");
    var live      = resolve(rootEl, "[data-k-live]");
    var indicator = resolve(rootEl, "[data-k-indicator]");
    var track     = resolve(rootEl, "[data-k-track]");
    var btnPrev   = resolve(rootEl, "[data-k-prev]");
    var btnPlay   = resolve(rootEl, "[data-k-play]");
    var btnNext   = resolve(rootEl, "[data-k-next]");

    if (!stage) {
      warn("stepPlayer: no [data-k-stage] inside the player root.");
      return null;
    }

    playerSeq += 1;
    var stageId = rootEl.id || ("k-player-" + playerSeq);
    if (!rootEl.id) { rootEl.id = stageId; }

    /* Wire the a11y contract onto the markup so a page cannot get it wrong. */
    stage.setAttribute("tabindex", "0");
    stage.setAttribute("role", "region");
    stage.setAttribute("aria-label", options.label || "Recorded run, step content");

    if (live) {
      live.setAttribute("aria-live", "polite");
      live.setAttribute("aria-atomic", "true");
      live.setAttribute("role", "status");
    }
    /* The visible counter would double-announce next to the live region. */
    if (indicator) { indicator.setAttribute("aria-hidden", "true"); }
    if (track) { track.setAttribute("aria-hidden", "true"); }

    /* Ticks are built once, up front, so the row never changes height. */
    var ticks = [];
    if (track) {
      track.innerHTML = "";
      for (var t = 0; t < total; t++) {
        var tick = document.createElement("span");
        tick.className = "k-player__tick";
        track.appendChild(tick);
        ticks.push(tick);
      }
    }

    var index = 0;
    var playing = false;
    var timer = null;
    var destroyed = false;

    function clampIndex(i) {
      i = Math.round(Number(i));
      if (!isFinite(i)) { return 0; }
      if (i < 0) { return 0; }
      if (i > total - 1) { return total - 1; }
      return i;
    }

    function stepCaption(step) {
      if (step && typeof step === "object" && typeof step.caption === "string") {
        return step.caption;
      }
      return "";
    }

    function defaultRender(step) {
      if (typeof step === "string") {
        stage.textContent = step;
        return;
      }
      if (step && typeof step === "object") {
        if (typeof step.html === "string") {
          /* Authored content out of your own data file, not user input. */
          stage.innerHTML = step.html;
          return;
        }
        if (typeof step.text === "string") {
          stage.textContent = step.text;
          return;
        }
      }
      stage.textContent = "";
    }

    function setDisabled(btn, off) {
      if (!btn) { return; }
      btn.setAttribute("aria-disabled", off ? "true" : "false");
    }

    function render() {
      var step = steps[index];

      if (typeof options.onRender === "function") {
        try {
          options.onRender(step, index, {
            stage: stage, caption: caption, total: total, root: rootEl
          });
        } catch (e) {
          warn("stepPlayer: onRender threw at step " + (index + 1) + ".");
          defaultRender(step);
        }
      } else {
        defaultRender(step);
      }

      var text = stepCaption(step);
      if (caption) { caption.textContent = text; }

      var counter = "Step " + (index + 1) + " of " + total;
      if (indicator) { indicator.textContent = counter; }
      if (live) { live.textContent = counter + (text ? ". " + text : ""); }

      for (var i = 0; i < ticks.length; i++) {
        ticks[i].setAttribute("data-done", i <= index ? "true" : "false");
      }

      setDisabled(btnPrev, index === 0);
      setDisabled(btnNext, index === total - 1);

      rootEl.setAttribute("data-state", playing ? "playing" : "paused");
      rootEl.setAttribute("data-index", String(index));
    }

    function clearTimer() {
      if (timer !== null) {
        window.clearTimeout(timer);
        timer = null;
      }
    }

    function schedule() {
      clearTimer();
      if (!playing || destroyed) { return; }
      timer = window.setTimeout(function () {
        timer = null;
        if (!playing || destroyed) { return; }
        if (index >= total - 1) {
          pause();          /* Stop at the end. Never wrap, never loop. */
          return;
        }
        index = index + 1;
        render();
        schedule();
      }, dwell);
    }

    function setPlayLabel() {
      if (!btnPlay) { return; }
      var word = playing ? "Pause" : "Play";
      var textNode = btnPlay.querySelector("[data-k-play-label]");
      if (textNode) { textNode.textContent = word; }
      else { btnPlay.textContent = word; }
      btnPlay.setAttribute("aria-label", playing ? "Pause the run" : "Play the run");
      btnPlay.setAttribute("aria-pressed", playing ? "true" : "false");
    }

    function play() {
      if (destroyed || playing) { return; }
      /* Pressing play on the last step replays from the beginning, which is
         an explicit user action, not a silent loop. */
      if (index >= total - 1) { index = 0; }
      playing = true;
      setPlayLabel();
      render();
      schedule();
    }

    /* Stop the clock without repainting. Used when the very next thing we do
       is move to another step, so the live region announces once, not twice. */
    function stopClock() {
      playing = false;
      clearTimer();
      setPlayLabel();
    }

    function pause() {
      if (destroyed) { return; }
      stopClock();
      render();
    }

    function toggle() { if (playing) { pause(); } else { play(); } }

    function goTo(i, announce) {
      if (destroyed) { return; }
      var next = clampIndex(i);
      if (next === index && announce !== true) { return; }
      index = next;
      render();
      if (playing) { schedule(); }
    }

    function next() {
      if (destroyed || index >= total - 1) { return; }
      stopClock();                /* Manual stepping takes over from autoplay. */
      goTo(index + 1, true);
    }

    function prev() {
      if (destroyed || index <= 0) { return; }
      stopClock();
      goTo(index - 1, true);
    }

    /* ---- events ---- */

    function onPrev(ev) { ev.preventDefault(); prev(); }
    function onNext(ev) { ev.preventDefault(); next(); }
    function onPlay(ev) { ev.preventDefault(); toggle(); }

    function typingTarget(el) {
      if (!isEl(el)) { return false; }
      var tag = el.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") { return true; }
      return el.isContentEditable === true;
    }

    /* Bound on the root, so it fires wherever focus sits inside the player. */
    function onKey(ev) {
      if (ev.defaultPrevented || ev.altKey || ev.ctrlKey || ev.metaKey) { return; }
      if (typingTarget(ev.target)) { return; }

      var k = ev.key;
      if (k === "ArrowRight") { ev.preventDefault(); next(); return; }
      if (k === "ArrowLeft")  { ev.preventDefault(); prev(); return; }
      if (k === "Home")       { ev.preventDefault(); stopClock(); goTo(0, true); return; }
      if (k === "End")        { ev.preventDefault(); stopClock(); goTo(total - 1, true); return; }
      if (k === " " || k === "Spacebar") {
        /* Let the buttons keep their own native space activation. */
        if (ev.target === stage) { ev.preventDefault(); toggle(); }
      }
    }

    if (btnPrev) { btnPrev.addEventListener("click", onPrev); }
    if (btnNext) { btnNext.addEventListener("click", onNext); }
    if (btnPlay) { btnPlay.addEventListener("click", onPlay); }
    rootEl.addEventListener("keydown", onKey);

    /* Pause if the tab is hidden, so a reader never comes back mid-run. */
    function onVisibility() {
      if (document.hidden && playing) { pause(); }
    }
    document.addEventListener("visibilitychange", onVisibility);

    index = clampIndex(options.startIndex || 0);
    setPlayLabel();
    render();

    var controller = {
      play: play,
      pause: pause,
      toggle: toggle,
      next: next,
      prev: prev,
      goTo: function (i) { stopClock(); goTo(i, true); },
      length: total,
      index: function () { return index; },
      isPlaying: function () { return playing; },
      destroy: function () {
        destroyed = true;
        clearTimer();
        if (btnPrev) { btnPrev.removeEventListener("click", onPrev); }
        if (btnNext) { btnNext.removeEventListener("click", onNext); }
        if (btnPlay) { btnPlay.removeEventListener("click", onPlay); }
        rootEl.removeEventListener("keydown", onKey);
        document.removeEventListener("visibilitychange", onVisibility);
      }
    };

    return controller;
  };

  /* ------------------------------------------------------------------
     Kit.heroWash(heroEl) -> { destroy }

     Cursor-tracked radial wash, hero only.

       - One pending rAF at most. pointermove only stores coordinates.
       - Off entirely under prefers-reduced-motion: reduce, and re-checked
         live when the user flips that setting.
       - Touch and pen never move it. Without a mouse the hero keeps the
         designed resting position from CSS and looks finished.
       - Writes a custom property on the wash layer only. The wash is
         position: absolute inside a `contain: paint` hero, so nothing
         outside the hero repaints and nothing reflows.
       - The wash layer is pointer-events: none, so selection and hero
         links behave exactly as they would without it.
     ------------------------------------------------------------------ */

  Kit.heroWash = function (heroEl, opts) {
    opts = opts || {};

    if (!isEl(heroEl)) { return { destroy: function () {} }; }

    var wash = heroEl.querySelector("[data-k-wash]") ||
               heroEl.querySelector(".k-hero__wash");
    if (!wash) { return { destroy: function () {} }; }

    var restX = opts.restX || "82%";
    var restY = opts.restY || "14%";

    var mq = null;
    if (typeof window.matchMedia === "function") {
      mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    }

    var frame = 0;
    var px = 0, py = 0;
    var attached = false;
    var dead = false;

    var hasCustomRest = !!(opts.restX || opts.restY);

    /* Back to the resting composition: drop the inline values so the CSS
       defaults take over again, unless this page asked for its own. */
    function reset() {
      if (hasCustomRest) {
        wash.style.setProperty("--k-wash-x", restX);
        wash.style.setProperty("--k-wash-y", restY);
      } else {
        wash.style.removeProperty("--k-wash-x");
        wash.style.removeProperty("--k-wash-y");
      }
    }

    function paint() {
      frame = 0;
      if (dead) { return; }
      var r = heroEl.getBoundingClientRect();
      if (!r.width || !r.height) { return; }
      var x = ((px - r.left) / r.width) * 100;
      var y = ((py - r.top) / r.height) * 100;
      if (x < -20) { x = -20; } else if (x > 120) { x = 120; }
      if (y < -20) { y = -20; } else if (y > 120) { y = 120; }
      wash.style.setProperty("--k-wash-x", x.toFixed(2) + "%");
      wash.style.setProperty("--k-wash-y", y.toFixed(2) + "%");
    }

    function onMove(ev) {
      /* Mouse only. A finger or a stylus leaves the resting composition. */
      if (ev.pointerType && ev.pointerType !== "mouse") { return; }
      px = ev.clientX;
      py = ev.clientY;
      if (frame) { return; }              /* One pending frame, maximum. */
      frame = window.requestAnimationFrame(paint);
    }

    function onLeave() {
      if (frame) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
      reset();
    }

    function attach() {
      if (attached || dead) { return; }
      heroEl.addEventListener("pointermove", onMove, { passive: true });
      heroEl.addEventListener("pointerleave", onLeave, { passive: true });
      attached = true;
    }

    function detach() {
      if (!attached) { return; }
      heroEl.removeEventListener("pointermove", onMove);
      heroEl.removeEventListener("pointerleave", onLeave);
      attached = false;
      if (frame) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
      reset();
    }

    function apply() {
      if (dead) { return; }
      var reduce = mq ? mq.matches : false;
      var canHover = true;
      if (typeof window.matchMedia === "function") {
        canHover = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
      }
      var noRaf = typeof window.requestAnimationFrame !== "function";
      if (reduce || !canHover || noRaf) { detach(); } else { attach(); }
    }

    /* Live re-check when the OS preference changes mid-visit. */
    var mqOff = function () {};
    if (mq) {
      if (typeof mq.addEventListener === "function") {
        mq.addEventListener("change", apply);
        mqOff = function () { mq.removeEventListener("change", apply); };
      } else if (typeof mq.addListener === "function") {
        mq.addListener(apply);
        mqOff = function () { mq.removeListener(apply); };
      }
    }

    /* The resting composition lives in CSS (--k-wash-x / --k-wash-y on :root),
       so the hero is already finished before this script runs. reset() only
       writes inline values when this page asked for its own resting point. */
    reset();

    apply();

    return {
      destroy: function () {
        dead = true;
        detach();
        mqOff();
      }
    };
  };

  /* ------------------------------------------------------------------
     Kit.recordedRunBadge(el, { date, commit, href, label })

     Fills a badge element that already exists in the markup, so it takes up
     its space from first paint and nothing shifts when JS runs.
     ------------------------------------------------------------------ */

  Kit.recordedRunBadge = function (el, info) {
    if (!isEl(el)) { return; }
    info = info || {};

    var date = info.date || "";
    var commit = String(info.commit || "").slice(0, 7);
    var label = info.label || "Recorded run";

    var parts = [label];
    if (date) { parts.push(date); }

    var text = el.querySelector("[data-k-badge-text]");
    var target = text || el;

    var html = Kit.escapeHtml(parts.join(", "));
    if (commit) {
      html += ", commit <span class=\"k-badge-run__sha\">" +
              Kit.escapeHtml(commit) + "</span>";
    }
    target.innerHTML = html;

    if (info.href && el.tagName === "A") {
      if (String(info.href).charAt(0) === "/") {
        warn("recordedRunBadge: href is absolute, use a relative path.");
      }
      el.setAttribute("href", info.href);
    }

    var readable = parts.join(", ") + (commit ? ", commit " + commit : "");
    el.setAttribute("aria-label", readable + ", opens the captured data file");
    el.setAttribute("title", readable);
  };

  /* ------------------------------------------------------------------
     Kit.theme

     "system" clears the override and lets prefers-color-scheme decide.
     localStorage can throw in a locked-down browser or under file:, so
     every access is guarded.
     ------------------------------------------------------------------ */

  var THEME_KEY = "k-theme";

  function store(key, value) {
    try {
      if (value === null) { window.localStorage.removeItem(key); }
      else { window.localStorage.setItem(key, value); }
    } catch (e) { /* private mode, or file:, both fine to ignore */ }
  }

  function read(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }

  Kit.theme = {
    get: function () {
      var v = document.documentElement.getAttribute("data-theme");
      return v === "dark" || v === "light" ? v : "system";
    },
    set: function (mode) {
      var root = document.documentElement;
      if (mode === "dark" || mode === "light") {
        root.setAttribute("data-theme", mode);
        store(THEME_KEY, mode);
      } else {
        root.removeAttribute("data-theme");
        store(THEME_KEY, null);
      }
      return Kit.theme.get();
    },
    restore: function () {
      var saved = read(THEME_KEY);
      if (saved === "dark" || saved === "light") {
        document.documentElement.setAttribute("data-theme", saved);
      }
      return Kit.theme.get();
    },
    mount: function (btn) {
      if (!isEl(btn)) { return; }
      function label() {
        var mode = Kit.theme.get();
        var word = mode === "dark" ? "Dark" : (mode === "light" ? "Light" : "Auto");
        var slot = btn.querySelector("[data-k-theme-label]");
        if (slot) { slot.textContent = word; } else { btn.textContent = word; }
        btn.setAttribute("aria-label", "Colour theme: " + word + ". Activate to change.");
      }
      btn.addEventListener("click", function () {
        var order = ["system", "light", "dark"];
        var at = order.indexOf(Kit.theme.get());
        Kit.theme.set(order[(at + 1) % order.length]);
        label();
      });
      label();
    }
  };

  /* ------------------------------------------------------------------
     Auto-wiring. Opt in from markup, no surprises.
       [data-k-hero-wash]     on the hero element
       [data-k-theme-toggle]  on a button
     ------------------------------------------------------------------ */

  /* Applied at script-execution time, not at DOMContentLoaded. A deferred
     classic script runs after parsing but before first paint, so a saved
     theme is in place before anything is drawn and there is no flash. */
  Kit.theme.restore();

  function autoInit() {
    var heroes = document.querySelectorAll("[data-k-hero-wash]");
    for (var i = 0; i < heroes.length; i++) { Kit.heroWash(heroes[i]); }

    var toggles = document.querySelectorAll("[data-k-theme-toggle]");
    for (var j = 0; j < toggles.length; j++) { Kit.theme.mount(toggles[j]); }
  }

  Kit.autoInit = autoInit;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", autoInit);
  } else {
    autoInit();
  }

  window.Kit = Kit;

})(window, document);
