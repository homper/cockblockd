(function () {
  "use strict";
  if (window.__cb_kwblock_init) return;
  window.__cb_kwblock_init = true;

  var KEYWORDS = [];
  var TITLE_ONLY = false;
  var re = null;
  var blocked = false;

  function buildRegex(keywords) {
    if (!keywords || !keywords.length) return null;
    var esc = function (s) {
      return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    };
    var pattern = "(?<![\\p{L}\\p{N}])(?:" +
      keywords.map(esc).join("|") +
      ")(?![\\p{L}\\p{N}])";
    return new RegExp(pattern, "iu");
  }

  function check() {
    if (blocked || !re) return;
    var text = document.title || "";
    if (!TITLE_ONLY && document.body) {
      text += " " + (document.body.textContent || "");
    }
    if (re.test(text)) {
      blocked = true;
      browser.runtime.sendMessage({ cmd: "close-tab" }).catch(function () {});
    }
  }

  function start() {
    check();
    var timer = 0;
    function schedule() {
      clearTimeout(timer);
      timer = setTimeout(check, 300);
    }
    var titleEl = document.querySelector("title");
    if (titleEl) {
      new MutationObserver(schedule).observe(titleEl, {
        childList: true,
        characterData: true,
        subtree: true
      });
    }
    ["pushState", "replaceState"].forEach(function (m) {
      var orig = history[m];
      history[m] = function () {
        orig.apply(this, arguments);
        schedule();
      };
    });
    window.addEventListener("popstate", schedule);
    window.addEventListener("hashchange", schedule);
  }

  // Keyword list comes from managed storage (a JSON manifest on disk that
  // is never bundled in the signed package).
  browser.storage.managed.get(null).then(function (cfg) {
    KEYWORDS = Array.isArray(cfg.keywords) ? cfg.keywords : [];
    TITLE_ONLY = !!cfg.titleOnly;
    re = buildRegex(KEYWORDS);
    start();
  }).catch(function () {
    start();
  });
})();
