// Loaded SYNCHRONOUSLY in <head>, before anything paints.
//
// The Content-Security-Policy is `default-src 'self'`, which forbids inline
// script -- so the usual one-line anti-flash snippet cannot live in the HTML.
// This file is that snippet, served from the same origin. It must stay tiny and
// must not touch the DOM beyond the root element, because it runs before <body>
// exists.
(function () {
  try {
    var stored = localStorage.getItem("veridor-theme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.setAttribute("data-theme", stored);
    }
  } catch (error) {
    // A browser with storage disabled still gets the system preference via the
    // prefers-color-scheme media query in the stylesheet. Nothing to do.
  }
})();
