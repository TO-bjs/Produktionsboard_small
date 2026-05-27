(function () {
  const SLIDESHOW_FLAG = "slideshow";
  const SLIDESHOW_VALUE = "1";

  const FLOW_CONFIG = {
    intervalMs: 60000,
    pages: ["/landing", "/anzeige", "/schulungen", "/qualimatrix"],
    startPath: "/landing"
  };

  let flowTimeoutId = null;

  function normalizePath(path) {
    return (path || "").replace(/\/+$/, "") || "/";
  }

  function isSlideshowEnabled() {
    const params = new URLSearchParams(window.location.search);
    return params.get(SLIDESHOW_FLAG) === SLIDESHOW_VALUE;
  }

  function getSlideshowIndex(pathname) {
    return FLOW_CONFIG.pages.indexOf(normalizePath(pathname));
  }

  function getNextSlideshowUrl(pathname) {
    const currentIndex = getSlideshowIndex(pathname);
    if (currentIndex === -1) return null;

    const nextPath = FLOW_CONFIG.pages[(currentIndex + 1) % FLOW_CONFIG.pages.length];
    return `${nextPath}?${SLIDESHOW_FLAG}=${SLIDESHOW_VALUE}`;
  }

  function stopPageFlow() {
    if (flowTimeoutId) {
      clearTimeout(flowTimeoutId);
      flowTimeoutId = null;
    }
  }

  function startPageFlow(options = {}) {
    const force = options.force === true;
    if (!force && !isSlideshowEnabled()) return false;

    stopPageFlow();
    const nextUrl = getNextSlideshowUrl(window.location.pathname);
    if (!nextUrl) return false;

    flowTimeoutId = setTimeout(() => {
      window.location.href = nextUrl;
    }, FLOW_CONFIG.intervalMs);

    return true;
  }

  function getStartUrl() {
    return `${FLOW_CONFIG.startPath}?${SLIDESHOW_FLAG}=${SLIDESHOW_VALUE}`;
  }

  window.SlideshowFlow = {
    config: FLOW_CONFIG,
    isSlideshowEnabled,
    startPageFlow,
    stopPageFlow,
    getNextSlideshowUrl,
    getStartUrl
  };
})();
