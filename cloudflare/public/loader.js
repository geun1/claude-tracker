// Top-progress bar + fetch interceptor. Insert via <script src="/loader.js"></script>.
(function () {
  if (window.__trackerLoader) return;
  window.__trackerLoader = true;
  const css = `
    #__progress{position:fixed;top:0;left:0;height:2px;width:0;background:linear-gradient(90deg,#fb923c,#f0abfc);
      z-index:9999;transition:width .25s ease, opacity .35s ease;box-shadow:0 0 6px #fb923c;opacity:0}
    #__progress.show{opacity:1}
    .skel{display:inline-block;background:linear-gradient(90deg,#1f242c 25%,#2a2f37 50%,#1f242c 75%);
      background-size:200% 100%;animation:skel 1.2s linear infinite;border-radius:4px;height:14px;width:100%}
    @keyframes skel{0%{background-position:200% 0}100%{background-position:-200% 0}}
    .skel-line{display:block;height:14px;margin:6px 0;background:linear-gradient(90deg,#1f242c 25%,#2a2f37 50%,#1f242c 75%);
      background-size:200% 100%;animation:skel 1.2s linear infinite;border-radius:4px}
  `;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);
  const bar = document.createElement("div");
  bar.id = "__progress";
  document.documentElement.appendChild(bar);

  let active = 0, target = 0, timer = null;
  function tick() {
    if (active === 0) {
      bar.style.width = "100%";
      bar.classList.remove("show");
      setTimeout(() => { bar.style.width = "0"; }, 350);
      clearInterval(timer); timer = null;
      return;
    }
    target = Math.min(0.92, target + (1 - target) * 0.15);
    bar.style.width = (target * 100).toFixed(1) + "%";
  }
  function start() {
    active++;
    if (active === 1) {
      target = 0.05;
      bar.style.width = "5%";
      bar.classList.add("show");
      if (!timer) timer = setInterval(tick, 250);
    }
  }
  function done() {
    active = Math.max(0, active - 1);
    if (active === 0) tick();
  }
  const orig = window.fetch;
  window.fetch = function (...args) {
    start();
    return orig.apply(this, args).finally(done);
  };
  // Expose for manual control if needed
  window.__loader = { start, done };
})();
