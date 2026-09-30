// Dashboard interactivity — kept in a separate file so the CSP
// (script-src 'self') stays strict.
const tickerLines = [
  "All systems nominal.",
  "Password hashes: still slow, still secure.",
  "No SQL was harmed in the making of this app.",
  "Your session cookie has been signed. It's legally binding now.",
  "CSRF tokens rotated. Politely.",
  "Rate limiter idling. It has never had to work.",
  "The .env file is gitignored. We checked.",
];
const tips = [
  "Don't reuse passwords. Even across tabs.",
  "A password manager is a vault. Your brain is a sticky note.",
  "If it sounds too good to be secure, it's a phishing email.",
  "Two-factor auth: two wrong guesses required. Worth it.",
  "HttpOnly means scripts can't read the cookie. The cookie is embarrassed.",
  "Rotate your secrets. Not your excuses.",
  "Backups are the only undo button life offers.",
  "Least privilege: give the bot only the key to one door.",
];

setInterval(() => {
  const el = document.getElementById("ticker");
  if (!el) return;
  el.classList.remove("flip");
  void el.offsetWidth;
  const i = (el.dataset.i || "0");
  const next = (parseInt(i, 10) + 1) % tickerLines.length;
  el.dataset.i = String(next);
  el.textContent = tickerLines[next];
  el.classList.add("flip");
}, 5000);

document.querySelector(".tip button").addEventListener("click", () => {
  tips.sort(() => Math.random() - 0.5);
  document.getElementById("tip").textContent = tips[0];
});

setTimeout(() => {
  const pct = 60 + Math.floor(Math.random() * 41);
  const fill = document.getElementById("clearance-fill");
  fill.style.width = pct + "%";
  setTimeout(() => {
    document.getElementById("clearance-label").textContent =
      "clearance recalibrated to " + pct + "%. do not tell it.";
  }, 900);
}, 400);