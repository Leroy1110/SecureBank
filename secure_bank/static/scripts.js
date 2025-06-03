/* static/scripts.js */
(() => {
    const toggle = document.getElementById('theme-toggle');
    if (!toggle) return;
    const root = document.documentElement;

    const stored = localStorage.getItem('sb-theme');
    if (stored) root.setAttribute('data-bs-theme', stored);

    toggle.addEventListener('click', () => {
        const current = root.getAttribute('data-bs-theme') || 'light';
        const next = current === 'light' ? 'dark' : 'light';
        root.setAttribute('data-bs-theme', next);
        localStorage.setItem('sb-theme', next);
    });
})();