// Scroll Animation Effect
document.addEventListener("DOMContentLoaded", function () {
    const heroText = document.querySelector(".hero-text");

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add("visible");
            }
        });
    });

    observer.observe(heroText);
});

// Change Nav Background on Scroll
window.addEventListener("scroll", function () {
    let nav = document.querySelector("nav");
    if (window.scrollY > 50) {
        nav.classList.add("scrolled");
    } else {
        nav.classList.remove("scrolled");
    }
});
