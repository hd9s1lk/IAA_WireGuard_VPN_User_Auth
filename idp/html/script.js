function startCountdown(seconds) {
    const countdown = document.getElementById('countdown');
    if (!countdown) return;

    let remaining = seconds;
    const interval = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
            clearInterval(interval);
            window.location.href = '/login';
        } else {
            countdown.textContent = remaining;
        }
    }, 1000);
}
