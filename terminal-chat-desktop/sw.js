// public/sw.js

self.addEventListener('push', e => {
    const data = e.data.json();

    self.registration.showNotification(data.title, {
        body: data.body,
        icon: 'https://cdn-icons-png.flaticon.com/512/2069/2069503.png', // Cooles Hacker Icon URL oder lokal
        vibrate: [200, 100, 200]
    });
});