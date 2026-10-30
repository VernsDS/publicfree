require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const helmet = require('helmet');
const mongoose = require('mongoose');

const app = express();

// Trust proxy sangat penting untuk Vercel agar bisa membaca IP asli user
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(helmet({ contentSecurityPolicy: false }));

// ================= DATABASE MONGODB =================
const MONGODB_URI = process.env.MONGODB_URI; 

// Koneksi MongoDB (Tanpa opsi usenewurlparser untuk Mongoose versi terbaru)
mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Terhubung ke Database MongoDB!'))
    .catch(err => {
        console.log('❌ KONEKSI MONGODB GAGAL!');
        console.log('Alasan Error:', err.message);
    });

// Skema Database User (Menyimpan IP dan Jumlah Kuota)
const UserSchema = new mongoose.Schema({
    ipAddress: { type: String, required: true, unique: true },
    usedQuota: { type: Number, default: 0 },
    subdomains: [String]
});
const User = mongoose.model('User', UserSchema);
// ====================================================

// Ambil IP User Asli (Disesuaikan untuk sistem proxy Vercel)
const getClientIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
    if (ip) {
        ip = ip.split(',')[0].trim(); // Ambil IP paling depan jika ada banyak (Vercel)
        return ip.replace('::ffff:', '');
    }
    return 'unknown';
};

// 1. Endpoint Tampilan Web Utama
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. Endpoint Cek Status Kuota (Untuk Progress Bar Frontend)
app.get('/api/status', async (req, res) => {
    const ip = getClientIp(req);
    try {
        let user = await User.findOne({ ipAddress: ip });
        if (!user) user = { usedQuota: 0 }; // Jika belum pernah buat
        res.json({ success: true, used: user.usedQuota, limit: 2 });
    } catch (err) {
        console.log('Error API Status:', err.message);
        res.json({ success: true, used: 0, limit: 2 });
    }
});

// 3. Endpoint Eksekusi Subdomain
app.post('/api/create', async (req, res) => {
    const { subdomain, domain, recordType, target, cfToken } = req.body;
    const ip = getClientIp(req);

    if (!subdomain || !domain || !recordType || !target || !cfToken) {
        return res.status(400).json({ success: false, message: "Semua data wajib diisi!" });
    }

    try {
        // Cek Kuota Database
        let user = await User.findOne({ ipAddress: ip });
        if (user && user.usedQuota >= 2) {
            return res.status(403).json({ success: false, message: "Limit Tercapai: Kamu sudah membuat 2 subdomain dari IP ini." });
        }

        // Verifikasi Turnstile Captcha
        const verifyTurnstile = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            secret: process.env.TURNSTILE_SECRET_KEY,
            response: cfToken
        });
        if (!verifyTurnstile.data.success) {
            return res.status(403).json({ success: false, message: "Verifikasi Captcha gagal." });
        }

        // Tembak Cloudflare API
        const zoneId = process.env.CF_ZONE_PUBLICFREE;
        await axios.post(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
            type: recordType,
            name: `${subdomain}.${domain}`,
            content: target,
            ttl: 1,
            proxied: false
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.CF_API_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });

        // JIKA SUKSES -> Simpan IP & Kurangi Kuota di Database
        if (!user) {
            user = new User({ ipAddress: ip, usedQuota: 1, subdomains: [`${subdomain}.${domain}`] });
        } else {
            user.usedQuota += 1;
            user.subdomains.push(`${subdomain}.${domain}`);
        }
        await user.save();

        return res.json({ success: true, message: `${subdomain}.${domain} berhasil dibuat!` });

    } catch (error) {
        if (error.response?.data?.errors) {
            return res.status(400).json({ success: false, message: `Cloudflare: ${error.response.data.errors[0].message}` });
        }
        console.log('Error API Create:', error.message);
        return res.status(500).json({ success: false, message: "Terjadi gangguan pada server backend." });
    }
});

// ================= PENGATURAN SERVER VERCEL =================
// Memastikan app.listen HANYA berjalan di komputer lokal (testing),
// dan otomatis mati saat di-deploy ke Vercel agar tidak menyebabkan crash.
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 API Landing Page aktif di port ${PORT}`));
}

// WAJIB ADA: Mengekspor aplikasi agar bisa dibaca oleh sistem Vercel Serverless
module.exports = app;