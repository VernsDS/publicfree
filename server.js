require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const helmet = require('helmet');
const mongoose = require('mongoose');

const app = express();

// Trust proxy wajib di Vercel/Cloudflare supaya IP asli user terbaca dari X-Forwarded-For
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '16kb' }));
app.use(helmet({ contentSecurityPolicy: false }));

// ================= KONFIGURASI =================
const MONGODB_URI = process.env.MONGODB_URI;
const PUBLIC_DOMAIN = String(process.env.PUBLIC_DOMAIN || 'publicfree.web.id').trim().toLowerCase();

const parsedLimit = Number.parseInt(process.env.MAX_SUBDOMAINS_PER_IP, 10);
const MAX_SUBDOMAINS = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : 2;

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

// ================= DATABASE MONGODB =================
// Koneksi di-cache per instance lambda. Tanpa ini, request pertama bisa datang
// sebelum koneksi selesai dan Mongo "buffering" sampai function timeout.
let dbPromise = null;

function connectDB() {
    if (mongoose.connection.readyState === 1) return Promise.resolve();
    if (!MONGODB_URI) return Promise.reject(new Error('MONGODB_URI belum diatur'));

    if (!dbPromise) {
        dbPromise = mongoose
            .connect(MONGODB_URI, { serverSelectionTimeoutMS: 8000, maxPoolSize: 5 })
            .then(() => {
                console.log('✅ Terhubung ke Database MongoDB!');
            })
            .catch((err) => {
                dbPromise = null; // biar request berikutnya mencoba menyambung lagi
                console.error('❌ KONEKSI MONGODB GAGAL:', err.message);
                throw err;
            });
    }
    return dbPromise;
}

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err.message);
});

// Skema Database User (Menyimpan IP, Jumlah Kuota, dan Daftar Subdomain)
const SubdomainRecordSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        type: { type: String, default: 'A' },
        target: { type: String, default: '' },
        createdAt: { type: Date, default: Date.now }
    },
    { _id: false }
);

const UserSchema = new mongoose.Schema(
    {
        ipAddress: { type: String, required: true, unique: true },
        usedQuota: { type: Number, default: 0 },
        // Dipertahankan untuk kompatibilitas data lama
        subdomains: [String],
        // Data lengkap untuk menu "List Domain Saya"
        records: [SubdomainRecordSchema]
    },
    { timestamps: true }
);

const User = mongoose.models.User || mongoose.model('User', UserSchema);
// ====================================================

// ================= HELPER =================
// Ambil IP User Asli (disesuaikan untuk proxy Vercel / Cloudflare)
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (!ip) ip = req.headers['cf-connecting-ip'] || req.socket?.remoteAddress || req.ip || '';
    ip = String(ip).split(',')[0].trim().replace(/^::ffff:/i, '');
    return ip || 'unknown';
};

const normalizeName = (value) => String(value || '').trim().toLowerCase().replace(/\.$/, '');

const isValidIpv4 = (value) => {
    const parts = String(value).trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
};

const isValidHostname = (value) => {
    const host = String(value).trim().replace(/\.$/, '');
    if (!host || host.length > 253) return false;
    const labels = host.split('.');
    if (labels.length < 2) return false;
    return labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
};

const SUBDOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?$/;
const RESERVED_SUBDOMAINS = new Set(['www', 'api', 'admin', 'mail', 'ns1', 'ns2']);

// Daftar subdomain milik satu IP, digabung dari data baru (records) dan data lama (subdomains)
const listSubdomains = (user) => {
    if (!user) return [];
    const items = [];
    const seen = new Set();

    const push = (name, type, target, createdAt) => {
        const key = normalizeName(name);
        if (!key || seen.has(key)) return;
        seen.add(key);
        items.push({
            name: String(name),
            type: type || 'A',
            target: target || '',
            createdAt: createdAt || null
        });
    };

    (user.records || []).forEach((record) => push(record.name, record.type, record.target, record.createdAt));
    (user.subdomains || []).forEach((name) => push(name, 'A', '', null));

    return items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
};

const verifyTurnstile = async (token, ip) => {
    if (!process.env.TURNSTILE_SECRET_KEY) {
        throw new Error('TURNSTILE_SECRET_KEY belum diatur di server');
    }
    const form = new URLSearchParams();
    form.append('secret', process.env.TURNSTILE_SECRET_KEY);
    form.append('response', token);
    if (ip && ip !== 'unknown') form.append('remoteip', ip);

    const { data } = await axios.post(TURNSTILE_VERIFY_URL, form.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000
    });
    return data;
};

const createDnsRecord = async ({ type, name, content }) => {
    const zoneId = process.env.CF_ZONE_PUBLICFREE;
    const token = process.env.CF_API_TOKEN;
    if (!zoneId || !token) {
        throw new Error('Konfigurasi Cloudflare (CF_API_TOKEN / CF_ZONE_PUBLICFREE) belum lengkap di server');
    }

    const { data } = await axios.post(
        `${CF_API_BASE}/zones/${zoneId}/dns_records`,
        { type, name, content, ttl: 1, proxied: false },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            timeout: 15000
        }
    );

    // Cloudflare kadang membalas HTTP 200 dengan success: false
    if (!data || data.success !== true) {
        const first = data?.errors?.[0];
        const error = new Error(first?.message || 'Cloudflare menolak permintaan pembuatan record');
        error.cfErrors = data?.errors;
        throw error;
    }
    return data.result;
};

const describeCloudflareError = (error) => {
    const errors = error.response?.data?.errors || error.cfErrors;
    if (Array.isArray(errors) && errors.length > 0) {
        const first = errors[0];
        let hint = '';
        if ([9109, 9106, 10000, 1000, 6003].includes(first.code)) {
            hint = ' Token API Cloudflare tidak valid atau tidak punya izin "Zone.DNS: Edit".';
        } else if ([81057, 81058].includes(first.code)) {
            hint = ' Record dengan nama tersebut sudah ada di Cloudflare.';
        }
        return `Cloudflare (${first.code}): ${first.message}.${hint}`;
    }
    if (error.code === 'ECONNABORTED') {
        return 'Cloudflare tidak merespons (timeout). Coba lagi beberapa saat.';
    }
    return null;
};

// Pesan error yang aman ditampilkan ke user (tanpa membocorkan detail internal)
const publicErrorMessage = (error) => {
    const cfMessage = describeCloudflareError(error);
    if (cfMessage) return cfMessage;
    if (error.message && error.message.startsWith('Konfigurasi Cloudflare')) return error.message;
    return 'Terjadi gangguan pada server backend. Coba lagi beberapa saat.';
};

const reserveQuota = async (ip) => {
    await connectDB();

    // Tambah kuota hanya jika masih di bawah limit (atomik, aman untuk request bersamaan)
    let user = await User.findOneAndUpdate(
        { ipAddress: ip, usedQuota: { $lt: MAX_SUBDOMAINS } },
        { $inc: { usedQuota: 1 } },
        { new: true }
    );
    if (user) return user;

    // Belum ada dokumen untuk IP ini -> buat baru dengan kuota 1
    try {
        return await User.create({ ipAddress: ip, usedQuota: 1, subdomains: [], records: [] });
    } catch (error) {
        if (error?.code === 11000) {
            // Ada request lain yang lebih dulu membuat dokumen, ulangi increment
            user = await User.findOneAndUpdate(
                { ipAddress: ip, usedQuota: { $lt: MAX_SUBDOMAINS } },
                { $inc: { usedQuota: 1 } },
                { new: true }
            );
            return user || null;
        }
        throw error;
    }
};

const rollbackQuota = async (ip) => {
    try {
        await User.updateOne({ ipAddress: ip, usedQuota: { $gt: 0 } }, { $inc: { usedQuota: -1 } });
    } catch (error) {
        console.error('Gagal mengembalikan kuota:', error.message);
    }
};

const persistRecord = async (ip, record) => {
    await User.updateOne(
        { ipAddress: ip },
        {
            $push: {
                records: record,
                subdomains: record.name
            }
        }
    );
};

const loadOwnedData = async (ip) => {
    await connectDB();
    const user = await User.findOne({ ipAddress: ip }).lean();
    const used = Math.max(0, Number(user?.usedQuota) || 0);
    return {
        used,
        limit: MAX_SUBDOMAINS,
        remaining: Math.max(0, MAX_SUBDOMAINS - used),
        subdomains: listSubdomains(user)
    };
};

const noStore = (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
};
// ====================================================

// 1. Endpoint Tampilan Web Utama (lokal; di Vercel index.html disajikan sebagai static)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', noStore);

// 2. Endpoint Cek Status Kuota (untuk progress bar frontend)
app.get('/api/status', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const data = await loadOwnedData(ip);
        return res.json({ success: true, ...data });
    } catch (error) {
        console.error('Error API Status:', error.message);
        return res.status(503).json({
            success: false,
            used: 0,
            limit: MAX_SUBDOMAINS,
            message: 'Database sedang tidak bisa diakses. Coba muat ulang beberapa saat lagi.'
        });
    }
});

// 3. Endpoint Daftar Subdomain Milik IP Ini ("List Domain Saya")
app.get('/api/subdomains', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const data = await loadOwnedData(ip);
        return res.json({ success: true, ...data });
    } catch (error) {
        console.error('Error API Subdomains:', error.message);
        return res.status(503).json({
            success: false,
            limit: MAX_SUBDOMAINS,
            subdomains: [],
            message: 'Database sedang tidak bisa diakses. Coba lagi beberapa saat.'
        });
    }
});

// 4. Endpoint Eksekusi Subdomain
app.post('/api/create', async (req, res) => {
    const ip = getClientIp(req);
    const body = req.body || {};

    const subdomain = normalizeName(body.subdomain);
    const requestedDomain = normalizeName(body.domain || PUBLIC_DOMAIN);
    const recordType = String(body.recordType || '').trim().toUpperCase();
    const target = String(body.target || '').trim();
    const cfToken = typeof body.cfToken === 'string' ? body.cfToken : '';

    // --- Validasi input ---
    if (!subdomain || !recordType || !target || !cfToken) {
        return res.status(400).json({ success: false, message: 'Semua data wajib diisi, termasuk verifikasi captcha.' });
    }
    if (requestedDomain !== PUBLIC_DOMAIN) {
        return res.status(400).json({ success: false, message: `Hanya subdomain ${PUBLIC_DOMAIN} yang didukung.` });
    }
    if (subdomain.length > 30 || !SUBDOMAIN_REGEX.test(subdomain)) {
        return res.status(400).json({
            success: false,
            message: 'Nama subdomain tidak valid. Gunakan huruf, angka, atau strip (-), maksimal 30 karakter, dan tidak diawali/diakhiri strip.'
        });
    }
    if (RESERVED_SUBDOMAINS.has(subdomain)) {
        return res.status(400).json({ success: false, message: `Nama "${subdomain}" tidak bisa dipakai, silakan pilih nama lain.` });
    }
    if (recordType !== 'A' && recordType !== 'CNAME') {
        return res.status(400).json({ success: false, message: 'Tipe record harus A atau CNAME.' });
    }
    if (recordType === 'A' && !isValidIpv4(target)) {
        return res.status(400).json({ success: false, message: 'Target untuk A Record harus berupa alamat IPv4 yang valid, contoh: 103.123.45.67' });
    }
    if (recordType === 'CNAME' && !isValidHostname(target)) {
        return res.status(400).json({ success: false, message: 'Target untuk CNAME harus berupa domain yang valid, contoh: cname.vercel-dns.com' });
    }

    const fqdn = `${subdomain}.${PUBLIC_DOMAIN}`;

    // --- Verifikasi Turnstile (sebelum menyentuh kuota / Cloudflare) ---
    let captcha;
    try {
        captcha = await verifyTurnstile(cfToken, ip);
    } catch (error) {
        console.error('Error verifikasi Turnstile:', error.message);
        return res.status(502).json({ success: false, message: 'Tidak bisa memverifikasi captcha ke Cloudflare. Coba lagi.' });
    }
    if (!captcha?.success) {
        return res.status(403).json({
            success: false,
            message: 'Verifikasi captcha gagal atau kedaluwarsa. Selesaikan captcha lalu coba lagi.'
        });
    }

    // --- Cek & pesan kuota ---
    let reserved;
    try {
        const before = await User.findOne({ ipAddress: ip }).lean();
        if (listSubdomains(before).some((item) => normalizeName(item.name) === fqdn)) {
            return res.status(409).json({ success: false, message: `${fqdn} sudah pernah kamu buat dari IP ini.` });
        }
        reserved = await reserveQuota(ip);
    } catch (error) {
        console.error('Error database saat cek kuota:', error.message);
        return res.status(503).json({ success: false, message: 'Database sedang tidak bisa diakses. Coba lagi beberapa saat.' });
    }
    if (!reserved) {
        return res.status(403).json({
            success: false,
            message: `Limit Tercapai: 1 IP Address hanya mendapat ${MAX_SUBDOMAINS}x kuota subdomain.`
        });
    }

    // --- Buat DNS record di Cloudflare ---
    let created;
    try {
        created = await createDnsRecord({ type: recordType, name: fqdn, content: target });
    } catch (error) {
        await rollbackQuota(ip);
        const message = describeCloudflareError(error) || publicErrorMessage(error);
        console.error('Error API Create (Cloudflare):', error.message);
        console.error('Detail:', JSON.stringify(error.response?.data || error.cfErrors || {}).slice(0, 500));
        return res.status(400).json({ success: false, message });
    }

    // DNS sudah terbuat. Kalau pencatatan daftar gagal, jangan kembalikan kuota
    // (record DNS-nya tetap ada), cukup catat di log.
    const record = {
        name: fqdn,
        type: recordType,
        target,
        createdAt: new Date()
    };
    try {
        await persistRecord(ip, record);
    } catch (error) {
        console.error('DNS dibuat tapi gagal menyimpan daftar subdomain:', error.message);
    }

    return res.json({
        success: true,
        message: `${fqdn} berhasil dibuat dan sudah terdaftar di Cloudflare!`,
        subdomain: record,
        used: reserved.usedQuota,
        limit: MAX_SUBDOMAINS,
        remaining: Math.max(0, MAX_SUBDOMAINS - reserved.usedQuota),
        cloudflareId: created?.id || null
    });
});

// 5. Endpoint Diagnostik (tidak menampilkan nilai rahasia, hanya status konfigurasi)
app.get('/api/health', async (req, res) => {
    const config = {
        mongodb: Boolean(process.env.MONGODB_URI),
        cloudflareToken: Boolean(process.env.CF_API_TOKEN),
        cloudflareZone: Boolean(process.env.CF_ZONE_PUBLICFREE),
        turnstileSecret: Boolean(process.env.TURNSTILE_SECRET_KEY)
    };

    let database = 'disconnected';
    try {
        await connectDB();
        database = mongoose.connection.readyState === 1 ? 'connected' : 'connecting';
    } catch (error) {
        database = 'error';
    }

    let cloudflare = 'not_configured';
    if (config.cloudflareToken && config.cloudflareZone) {
        try {
            const { data } = await axios.get(`${CF_API_BASE}/zones/${process.env.CF_ZONE_PUBLICFREE}`, {
                headers: { Authorization: `Bearer ${process.env.CF_API_TOKEN}` },
                timeout: 8000
            });
            cloudflare = data?.success ? 'ok' : 'rejected';
        } catch (error) {
            cloudflare = error.response?.status === 403 || error.response?.status === 401 ? 'invalid_token' : 'unreachable';
            console.error('Health check Cloudflare:', error.response?.status || error.message);
        }
    }

    return res.json({
        success: true,
        domain: PUBLIC_DOMAIN,
        quotaPerIp: MAX_SUBDOMAINS,
        config,
        database,
        cloudflare
    });
});

// Endpoint /api yang tidak dikenal tetap dibalas JSON (bukan HTML redirect)
app.use('/api', (req, res) => {
    res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan.' });
});

// Handler error terakhir: body JSON rusak / error tak terduga
app.use((err, req, res, next) => {
    if (err?.type === 'entity.parse.failed') {
        return res.status(400).json({ success: false, message: 'Format request tidak valid.' });
    }
    console.error('Unhandled error:', err?.message || err);
    if (req.path.startsWith('/api')) {
        return res.status(500).json({ success: false, message: 'Terjadi gangguan pada server backend.' });
    }
    next(err);
});

// ================= PENGATURAN SERVER =================
// app.listen hanya untuk lokal. Di Vercel, function diekspor dan dipanggil platform.
if (!process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 API Landing Page aktif di http://localhost:${PORT}`));
}

module.exports = app;
