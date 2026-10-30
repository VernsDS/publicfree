require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const dns = require('dns');
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
// Vercel Functions tidak punya jalur IPv6 keluar. Kalau driver memilih alamat
// IPv6, koneksi hanya akan menggantung sampai serverSelectionTimeout habis.
// Paksa IPv4 supaya koneksi tidak pernah menunggu jalur yang tidak ada.
try {
    dns.setDefaultResultOrder('ipv4first');
} catch (error) {
    console.warn('dns.setDefaultResultOrder tidak didukung:', error.message);
}

// Opsi koneksi yang aman untuk serverless (Vercel)
const MONGO_OPTIONS = {
    serverSelectionTimeoutMS: 6000,
    connectTimeoutMS: 6000,
    socketTimeoutMS: 30000,
    maxIdleTimeMS: 60000,
    maxPoolSize: 5,
    minPoolSize: 0,
    family: 4,
    bufferCommands: false,
    retryWrites: true,
    retryReads: true
};

// Koneksi di-cache per instance lambda, tapi cache-nya dibuang setiap kali
// koneksi terputus supaya request berikutnya benar-benar menyambung ulang.
let connectPromise = null;

function waitForConnection(timeoutMs = 6000) {
    return new Promise((resolve, reject) => {
        const conn = mongoose.connection;
        if (conn.readyState === 1) return resolve();

        const timer = setTimeout(() => {
            cleanup();
            reject(new Error('Timeout menunggu koneksi MongoDB'));
        }, timeoutMs);

        const onConnected = () => { cleanup(); resolve(); };
        const onError = (err) => { cleanup(); reject(err); };

        function cleanup() {
            clearTimeout(timer);
            conn.removeListener('connected', onConnected);
            conn.removeListener('error', onError);
        }

        conn.once('connected', onConnected);
        conn.once('error', onError);
    });
}

function connectDB() {
    if (mongoose.connection.readyState === 1) return Promise.resolve();

    if (!MONGODB_URI) {
        const error = new Error('MONGODB_URI belum diatur di server');
        error.code = 'MONGODB_URI_MISSING';
        return Promise.reject(error);
    }

    // Sedang connecting: pakai promise yang sama supaya tidak buka koneksi ganda
    if (mongoose.connection.readyState === 2) {
        return connectPromise || waitForConnection();
    }

    if (!connectPromise) {
        connectPromise = mongoose
            .connect(MONGODB_URI, MONGO_OPTIONS)
            .then(() => {
                console.log('✅ Terhubung ke Database MongoDB!');
            })
            .catch((err) => {
                console.error('❌ KONEKSI MONGODB GAGAL:', err.name, '-', err.message);
                throw err;
            })
            .finally(() => {
                connectPromise = null;
            });
    }
    return connectPromise;
}

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err.message);
});

// Kalau socket mati (Atlas menutup koneksi idle, function di-freeze, dsb.),
// buang cache koneksi agar request berikutnya menyambung ulang.
['disconnected', 'close'].forEach((event) => {
    mongoose.connection.on(event, () => {
        connectPromise = null;
        if (event === 'disconnected') {
            console.warn('⚠️ Koneksi MongoDB terputus. Akan menyambung ulang saat ada request.');
        }
    });
});

// Klasifikasi error database (aman ditampilkan, tanpa detail rahasia)
const classifyDbError = (error) => {
    if (!error) return 'UNKNOWN';
    if (error.code === 'MONGODB_URI_MISSING') return 'MONGODB_URI_MISSING';

    const name = String(error.name || '');
    const message = String(error.message || '');
    const combined = name + ' ' + message;

    if (name === 'MongoParseError' || /URI malformed|Invalid scheme/i.test(message)) return 'INVALID_URI';
    if (/ENOTFOUND|EAI_AGAIN|querySrv|queryTxt/i.test(message)) return 'DNS_ERROR';
    if (/Authentication failed|bad auth|SCRAM/i.test(message)) return 'AUTH_FAILED';
    if (name === 'MongoServerError' && [13, 18, 8000].includes(error.code)) return 'AUTH_FAILED';
    if (/MongoNotConnectedError|Client must be connected|buffering timed out|topology is closed|connection .* closed/i.test(combined)) return 'CONNECTION_LOST';
    if (name === 'MongoServerSelectionError' || name === 'MongoNetworkError' || /ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|timed out/i.test(message)) return 'NETWORK_UNREACHABLE';
    return 'UNKNOWN';
};

const DB_ERROR_HINTS = {
    MONGODB_URI_MISSING: 'Env var MONGODB_URI belum diisi di Vercel (Settings > Environment Variables).',
    INVALID_URI: 'Format connection string salah. Salin ulang tanpa tanda kutip atau spasi tambahan.',
    AUTH_FAILED: 'Username/password database salah, atau user belum punya akses ke database ini.',
    DNS_ERROR: 'DNS gagal me-resolve host MongoDB Atlas dari server Vercel.',
    NETWORK_UNREACHABLE: 'Vercel tidak bisa menjangkau cluster. Buka Atlas > Network Access, izinkan 0.0.0.0/0, dan pastikan cluster tidak paused.',
    CONNECTION_LOST: 'Koneksi ke database terputus. Coba muat ulang; server akan menyambung ulang otomatis.',
    UNKNOWN: 'Cek Runtime Logs di dashboard Vercel untuk detail error-nya.'
};

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
    await connectDB();
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

// Baca data dengan satu kali percobaan ulang kalau koneksi ternyata sudah mati.
// Hanya dipakai untuk operasi baca supaya tidak ada risiko data dobel.
const TRANSIENT_DB_ERROR = /MongoNotConnectedError|Client must be connected|buffering timed out|topology is closed|connection .* closed/i;

const withDB = async (operation) => {
    try {
        await connectDB();
        return await operation();
    } catch (error) {
        if (!TRANSIENT_DB_ERROR.test(String(error?.name || '') + ' ' + String(error?.message || ''))) {
            throw error;
        }
        connectPromise = null;
        await connectDB();
        return operation();
    }
};

const loadOwnedData = async (ip) => {
    const user = await withDB(() => User.findOne({ ipAddress: ip }).lean());
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
        await connectDB();
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
    let databaseError = null;
    let databaseHint = null;
    try {
        await connectDB();
        database = mongoose.connection.readyState === 1 ? 'connected' : 'connecting';
    } catch (error) {
        database = 'error';
        databaseError = classifyDbError(error);
        databaseHint = DB_ERROR_HINTS[databaseError];
        console.error('Health check database:', error.name, '-', error.message);
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
        databaseError,
        databaseHint,
        cloudflare,
        region: process.env.VERCEL_REGION || null,
        node: process.version
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
