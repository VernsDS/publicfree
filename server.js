require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
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

// ================= VERIFIKASI MANUSIA (MATEMATIKA) =================
// Soal dibuat di server lalu ditandatangani HMAC, jadi jawaban tidak dikirim
// ke browser dan token tidak bisa dipalsukan.
const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || process.env.TURNSTILE_SECRET_KEY || process.env.CF_API_TOKEN || 'publicfree-captcha-dev';
const CAPTCHA_TTL_MS = 5 * 60 * 1000;

const randomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const signChallenge = (nonce, exp, answer) =>
    crypto.createHmac('sha256', CAPTCHA_SECRET).update(nonce + '.' + exp + '.' + answer).digest('hex').slice(0, 32);

const createChallenge = () => {
    const nonce = crypto.randomBytes(8).toString('hex');
    const exp = Date.now() + CAPTCHA_TTL_MS;
    let question;
    let answer;

    if (Math.random() < 0.5) {
        // Perkalian: faktor 2-9 dan 2-11, hasil maksimal 99
        const a = randomInt(2, 9);
        const b = randomInt(2, 11);
        answer = a * b;
        question = a + ' × ' + b;
    } else {
        // Penjumlahan: hasil maksimal 99
        const a = randomInt(10, 79);
        const b = randomInt(2, 99 - a);
        answer = a + b;
        question = a + ' + ' + b;
    }

    return { question, token: nonce + '.' + exp + '.' + signChallenge(nonce, exp, answer) };
};

const verifyChallenge = (token, answerRaw) => {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return { ok: false, reason: 'format' };

    const nonce = parts[0];
    const exp = Number(parts[1]);
    const signature = parts[2];

    if (!nonce || !Number.isFinite(exp) || !signature) return { ok: false, reason: 'format' };
    if (Date.now() > exp) return { ok: false, reason: 'expired' };

    const answer = String(answerRaw === undefined || answerRaw === null ? '' : answerRaw).trim();
    if (!/^\d{1,3}$/.test(answer)) return { ok: false, reason: 'answer' };

    const expected = signChallenge(nonce, exp, Number(answer));
    const given = Buffer.from(signature);
    const target = Buffer.from(expected);
    if (given.length !== target.length) return { ok: false, reason: 'answer' };

    return crypto.timingSafeEqual(given, target) ? { ok: true } : { ok: false, reason: 'answer' };
};

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

    if (name === 'MongoParseError' || /URI malformed|Invalid scheme|MONGODB_URI/i.test(message)) return 'INVALID_URI';
    if (/ENOTFOUND|EAI_AGAIN|querySrv|queryTxt|getaddrinfo/i.test(message)) return 'DNS_ERROR';
    if (/Authentication failed|bad auth|SCRAM/i.test(message)) return 'AUTH_FAILED';
    if (/MongoServerError/.test(name) && [13, 18, 8000].includes(error.code)) return 'AUTH_FAILED';
    if (/MongoNotConnectedError|Client must be connected|buffering timed out|topology is closed|connection .* closed/i.test(combined)) return 'CONNECTION_LOST';
    // Mongoose membungkus error driver jadi "MongooseServerSelectionError"
    if (/Mongo(ose)?(ServerSelection|Network|Timeout)Error/i.test(name) ||
        /server selection|Could not connect to any servers|IP whitelist|connect (ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH)|timed out/i.test(message)) {
        return 'NETWORK_UNREACHABLE';
    }
    return 'UNKNOWN';
};

// Buang detail sensitif (URI, host, IP) sebelum ditampilkan di /api/health
const sanitizeDbMessage = (message) => String(message || '')
    .replace(/mongodb(\+srv)?:\/\/[^\s"']+/gi, 'mongodb://<disembunyikan>')
    .replace(/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.mongodb\.net(?::\d+)?/gi, '<host>.mongodb.net')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, '<ip>')
    .slice(0, 400);

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
        cloudflareId: { type: String, default: null },
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

// Statistik harian (dihitung per hari WIB). Dipisah dari data user supaya
// angka "bulan ini" dan "total" tetap ada walau subdomain dihapus.
const DailyStatSchema = new mongoose.Schema({
    date: { type: String, required: true, unique: true },
    count: { type: Number, default: 0 }
});
const DailyStat = mongoose.models.DailyStat || mongoose.model('DailyStat', DailyStatSchema);

const MetaSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    at: { type: Date, default: Date.now }
});
const Meta = mongoose.models.Meta || mongoose.model('Meta', MetaSchema);
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

    const push = (name, type, target, createdAt, cloudflareId) => {
        const key = normalizeName(name);
        if (!key || seen.has(key)) return;
        seen.add(key);
        items.push({
            name: String(name),
            type: type || 'A',
            target: target || '',
            cloudflareId: cloudflareId || null,
            createdAt: createdAt || null
        });
    };

    (user.records || []).forEach((record) => push(record.name, record.type, record.target, record.createdAt, record.cloudflareId));
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

const deleteDnsRecord = async ({ id, name, type }) => {
    const zoneId = process.env.CF_ZONE_PUBLICFREE;
    const token = process.env.CF_API_TOKEN;
    if (!zoneId || !token) {
        throw new Error('Konfigurasi Cloudflare (CF_API_TOKEN / CF_ZONE_PUBLICFREE) belum lengkap di server');
    }

    let recordId = id || null;

    // Record lama belum menyimpan id Cloudflare, jadi dicari dulu berdasarkan nama
    if (!recordId) {
        const { data } = await axios.get(`${CF_API_BASE}/zones/${zoneId}/dns_records`, {
            headers: { Authorization: `Bearer ${token}` },
            params: { name, per_page: 1 },
            timeout: 15000
        });
        if (!data || data.success !== true) {
            const first = data?.errors?.[0];
            const error = new Error(first?.message || 'Gagal mencari record di Cloudflare');
            error.cfErrors = data?.errors;
            throw error;
        }
        recordId = data.result?.[0]?.id || null;
        if (!recordId) return { deleted: false, missing: true };
    }

    try {
        await axios.delete(`${CF_API_BASE}/zones/${zoneId}/dns_records/${recordId}`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 15000
        });
        return { deleted: true };
    } catch (error) {
        const code = error.response?.data?.errors?.[0]?.code;
        if (error.response?.status === 404 || code === 81044 || code === 81057) {
            return { deleted: false, missing: true };
        }
        throw error;
    }
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

// ================= STATISTIK =================
const WIB_OFFSET_MS = 7 * 60 * 60 * 1000;

// Tanggal (YYYY-MM-DD) menurut zona waktu WIB
const wibDayKey = (date) => new Date((date ? date.getTime() : Date.now()) + WIB_OFFSET_MS).toISOString().slice(0, 10);

// Isi statistik lama dari data subdomain yang sudah ada (sekali saja)
const ensureStatsBackfill = async () => {
    const claimed = await Meta.findOneAndUpdate(
        { key: 'stats-backfill-v1' },
        { $setOnInsert: { at: new Date() } },
        { upsert: true, new: false }
    ).lean();

    if (claimed) return; // sudah pernah diisi oleh request lain

    const rows = await User.aggregate([
        { $unwind: '$records' },
        { $match: { 'records.createdAt': { $type: 'date' } } },
        {
            $group: {
                _id: { $dateToString: { format: '%Y-%m-%d', date: '$records.createdAt', timezone: 'Asia/Jakarta' } },
                count: { $sum: 1 }
            }
        }
    ]);

    for (const row of rows) {
        if (!row._id) continue;
        await DailyStat.updateOne({ date: row._id }, { $inc: { count: row.count } }, { upsert: true });
    }

    console.log('✅ Backfill statistik harian:', rows.length, 'hari');
};

let statsBackfillDone = false;
let statsCache = { at: 0, value: { today: 0, month: 0, total: 0 } };

const getStats = async () => {
    if (Date.now() - statsCache.at < 4000) return statsCache.value;

    if (!statsBackfillDone) {
        try {
            await ensureStatsBackfill();
            statsBackfillDone = true;
        } catch (error) {
            console.error('Backfill statistik gagal:', error.message);
        }
    }

    const todayKey = wibDayKey();
    const monthPrefix = todayKey.slice(0, 7);

    const rows = await DailyStat.aggregate([
        {
            $group: {
                _id: null,
                today: { $sum: { $cond: [{ $eq: ['$date', todayKey] }, '$count', 0] } },
                month: { $sum: { $cond: [{ $regexMatch: { input: '$date', regex: '^' + monthPrefix } }, '$count', 0] } },
                total: { $sum: '$count' }
            }
        }
    ]);

    const row = rows[0] || { today: 0, month: 0, total: 0 };
    const value = { today: row.today || 0, month: row.month || 0, total: row.total || 0 };
    statsCache = { at: Date.now(), value };
    return value;
};

const recordCreateStat = async () => {
    try {
        await DailyStat.updateOne({ date: wibDayKey() }, { $inc: { count: 1 } }, { upsert: true });
        statsCache.at = 0; // paksa hitung ulang
    } catch (error) {
        console.error('Gagal mencatat statistik harian:', error.message);
    }
};

// ================= SINKRONISASI CLOUDFLARE =================
// Subdomain yang dihapus langsung dari dashboard Cloudflare ikut dihapus dari
// database, sehingga kuota ikut turun (misal 1/2 menjadi 0/2).
const SYNC_TTL_MS = 30 * 1000;
const lastSyncAt = new Map();

const findDnsRecord = async (name) => {
    const zoneId = process.env.CF_ZONE_PUBLICFREE;
    const token = process.env.CF_API_TOKEN;
    if (!zoneId || !token) return null;

    const { data } = await axios.get(`${CF_API_BASE}/zones/${zoneId}/dns_records`, {
        headers: { Authorization: `Bearer ${token}` },
        params: { name, per_page: 1 },
        timeout: 15000
    });

    if (!data || data.success !== true) {
        throw new Error('Cloudflare menolak permintaan daftar DNS');
    }

    return data.result?.[0] || null;
};

const syncUserRecords = async (ip, options) => {
    const force = Boolean(options && options.force);
    const last = lastSyncAt.get(ip) || 0;
    if (!force && Date.now() - last < SYNC_TTL_MS) return { removed: 0, skipped: true };
    lastSyncAt.set(ip, Date.now());

    if (!process.env.CF_ZONE_PUBLICFREE || !process.env.CF_API_TOKEN) return { removed: 0, skipped: true };

    const user = await withDB(() => User.findOne({ ipAddress: ip }).lean());
    if (!user) return { removed: 0 };

    const entries = listSubdomains(user);
    if (!entries.length) return { removed: 0 };

    // Kalau ada satu saja request ke Cloudflare yang gagal, jangan hapus apa pun
    // (biar tidak salah menganggap record hilang).
    const checked = await Promise.all(
        entries.slice(0, 10).map(async (entry) => ({ entry, cf: await findDnsRecord(entry.name) }))
    );

    const records = [];
    let removed = 0;
    let changed = false;

    for (const item of checked) {
        const entry = item.entry;
        const cf = item.cf;

        if (!cf) {
            removed += 1;
            changed = true;
            continue;
        }

        const next = {
            name: entry.name,
            type: cf.type || entry.type,
            target: cf.content || entry.target,
            cloudflareId: cf.id || entry.cloudflareId || null,
            createdAt: entry.createdAt || (cf.created_on ? new Date(cf.created_on) : new Date())
        };

        if (
            entry.type !== next.type ||
            entry.target !== next.target ||
            entry.cloudflareId !== next.cloudflareId ||
            !entry.createdAt
        ) {
            changed = true;
        }

        records.push(next);
    }

    if (changed) {
        await User.updateOne(
            { ipAddress: ip },
            {
                $set: {
                    records,
                    subdomains: records.map((record) => record.name),
                    usedQuota: records.length
                }
            }
        );
        console.log(`Sinkronisasi ${ip}: ${removed} subdomain hilang, ${records.length} tersisa.`);
    }

    return { removed, skipped: false };
};

const loadOwnedData = async (ip) => {
    const user = await withDB(() => User.findOne({ ipAddress: ip }).lean());
    const used = Math.max(0, Number(user?.usedQuota) || 0);

    let stats = { today: 0, month: 0, total: 0 };
    try {
        stats = await getStats();
    } catch (error) {
        console.error('Gagal menghitung statistik:', error.message);
    }

    return {
        used,
        limit: MAX_SUBDOMAINS,
        remaining: Math.max(0, MAX_SUBDOMAINS - used),
        subdomains: listSubdomains(user),
        today: stats.today,
        month: stats.month,
        total: stats.total
    };
};

const noStore = (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
};

// Rate limit sederhana per IP (in-memory) untuk menahan bot / scraper.
// Cukup untuk satu instance; di serverless batasnya berlaku per instance.
const rateBuckets = new Map();

const rateLimit = (name, windowMs, max) => (req, res, next) => {
    const ip = getClientIp(req);
    const bucketKey = name + ':' + ip;
    const now = Date.now();

    if (rateBuckets.size > 5000) rateBuckets.clear();

    let bucket = rateBuckets.get(bucketKey);
    if (!bucket || now - bucket.start > windowMs) {
        bucket = { start: now, count: 0 };
        rateBuckets.set(bucketKey, bucket);
    }

    bucket.count += 1;

    if (bucket.count > max) {
        const retry = Math.max(1, Math.ceil((bucket.start + windowMs - now) / 1000));
        res.set('Retry-After', String(retry));
        return res.status(429).json({ success: false, message: `Terlalu banyak permintaan. Coba lagi dalam ${retry} detik.` });
    }

    return next();
};
// ====================================================

// 1. Endpoint Tampilan Web Utama (lokal; di Vercel index.html disajikan sebagai static)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/api', noStore);

// 2. Endpoint Soal Verifikasi Manusia (penjumlahan / perkalian)
app.get('/api/captcha', rateLimit('captcha', 10 * 60 * 1000, 40), (req, res) => {
    const challenge = createChallenge();
    return res.json({ success: true, question: challenge.question, token: challenge.token });
});

// 3. Endpoint Statistik (jumlah subdomain yang dibuat hari ini)
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await withDB(() => getStats());
        return res.json({ success: true, ...stats });
    } catch (error) {
        console.error('Error API Stats:', error.message);
        return res.status(503).json({ success: false, today: 0, month: 0, total: 0, message: 'Statistik belum bisa dimuat.' });
    }
});

// Sinkronisasi manual: cocokkan database dengan record yang benar-benar ada di Cloudflare
app.post('/api/sync', rateLimit('sync', 5 * 60 * 1000, 20), async (req, res) => {
    const ip = getClientIp(req);
    try {
        const result = await syncUserRecords(ip, { force: true });
        const data = await loadOwnedData(ip);
        return res.json({
            success: true,
            removed: result.removed || 0,
            message: result.removed
                ? `${result.removed} subdomain yang sudah tidak ada di Cloudflare dihapus dari daftar.`
                : 'Semua subdomain sudah sinkron dengan Cloudflare.',
            ...data
        });
    } catch (error) {
        console.error('Error API Sync:', error.message);
        return res.status(502).json({ success: false, message: 'Gagal sinkronisasi dengan Cloudflare. Coba lagi beberapa saat.' });
    }
});

// 4. Endpoint Cek Status Kuota (untuk progress bar frontend)
app.get('/api/status', async (req, res) => {
    const ip = getClientIp(req);
    try {
        await syncUserRecords(ip).catch((error) => console.error('Sync otomatis gagal:', error.message));
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

// 5. Endpoint Daftar Subdomain Milik IP Ini ("List Domain Saya")
app.get('/api/subdomains', async (req, res) => {
    const ip = getClientIp(req);
    try {
        await syncUserRecords(ip).catch((error) => console.error('Sync otomatis gagal:', error.message));
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

// 6. Endpoint Hapus Subdomain (Cloudflare DNS + database)
app.delete('/api/subdomains/:name', rateLimit('delete', 10 * 60 * 1000, 20), async (req, res) => {
    const ip = getClientIp(req);
    const requested = normalizeName(decodeURIComponent(req.params.name || ''));

    if (!requested) {
        return res.status(400).json({ success: false, message: 'Nama subdomain tidak valid.' });
    }

    const fqdn = requested.includes('.') ? requested : `${requested}.${PUBLIC_DOMAIN}`;

    let user;
    try {
        await connectDB();
        user = await User.findOne({ ipAddress: ip }).lean();
    } catch (error) {
        console.error('Error database saat hapus:', error.message);
        return res.status(503).json({ success: false, message: 'Database sedang tidak bisa diakses. Coba lagi beberapa saat.' });
    }

    if (!user) {
        return res.status(404).json({ success: false, message: 'Belum ada subdomain yang tercatat untuk IP ini.' });
    }

    const owned = listSubdomains(user).find((item) => normalizeName(item.name) === fqdn);
    if (!owned) {
        return res.status(404).json({ success: false, message: `${fqdn} bukan milik IP Address ini.` });
    }

    try {
        const result = await deleteDnsRecord({
            id: owned.cloudflareId || null,
            name: fqdn,
            type: owned.type
        });

        const nextQuota = Math.max(0, (Number(user.usedQuota) || 0) - 1);
        await User.updateOne(
            { ipAddress: ip },
            {
                $set: { usedQuota: nextQuota },
                $pull: { records: { name: fqdn }, subdomains: fqdn }
            }
        );

        return res.json({
            success: true,
            message: result.missing
                ? `${fqdn} dihapus dari daftar (record DNS sudah tidak ada di Cloudflare).`
                : `${fqdn} berhasil dihapus dari Cloudflare.`,
            removed: fqdn,
            used: nextQuota,
            limit: MAX_SUBDOMAINS,
            remaining: Math.max(0, MAX_SUBDOMAINS - nextQuota)
        });
    } catch (error) {
        const message = describeCloudflareError(error) || publicErrorMessage(error);
        console.error('Error API Delete:', error.message);
        return res.status(502).json({ success: false, message });
    }
});

// 7. Endpoint Eksekusi Subdomain
app.post('/api/create', rateLimit('create', 10 * 60 * 1000, 8), async (req, res) => {
    const ip = getClientIp(req);
    const body = req.body || {};

    const subdomain = normalizeName(body.subdomain);
    const requestedDomain = normalizeName(body.domain || PUBLIC_DOMAIN);
    const recordType = String(body.recordType || '').trim().toUpperCase();
    const target = String(body.target || '').trim();
    const captchaToken = typeof body.captchaToken === 'string' ? body.captchaToken : '';
    const captchaAnswer = body.captchaAnswer;
    const cfToken = typeof body.cfToken === 'string' ? body.cfToken : '';

    // --- Validasi input ---
    if (!subdomain || !recordType || !target) {
        return res.status(400).json({ success: false, message: 'Semua data wajib diisi.' });
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

    // --- Verifikasi manusia (matematika, wajib) ---
    if (!captchaToken) {
        return res.status(400).json({ success: false, message: 'Soal verifikasi belum dimuat. Muat ulang halaman lalu coba lagi.' });
    }

    const human = verifyChallenge(captchaToken, captchaAnswer);
    if (!human.ok) {
        return res.status(403).json({
            success: false,
            message: human.reason === 'expired'
                ? 'Soal verifikasi sudah kedaluwarsa. Klik "Ganti soal" lalu jawab lagi.'
                : 'Jawaban verifikasi salah. Silakan jawab soal yang baru.'
        });
    }

    // --- Turnstile Cloudflare (wajib kalau secret dikonfigurasi) ---
    if (process.env.TURNSTILE_SECRET_KEY) {
        if (!cfToken) {
            return res.status(400).json({ success: false, message: 'Verifikasi Cloudflare wajib diselesaikan. Muat ulang halaman lalu coba lagi.' });
        }

        let turnstile;
        try {
            turnstile = await verifyTurnstile(cfToken, ip);
        } catch (error) {
            console.error('Error verifikasi Turnstile:', error.message);
            return res.status(502).json({ success: false, message: 'Tidak bisa memverifikasi captcha ke Cloudflare. Coba lagi.' });
        }

        if (!turnstile?.success) {
            return res.status(403).json({ success: false, message: 'Verifikasi Cloudflare gagal atau kedaluwarsa. Selesaikan captcha lalu coba lagi.' });
        }
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
        cloudflareId: created?.id || null,
        createdAt: new Date()
    };
    try {
        await persistRecord(ip, record);
    } catch (error) {
        console.error('DNS dibuat tapi gagal menyimpan daftar subdomain:', error.message);
    }

    await recordCreateStat();

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
    let databaseErrorName = null;
    let databaseErrorDetail = null;
    try {
        await connectDB();
        database = mongoose.connection.readyState === 1 ? 'connected' : 'connecting';
    } catch (error) {
        database = 'error';
        databaseError = classifyDbError(error);
        databaseHint = DB_ERROR_HINTS[databaseError];
        databaseErrorName = String(error?.name || 'Error');
        databaseErrorDetail = sanitizeDbMessage(error?.message);
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
        databaseErrorName,
        databaseErrorDetail,
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
