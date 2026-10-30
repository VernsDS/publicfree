# 🚀 Dokumentasi Projek: PublicFree Subdomain (publicfree.web.id)

## 📌 Deskripsi Singkat
Projek ini adalah sebuah aplikasi web (Landing Page & REST API) yang memungkinkan pengguna untuk membuat dan mendaftarkan subdomain secara gratis menggunakan ekstensi `.publicfree.web.id`. Sistem ini terhubung langsung ke **Cloudflare API** untuk melakukan pencatatan DNS (*A Record* atau *CNAME*) secara instan dan otomatis.

## 🛠️ Stack Teknologi
Projek ini dibangun menggunakan arsitektur modern dan disesuaikan untuk lingkungan *Serverless* (Vercel):
- **Frontend**: HTML5, CSS3 (Vanilla dengan gaya Premium Dark Mode / Glassmorphism), dan Vanilla JavaScript.
- **Backend**: Node.js dengan framework Express.js.
- **Database**: MongoDB Atlas (Cloud Database) menggunakan library `mongoose`.
- **Security & API**: Cloudflare API, Cloudflare Turnstile (Captcha), `helmet`, `express-rate-limit`, dan IP-API (Pendeteksi VPN).
- **Hosting / Deployment**: Vercel.

---

## ✨ Fitur-Fitur Utama

1. **Pembuatan DNS Instan**
   Pengguna dapat mengarahkan subdomain mereka langsung ke IP VPS (A Record) atau ke platform hosting lain seperti Vercel/GitHub Pages (CNAME).

2. **Keamanan & Anti-Bot Tingkat Tinggi**
   - **Cloudflare Turnstile**: Mencegah bot *scraper* tanpa membebani pengguna dengan teka-teki gambar yang rumit.
   - **Anti-VPN & Proxy**: Memblokir pengguna yang menggunakan VPN/Proxy untuk mencegah penyalahgunaan kuota.
   - **Frontend Protection**: Memblokir Klik Kanan dan *Developer Tools* (F12/Inspect Element) untuk menyembunyikan *source code* dari pengguna awam.

3. **Manajemen Kuota (Database Persistent)**
   - Setiap pengguna (berdasarkan IP Address) dibatasi hanya dapat membuat **Maksimal 2 Subdomain**.
   - Data kuota ini disimpan di **MongoDB Atlas**, sehingga data tidak akan hilang / *reset* meskipun server Vercel melakukan *restart* (Serverless cold-start).

4. **Desain Premium (UI/UX)**
   - Tampilan antarmuka kelas atas bergaya *dark-street / glassmorphism*.
   - Dilengkapi *Live Progress Bar* untuk menunjukkan sisa kuota IP pengguna.
   - *Popup Notification* otomatis untuk mengarahkan pengguna bergabung ke saluran WhatsApp.

---

## 🛤️ Perjalanan Projek (Apa Saja yang Sudah Kita Lakukan)

Projek ini telah melalui beberapa fase pengembangan hingga mencapai tahap *Production-Ready*:

### Tahap 1: Perombakan Frontend (UI/UX)
- Mengubah tampilan standar menjadi *Landing Page* premium dengan animasi *fade-up*, efek *glow*, dan tombol WhatsApp yang interaktif.
- Membangun logika *Progress Bar* yang mengambil data kuota IP pengguna secara langsung dari *backend* (`/api/status`).

### Tahap 2: Penguatan Keamanan Backend
- Menambahkan library `helmet` untuk mengamankan HTTP headers.
- Membuat dua jenis *Rate Limiter*: 
  1. *Spam Limiter* (Maksimal 15 request per menit).
  2. *Subdomain Limiter* berbasis IP Address.
- Membuat sistem *middleware* Anti-VPN dengan melakukan pencocokan IP menggunakan API pihak ketiga dan menyimpannya di dalam memori sementara (*cache*).

### Tahap 3: Migrasi Database ke Cloud
- **Masalah Awal**: Vercel tidak bisa menyimpan file lokal (seperti `database.json`) secara permanen.
- **Solusi**: Mengintegrasikan **MongoDB Atlas**. Kita mengatur *Cluster* gratis, memasukkan *IP Whitelist* (`0.0.0.0/0`), dan menyambungkan *URI Connection String* melalui `mongoose`.
- **Bug Fix**: Memperbaiki masalah pemblokiran internet (ECONNREFUSED) dengan menggunakan **Legacy URI String** dari MongoDB, dan menyesuaikan sintaks koneksi `mongoose` versi terbaru.

### Tahap 4: Penyesuaian Vercel (Serverless)
- Membuat file `vercel.json` khusus agar Vercel dapat memisahkan rute `/api` untuk backend Node.js dan me-render *frontend* (Static HTML) secara efisien.
- Mengekspor aplikasi Express (`module.exports = app`) alih-alih menggunakan `app.listen` yang menyebabkan error *crash* pada sistem *serverless* Vercel.

### Tahap 5: Finalisasi & Rilis
- Menambahkan domain Vercel ke dalam *Whitelist* Cloudflare Turnstile agar captcha bisa merender tanpa pesan *Domain Mismatch*.
- Membuat draf "Official Release" yang profesional untuk publikasi layanan ke komunitas.

---

## 🎯 Status Saat Ini
Projek sudah **100% Selesai dan Beroperasi (Online)**.
Backend telah tersambung sempurna dengan MongoDB Atlas dan Cloudflare API. Sistem keamanan berjalan dengan baik, dan aplikasi berhasil di-*deploy* di Vercel tanpa kendala *routing* atau *database reset*.