# @kawanua/license-sdk

SDK resmi untuk klien yang menggunakan sistem lisensi Kawanua. SDK ini menyediakan metode verifikasi lisensi berbasis JWT (RS256) di sisi klien dengan fitur auto-branding dan kontrol akses fitur yang dinamis.

## Fitur Utama

- **Verifikasi Aman:** Memverifikasi token JWT lisensi menggunakan RS256.
- **Dukungan Multi-Environment:** Mendukung browser (via `<script>`), CommonJS, dan ESM.
- **Kontrol Fitur:** Mendukung limitasi fitur berdasarkan plan (Starter, Professional, Enterprise).
- **Auto-Branding:** Secara otomatis menyuntikkan atau menyembunyikan elemen "Powered by Kawanua" sesuai ketentuan lisensi.
- **Auto-Refresh:** Mekanisme pembaruan token otomatis sebelum masa berlaku habis.

## Instalasi

### via CDN (Browser)

Tambahkan script berikut sebelum tag `</body>`:

```html
<script src="https://cdn.kawanua.id/sdk/license.min.js"></script>
```

### via NPM

```bash
npm install @kawanua/license-sdk
```

## Penggunaan

### Inisialisasi

```javascript
import { KawanuaLicense } from '@kawanua/license-sdk';

KawanuaLicense.init({
  token: 'YOUR_JWT_TOKEN',
  onRefresh: async () => {
    // Implementasi untuk fetch token baru dari server kamu
    const res = await fetch('/api/license/refresh');
    const { token } = await res.json();
    return token;
  },
  onReady: (state) => {
    console.log('Lisensi aktif, plan:', state.plan);
  },
  onError: (err) => {
    console.error('Inisialisasi gagal:', err.message);
  }
});
```

### Mengecek Akses Fitur

Setelah inisialisasi berhasil, kamu bisa mengecek apakah sebuah fitur diperbolehkan:

```javascript
// Mengecek boolean
if (KawanuaLicense.can('api_access')) {
  // Tampilkan fitur API
}

// Mendapatkan nilai (misal: limit jumlah user)
const maxUsers = KawanuaLicense.get('max_users');
```

## Referensi Plan

SDK secara otomatis mengatur batasan fitur berdasarkan plan:

| Fitur | Starter | Professional | Enterprise |
| :--- | :---: | :---: | :---: |
| **Remove Branding** | ❌ | ✅ | ✅ |
| **Custom Domain** | ❌ | ❌ | ✅ |
| **API Access** | ❌ | ✅ | ✅ |
| **Max Users** | 5 | 50 | ∞ |

## Lisensi

ISC

---
*Dibuat oleh [Kawanua Indo Digital](https://labs.kawanua.co)*
