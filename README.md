Vulnerable XSS Web Application
==============================
This is a small Node.js powered web application which is intentionally vulnerable to cross-site scripting.

It was created to demonstrate:

* How custom filtering and cleansing may be bypassed
* Alternative attack vectors to those typically documented

To read more about this, see our blog post at: https://research.digitalinterruption.com/2018/12/18/a-deeper-look-into-xss-payloads/

Prerequisites
-------------
* [Node.js (8.14 or higher)](https://nodejs.org/en/)
* [Yarn](https://yarnpkg.com/lang/en/) (or equivalent package manager)

Installation
------------
```bash
git clone https://github.com/DigitalInterruption/vulnerable-xss-app.git
cd vulnerable-xss-app
yarn install
```

Run `node app.js` and then visit http://localhost:3000 in your browser.

Usage
-----
Each of the vulnerable endpoints accepts a query string parameter named `xss` which is processed and output in the response.

### Vulnerable Endpoints
| Endpoints  | Description                                                              |
| ---------- | ------------------------------------------------------------------------ |
| `/`        | Reflects the `xss` parameter without modification                        |
| `/replace` | Replaces any `script` tags in  the `xss` parameter with `NAUGHTY_HACKER` |
| `/remove`  | Removes any `script` tags or `onerror` attributes in the `xss` parameter |

### Utility Endpoints
| Endpoints     | Description                                                                  |
| ------------- | ---------------------------------------------------------------------------- |
| `/keylogger`  | Logs the `data` form field from the request in the server console            |
| `/screenshot` | Decodes the base64 encoded image from the `data` field into `screenshot.png` |

### Static Resources
| Endpoints  | Description                                                                        |
| ---------- | ---------------------------------------------------------------------------------- |
| /media/*   | Various multimedia files to test vectors using the `img`, `audio` and `video` tags |
| /scripts/* | Scripts used to initialise attacks with larger payloads (e.g. keylogging)          |

### Examples
```
http://localhost:3000/?xss=<audio oncanplay=alert(1) src="/media/hack-the-planet.mp3" />
http://localhost:3000/?xss=<video autoplay=true onended=alert(1) src="/media/hack-the-planet.mp4" />
http://localhost:3000/remove?xss=<img src=x ononerrorerror=alert(1) />
http://localhost:3000/replace?xss=<script <script>>alert(1)</script <script>>
```

# Secure Vulnerable XSS App

This project upgrades an intentionally vulnerable XSS app with real-world security features including login/signup pages, rate-limiting, input sanitization, API security, and monitoring.

---

## 🔐 Features Implemented

### ✅ Authentication
- `/register` and `/login` routes with bcrypt password hashing
- JWT token authentication

### ✅ Brute-Force Protection
- Tracks failed login attempts by IP
- Temporarily blocks IPs after 5 failed attempts for 15 minutes

### ✅ Rate Limiting
- Limits login and registration to 100 requests per 15 minutes per IP

### ✅ API Security
- `x-api-key` required for secure API endpoints

### ✅ Input Validation & XSS Protection
- `validator` used for email validation
- `express-mongo-sanitize` for MongoDB query protection
- `DOMPurify` + HTML escaping to block XSS

### ✅ HTTP Security Headers
- `helmet` for secure headers
- CSP and HSTS configured

### ✅ Logging
- All events logged using `winston` to `security.log`

### ✅ Frontend
- `/login` and `/signup` forms with proper HTML & styling
- POSTs to backend using fetch()

---

## 💾 Setup Instructions

### 1. Clone the repo

```bash
git clone https://github.com/Nightshade2003/vulnerable-xss-app
cd vulnerable-xss-app
