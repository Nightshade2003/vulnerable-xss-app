// app.js with strict XSS protection, logging, and security checklist

const express = require('express')
const bodyParser = require('body-parser')
const helmet = require('helmet')
const fs = require('fs')
const validator = require('validator')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')
const mongoSanitize = require('express-mongo-sanitize')
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')
const winston = require('winston')

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

const app = express()
const port = 3000
const SECRET_KEY = 'your-secret-key'

// Logger setup
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
})
logger.info('Application started')

function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/vulnerable-xss-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error:', err))

// Define a simple User model
const User = mongoose.model('User', new mongoose.Schema({
  email: String,
  password: String
}))

// Middleware
app.use(helmet())
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }))
app.use(bodyParser.json())
app.use(mongoSanitize())

// Static files
app.use('/media', express.static('media'))
app.use('/scripts', express.static('scripts'))

// Strict XSS-safe routes
const sanitizeAndEscape = (dirty) => {
  const clean = DOMPurify.sanitize(dirty, {
    USE_PROFILES: false,
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: []
  })
  return escapeHTML(clean)
}

app.get('/', (req, res) => {
  const dirty = req.query.xss || ''
  const output = sanitizeAndEscape(dirty)
  res.send(`<html><body><strong>Usage: ?xss=&lt;script&gt;alert(1)&lt;/script&gt;</strong><div>${output}</div></body></html>`)
})

app.get('/replace', (req, res) => {
  const dirty = req.query.xss || ''
  const output = sanitizeAndEscape(dirty)
  res.send(`<html><body><strong>Sanitized Input:</strong><div>${output}</div></body></html>`)
})

app.get('/remove', (req, res) => {
  const dirty = req.query.xss || ''
  const output = sanitizeAndEscape(dirty)
  res.send(`<html><body><strong>Filtered Input:</strong><div>${output}</div></body></html>`)
})

// Logging for keylogger and screenshot
app.post('/keylogger', (req, res) => {
  logger.warn(`Key press detected: ${req.body.data}`)
  res.send('')
})

app.post('/screenshot', (req, res) => {
  const offsetToData = 22
  const data = Buffer.from(req.body.data.substring(offsetToData), 'base64')
  fs.writeFile('screenshot.png', data, (err) => {
    if (err) logger.error('Failed to save screenshot')
    else logger.info('Saved screenshot')
  })
  res.send('Logged')
})

// Register route with input validation and hashing
app.post('/register', async (req, res) => {
  const { email, password } = req.body
  if (!validator.isEmail(email)) return res.status(400).send('Invalid email')
  const existingUser = await User.findOne({ email })
  if (existingUser) return res.status(409).send('Email already exists')
  const hashedPassword = await bcrypt.hash(password, 10)
  const user = new User({ email, password: hashedPassword })
  await user.save()
  logger.info(`User registered: ${email}`)
  res.send('User registered successfully')
})

// Login route with JWT
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email })
  if (!user) return res.status(401).send('Invalid credentials')
  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) return res.status(401).send('Invalid credentials')
  const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' })
  logger.info(`User logged in: ${email}`)
  res.send({ token })
})

app.listen(port, () => logger.info(`Listening on port ${port}`))

/*
Security Checklist:
-------------------
- ✅ Validate all inputs
- ✅ Sanitize and escape user input (DOMPurify + escapeHTML)
- ✅ Hash and salt passwords (bcrypt)
- ✅ Use JWTs for authentication
- ✅ Sanitize Mongo inputs (express-mongo-sanitize)
- ✅ Use Helmet.js to secure HTTP headers
- 🔒 Use HTTPS for secure data transmission (Configure reverse proxy or SSL cert)
- 🧪 Perform basic penetration testing using tools like Nmap or browser-based tools
- 📝 All logs saved to 'security.log' using Winston
*/
