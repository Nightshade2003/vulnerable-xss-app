// app.js with in-app brute-force protection (Fail2Ban alternative)

const express = require('express')

const path = require('path');

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
const cors = require('cors')
const rateLimit = require('express-rate-limit')
require('dotenv').config()

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

const app = express()
const port = 3000
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key'
const API_KEY = process.env.API_KEY || 'your-secure-api-key'

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

const User = mongoose.model('User', new mongoose.Schema({
  email: String,
  password: String
}))

// Middleware
app.use(helmet())
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}))
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}))

app.use(cors({
  origin: 'https://your-frontend-domain.com',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }))
app.use(bodyParser.json())
app.use(mongoSanitize())

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, try again later.'
})

app.use('/login', apiLimiter)
app.use('/register', apiLimiter)

// Brute-force protection
const failedLogins = new Map()
const MAX_ATTEMPTS = 5
const BLOCK_TIME = 15 * 60 * 1000

// Static
app.use('/media', express.static('media'))
app.use('/scripts', express.static('scripts'))
app.use('/public', express.static(path.join(__dirname, 'public')))


const sanitizeAndEscape = (dirty) => {
  const clean = DOMPurify.sanitize(dirty, {
    USE_PROFILES: false,
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: []
  })
  return escapeHTML(clean)
}

// API Key protection
app.use('/api/secure', (req, res, next) => {
  const apiKey = req.headers['x-api-key']
  if (apiKey !== API_KEY) return res.status(403).send('Forbidden')
  next()
})

// Routes
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

// Logging
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

// Register
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

// Login with brute-force protection
app.post('/login', async (req, res) => {
  const ip = req.ip
  const now = Date.now()
  const record = failedLogins.get(ip) || { count: 0, lastAttempt: now }

  if (record.count >= MAX_ATTEMPTS && (now - record.lastAttempt) < BLOCK_TIME) {
    logger.warn(`IP blocked due to repeated login failures: ${ip}`)
    return res.status(429).send('Too many login attempts. Please try again later.')
  }

  const { email, password } = req.body
  const user = await User.findOne({ email })

  if (!user || !(await bcrypt.compare(password, user.password))) {
    failedLogins.set(ip, {
      count: record.count + 1,
      lastAttempt: now
    })
    logger.warn(`Failed login attempt for email: ${email} from IP: ${ip}`)
    return res.status(401).send('Invalid credentials')
  }

  failedLogins.delete(ip)
  const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' })
  logger.info(`User logged in: ${email} from IP: ${ip}`)
  res.send({ token })
})

// Optional: view blocked IPs (secure this in production)
app.get('/admin/attempts', (req, res) => {
  res.json(Object.fromEntries(failedLogins))
})

app.listen(port, () => logger.info(`Listening on port ${port}`))