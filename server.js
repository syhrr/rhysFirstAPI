const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

require('dotenv').config()
const jwt = require('jsonwebtoken')

const Database = require('better-sqlite3')
app.use(express.json())

// create a new DB
const db = new Database('todo.db')

// create the schema for the DB
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  )
`)

// when someone sends a GET request to the ROOT of the server
// this happens
app.get('/',(req,res) =>{
    res.send('Hello from server')
})


// when someone sends a GET request to /register
// this happens
app.get('/register',(req,res) =>{
    res.send('Register page')
})

// when you send a POST request to the /register route 
// return a 201 response json
app.post('/register', async (req, res) => {
    const { name, email, password} = req.body

    if (!name || !password || !email ) return res.status(400).json({ error: 'name, password and email are required' })

    const hash = await bcrypt.hash(password, 12)
        
 try {
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    ).run(name, email, hash)
    res.status(201).json({ id: result.lastInsertRowid, name })
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'email already taken ffs' })
    }
    throw err
  }
})

// get all users if you go to /users route
app.get('/users', (req,res) => {
    const users = db.prepare('SELECT * FROM users').all()
    res.json(users)

})

app.get('/todos', async (req, res) => {
  const {token} = req.body
  if (!token) return res.status(401).json({ error: 'token is required' })


})

// GET  for login page
app.get('/login',(req,res) => {
  res.send('Pls send login details')
})


app.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    
    // 400 bad request
    return res.status(400).json({ error: 'email and password are required' })
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  // use 401 instead of 404, 401 not authorised if email isnt in DB
  if (!user) return res.status(401).json({ error: 'user or password is incorrect' })

  // bcrypt compares the password with the hashed password stored in the DB
  const match = await bcrypt.compare(password, user.password_hash)

  if (!match) return res.status(401).json({ error: 'user or password is incorrect' })

  // make a JWT, client stores it and sends it in the body of every request
  const token = jwt.sign({ id: user.id, name: user.name },process.env.JWT_SECRET, { expiresIn: '1h' })
  
  // return a JSON with the token
  res.json({ id: user.id, name: user.name, token })


})



// listens on port 3000
app.listen(3000,() => {
    console.log("server is running")
})

