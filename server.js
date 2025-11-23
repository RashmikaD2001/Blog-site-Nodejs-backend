const bcrypt = require("bcrypt")
const express = require("express")
const db = require("better-sqlite3")("database.db")
db.pragma("journal_mode = WAL")

// database setup
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL)
    `).run()
})

createTables()

const app = express()

// template engine
app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))

// middleware - run this first
app.use((req, res, next) => {
    res.locals.errors=[]
    next()
})

app.get("/", (req, res) => {
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
}) 

app.post("/register", (req, res) => {

    const errors = []
    
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    req.body.password = req.body.password.trim()

    if(!req.body.username) errors.push("Username is required")
    if(req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters")
    if(req.body.username && req.body.username.length > 10) errors.push("Username cannot exceed 10 characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username cannot contain special characters")

    if(!req.body.password) errors.push("Password is required")
    if(req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters")
    if(req.body.password && req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Password must contain special characters")

    if(errors.length){
        return res.render("homepage", {errors})
    }

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)
    
    const preparedStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    preparedStatement.run(req.body.username, req.body.password)

    res.send("User registered successfully")
})

app.listen(3000)