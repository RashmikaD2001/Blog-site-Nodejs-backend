require("dotenv").config()

const express = require("express")

const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken')
const cookieParser = require("cookie-parser")

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
app.use(cookieParser())

// middleware - run this first
app.use((req, res, next) => {
    res.locals.errors=[]

    // validating incoming jwt token
    try{
        // token value, secret value
        const decoded = jwt.verfity(request.cookies.userCookie, process.env.JWTSECRET)
        req.user = decoded
    }catch(error){
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)

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

    if(errors.length){
        return res.render("homepage", {errors})
    }

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)
    
    const preparedStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = preparedStatement.run(req.body.username, req.body.password)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    // data object, secret value only we know - private key
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)
    
    res.cookie(
        // name, value cookie to remember, config object
        "userCookie",
        ourTokenValue,
        {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 1000 * 60 * 60 * 24
        }
    )

    res.send("User registered successfully")
})

app.listen(3000)