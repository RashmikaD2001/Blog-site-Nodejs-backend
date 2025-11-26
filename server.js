require("dotenv").config()

const express = require("express")

const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken')
const cookieParser = require("cookie-parser")

const sanitizeHTML = require("sanitize-html")

const db = require("better-sqlite3")("database.db")
db.pragma("journal_mode = WAL")

// database setup 
// transaction to run multiple statements at once
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL)
    `).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            createdDate TEXT,
            title STRING NOT NULL,
            body STRING NOT NULL
            authorId INTEGER NOT NULL,
            FOREIGN KEY(authorID) REFERENCES users(id))
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
        const decoded = jwt.verify(req.cookies.userCookie, process.env.JWTSECRET)
        req.user = decoded
    }catch(error){
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)

    next()
})


app.get("/", (req, res) => {

    if(req.user){
        return res.render("dashboard")
    }

    res.render("homepage")
})

app.get("/logout", (req, res) => {
    res.clearCookie("userCookie")
    res.redirect("/")
})

app.get("/login", (req, res) => {
    res.render("login")
}) 

app.post("/login", (req, res) => {
    
    const errors = []
    
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    req.body.password = req.body.password.trim()

    if(!req.body.username) errors.push("Username is required")
        if(!req.body.password) errors.push("Password is required")

    if(errors.length){
        return res.render("login", {errors})
    }

    const lookupStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const ourUser = lookupStatement.get(req.body.username)

    if(!ourUser){
        errors.push("Invalid username")
        return res.render("login", {errors})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, ourUser.password)

    if(!matchOrNot){
        errors.push("Invalid password")
        return res.render("login", {errors})
    }

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

    res.redirect("/")


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

    // check if username is already taken
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const existingUser = usernameStatement.get(req.body.username)
    if(existingUser){
        errors.push("Username is already taken")
        return res.render("homepage", {errors})
    }

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

    res.redirect("/")
})

// post crud
function mustBeLoggedIn(req, res, next){
    if(req.user){
        return next()
    }

    return res.redirect("/")
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

function sharedPostValidation(req){

    const errors = []

    if(typeof req.body.title !== "string") req.body.title = ""
    if(typeof req.body.body !== "string") req.body.body = ""

    req.body.title = req.body.title.trim()
    req.body.body = req.body.body.trim()

    // trim -sanitize or strip out html

    // input string, config object - input parameters
    req.body.title = sanitizeHTML(req.body.title, {allowedTags: [], allowedAttributes: {}})
    req.body.body = sanitizeHTML(req.body.body, {allowedTags: [], allowedAttributes: {}})

    if(!req.body.title) errors.push("Title is required")
    if(!req.body.body) errors.push("Body is required")

    return errors
}

// :id dynamic parameter 
app.get("post/:id", (req, res) => {
    const statement = db.prepare(
        "SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid=users.id WHERE posts.id = ?"
    )
    const post = statement.get(req.params.id)

    if(!post){
       return res.render("404") 
    }

    res.render("single-post", {post})
})

app.post("/create-post", mustBeLoggedIn, (req, res) => {

    const errors = sharedPostValidation(req)

    if(errors.length){
        return  res.render("create-post", {errors})
    }

    const insertStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
    const result = insertStatement.run(
        req.body.title,
        req.body.body,
        req.user.userid,
        new Date().toISOString()
    )

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const newPost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${newPost.id}`)
})

app.listen(3000)