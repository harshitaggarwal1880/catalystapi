require('dotenv').config();

let express = require("express");
let cookieParser = require("cookie-parser");
const { createConnection } = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const route = express.Router();

// Using environment variables for the database connection
const db = createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});


const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;


function authenticateToken(req, res, next) {
  const token = req.cookies.jwt;
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

route.get("/test", (req, res) => {
  const q = "Select * FROM users";
  console.log("log: show table");
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

route.post("/signup", (req, res) => {
  bcrypt.hash(req.body.password, 10, function (err, hash) {
    const q = "INSERT INTO users (`username`, `password`, `email`) VALUES (?)";
    const values = [req.body.username, hash, req.body.email];
    db.query(q, [values], (err, data) => {
      if (err) return res.json(err);
      res.send(data);
    });
  });
});

route.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const queryPromise = new Promise((resolve, reject) => {
        db.query("SELECT * FROM users WHERE username = ?;", [username], (err, results) => {
            if (err) {
                reject(err);
            } else {
                if (results[0]) {
                    resolve(results);
                } else {
                    res.send(false);
                }
            }
        });
    });
    const loginPromise = queryPromise
        .then((results) => {
            const result = results[0]; // Assuming you want the first row
            
            return new Promise((resolve, reject) => {
                bcrypt.compare(password, result.password, (err, isMatch) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ isMatch, userId: result.userId, username: result.username });
                    }
                });
            });
        })
        .catch((err) => {
            console.error(err);
            res.status(500).send("Error occurred");
    });
  loginPromise
    .then(({ isMatch, userId, username }) => {
      if (isMatch) {
        const user = { id: userId, name: username };
        const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET);
        res.cookie("jwt", accessToken);
        res.send(true);
      } else {
        res.send(false);
      }
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error occurred");
    });
});

route.get("/fetchCurrentUser", authenticateToken, (req, res) => {
  res.send(req.user);
});

route.get("/isLoggedIn", (req, res) => {
  if (req.cookies["jwt"]) {
    res.send(true);
  } else {
    res.send(false);
  }
});

function authenticateToken(req, res, next) {
  const token = req.cookies.jwt;
  if (token == null) return false;
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

route.get("/clear", (req, res) => {
  // res.clearCookie("jwt");
  res.clearCookie("jwt", { path: "/" });
  // res.cookie("jwt", "", {
  //   httpOnly: true,
  //   secure: true,
  //   sameSite: "none", });
  res.send(true);
});


module.exports = route;