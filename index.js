import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
env.config();

app.use(session({
  secret : process.env.SESSION_SECRET,
  resave : false,
  saveUninitialized : true,
  cookie : {
    maxAge : 1000 * 60 * 60 * 24,
  }
}))

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",async (req,res)=>{
  if(req.isAuthenticated()){
    const result = await db.query("SELECT * FROM todos WHERE user_id = $1",[req.user.id]);
    const items = result.rows;
    res.render("index.ejs", {
      listTitle: "Today",
      listItems: items,
  });
  }
  else{
    res.redirect("/login");
  }
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user , (err)=>{
            console.log(err)
            res.redirect("/secrets")
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect : "/secrets",
  failureRedirect : "/login",
}));

app.post("/add", async (req, res) => {
  if(req.isAuthenticated()){
    await db.query("INSERT INTO todos(user_id,title) VALUES ($1,$2)",[req.user.id,req.body.newItem]);
    res.redirect("/secrets");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/edit", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const item = req.body.updatedItemTitle;
  const id = req.body.updatedItemId;
  await db.query(
    "UPDATE todos SET title = $1 WHERE id = $2 AND user_id = $3",
    [item, id, req.user.id]
  );
  res.redirect("/secrets");
});

app.post("/delete", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  const id = req.body.deleteItemId;
  await db.query(
    "DELETE FROM todos WHERE id = $1 AND user_id = $2",
    [id, req.user.id]
  );
  res.redirect("/secrets");
});

app.get("/logout", (req, res) => {
  req.logout(err => {
    if (err) {
      console.log(err);
    }
    res.redirect("/login");
  });
});


passport.use(new Strategy(async function verify(username , password, cb){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null , user);
          } else {
            return cb(null, false);
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    return cb(err);
  }
}))

passport.serializeUser((user,cb)=>{
  cb(null, user);
});

passport.deserializeUser((user,cb)=>{
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});