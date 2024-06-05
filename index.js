import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
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

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

// we have to get this login page to trigger so a new get request .. it is defined in login and register ejs 
app.get("/auth/google", passport.authenticate("google",{  // this google strategy came from that passport strategy defined at end
    scope: ["profile" , "email"], // telling user that we are grabbing hold of this information 
                                  // once this gets approved then the google strategy gets hit up
}))

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect : "/secrets",
  failureRedirect: "/login",
}))

// making the logout route
app.get("/logout", (req,res)=>{
  req.logout((err)=>{
    if(err) console.log(err);
    res.redirect("/");
  });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use("google" , new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret : process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL : "https://www.googleapis.com/oauth2/v3/userinfo",

},async(accessToken , refreshToken , profile, cb)=>{  // now we added the callback function which gets triggered once the manage to login with their google account

    console.log(profile);

    // now we save their data in the database and be able to identify them in pur system
    try{

      const result = await db.query("SELECT * FROM users WHERE email = $1 ;", [profile.email]) // by console logging this profile we get to know this contain a email property that we can get
      if(result.rows.length === 0){
        const newuser = await db.query("INSERT INTO users (email,password) VALUES ($1,$2) ;", [profile.email, "google"]) // we dont have their password as they are signing in with google so to differentiate we save it as google
        cb(null, newuser.rows[0]);
      }else{
        // user already exists
        cb(null, result.rows[0]);
      }

    }catch(err){
      cb(err);
    }

})
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
