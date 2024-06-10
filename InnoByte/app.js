const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const User = require("./model/user");
const app = express();

// Connect to MongoDB
// add your mongodb connection link here
// you have to just add the database name, where you want to store your data
mongoose.connect("mongodb://localhost:27017/InnoByteDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log("MongoDB connected successfully");
}).catch((err) => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }
  jwt.verify(token, "secret_key", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Email configuration
// you will have to generate an app password of your email, 
//it will not work with your normal password, you will have to generate an app password in go to setting
const transporter = nodemailer.createTransport({
  service: "yahoo", // server name like gmail yahoo etc
  auth: {
    user: "..........", // paste your email id here
    pass: "............" // paste your generate app password here
  }
});

// Routes
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/secret", authenticateJWT, (req, res) => {
  res.render("secret");
});

app.get("/register", (req, res) => {
  res.render("register");
});

//hash password
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000);
    const newUser = await User.create({
      email: req.body.email,
      password: hashedPassword,
      username: req.body.username,
      verificationCode: verificationCode
    });

    // Send confirmation email with verification code
    const mailOptions = {
      from: "............", // paste your email id here
      to: newUser.email,
      subject: "Welcome to InnoByte Services! Please confirm your email",
      html: `<p>Hi ${newUser.username},</p><p>Thank you for registering with us. Your verification code is ${verificationCode}.</p>`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.error("Error sending email:", error);
      } else {
        console.log("Email sent: " + info.response);
      }
    });

    res.render("verify", { userId: newUser._id });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(400).json({ error: error.message });
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Incorrect email or password" });
    }
    // Render the secret.html file and pass the username to it
    res.render("secret", { username: user.username });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});



app.get("/logout", (req, res) => {
  res.redirect("/");
});

app.post("/confirm/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { verificationCode } = req.body;
    if (user.verificationCode !== verificationCode) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    // Mark the user as verified
    user.isVerified = true;
    await user.save();

    // Send confirmation email
    const confirmationMailOptions = {
      from: "...............", //paste your email id here
      to: user.email,
      subject: "Email Verification Successful",
      html: `<p>Hi ${user.username},</p><p>Your email has been successfully verified.</p>`,
    };

    transporter.sendMail(confirmationMailOptions, function (error, info) {
      if (error) {
        console.error("Error sending confirmation email:", error);
      } else {
        console.log("Confirmation Email sent: " + info.response);
      }
    });

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Error verifying email:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

const port = process.env.PORT || 3000; //port
app.listen(port, () => {
  console.log(`Server has started on port ${port}`);
});
