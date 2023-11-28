const express = require("express");
const session = require("express-session");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");
const app = express();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
app.use(express.static("views"));

const uri = "mongodb://127.0.0.1:27017";
const db = "authenticatie";

async function connection() {
  const client = new MongoClient(uri);
  try {
    await client.connect();
    console.log("Verbonden met MongoDB"); // Verbonden met MongoDB
    return client.db(db);
  } catch (error) {
    console.error("Fout bij het verbinden met MongoDB:", error); // Fout bij het verbinden met MongoDB
    throw error;
  }
}

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

function generateToken() {
  return crypto.randomBytes(3).toString("hex");
}

app.post("/register", async (req, res) => {
  // haal de username en password op uit de request body
  const { gebruikersnaam, emailadres, voornaam, achternaam, wachtwoord } =
    req.body;

  // check of de username en password zijn ingevuld
  if (
    !gebruikersnaam ||
    !emailadres ||
    !voornaam ||
    !achternaam ||
    !wachtwoord
  ) {
    return res.render("register", {
      status: "error",
      message: "Vul alle velden in", // Vul alle velden in
    });
  }

  if (wachtwoord.length < 6) {
    return res.render("register", {
      status: "error",
      message: "Wachtwoord moet minimaal 6 tekens bevatten", // Wachtwoord moet minimaal 6 tekens bevatten
    });
  }

  const db = await connection();
  const collection = db.collection("users");
  const user = await collection.findOne({
    $or: [{ gebruikersnaam: gebruikersnaam }, { emailadres: emailadres }],
  });

  if (user) {
    if (emailadres === user.emailadres) {
      return res.render("register", {
        status: "error",
        message: "E-mailadres bestaat al", // E-mailadres bestaat al
      });
    } else if (gebruikersnaam === user.gebruikersnaam) {
      return res.render("register", {
        status: "error",
        message: "Gebruikersnaam bestaat al", // Gebruikersnaam bestaat al
      });
    }
  } else {
    // hash het wachtwoord met bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(wachtwoord, salt);

    // maak verbinding met de database
    try {
      const db = await connection();
      const collection = db.collection("users");

      const idCollection = db.collection("_id");

      // haal het laatste id op uit de database
      let lastId = await idCollection.findOne({ name: "userId" });
      if (!lastId) {
        lastId = { name: "userId", value: 0 };
        await idCollection.insertOne(lastId);
      }

      // maak een nieuw id aan
      lastId.value += 1;
      await idCollection.updateOne(
        { name: "userId" },
        { $set: { value: lastId.value } } // update het id in de database
      );

      // maak een nieuw gebruiker object aan
      const newUser = {
        _id: lastId.value,
        gebruikersnaam: gebruikersnaam,
        emailadres: emailadres,
        voornaam: voornaam,
        achternaam: achternaam,
        wachtwoord: hashedPassword,
        failedAttempts: 0,
        blocked: 0,
        blockExpires: 0,
        token: generateToken(),
      };

      // voeg de gebruiker toe aan de database
      await collection.insertOne(newUser);

      // login pagina renderen
      return res.render("register", {
        status: "success",
        message: "Account succesvol aangemaakt", // Account succesvol aangemaakt
      });
    } catch (error) {
      return res.render("register", {
        status: "error",
        message: "Fout bij het registreren van de gebruiker", // Fout bij het registreren van de gebruiker
      });
    }
  }
});

app.get("/register", (req, res) => {
  res.render("register", {
    status: req.query.status,
    message: req.query.error,
  });
});

app.get("/login", (req, res) => {
  res.render("login", {
    status: req.query.status,
    message: req.query.error,
  });
});

async function sendVerificationEmail(emailadres, token, username) {
  const db = await connection();
  const collection = db.collection("users");

  let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.USEREMAIL,
      pass: process.env.USERPASSWORD,
    },
  });

  let mailOptions = {
    from: process.env.USEREMAIL,
    to: emailadres,
    subject: "Account Verificatie Token",
    text: `Hallo ${username},\n
      jouw token is ${token}`,
  };
  await collection.updateOne(
    { emailadres: emailadres },
    { $set: { token: token } }
  );

  transporter.sendMail(mailOptions, function (err) {
    if (err) {
      console.log("Fout bij het verzenden van de verificatie-e-mail", err); // Fout bij het verzenden van de verificatie-e-mail
    } else {
      console.log("Verificatie-e-mail verzonden"); // Verificatie-e-mail verzonden
    }
  });
}

// send email when user is blocked
async function sendBlockedEmail(emailadres, username) {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.USEREMAIL,
      pass: process.env.USERPASSWORD,
    },
  });

  let mailOptions = {
    from: process.env.usermail,
    to: emailadres,
    subject: "Je account is geblokkeerd",
    html: `<p>Hallo ${username}, \n\n Je account is geblokkeerd omdat je te vaak onjuiste inloggegevens hebt ingevoerd. Je kunt over 24 uur weer inloggen</p>`,
  };

  await transporter.sendMail(mailOptions);
  console.log("Bericht verzonden: %s", mailOptions.messageId); // Bericht verzonden
}

app.post("/login", async (req, res) => {
  const { gebruikersnaam, wachtwoord } = req.body;

  if (!gebruikersnaam || !wachtwoord) {
    return res.render("login", {
      status: "error",
      message: "Vul alle velden in",
    });
  }

  try {
    const db = await connection();
    const collection = db.collection("users");

    const user = await collection.findOne({
      $or: [{ gebruikersnaam: gebruikersnaam }, { emailadres: gebruikersnaam }],
    });

    if (!user) {
      return res.render("login", {
        status: "error",
        message: "Gebruiker bestaat niet",
      });
    }

    const isMatch = await bcrypt.compare(wachtwoord, user.wachtwoord);

    if (!isMatch) {
      const updatedUser = await collection.findOneAndUpdate(
        { gebruikersnaam: gebruikersnaam },
        { $inc: { failedAttempts: 1 } },
        { returnOriginal: false }
      );

      if (updatedUser.failedAttempts >= 3) {
        await sendBlockedEmail(user.emailadres, user.gebruikersnaam);

        const gebruikersnaam = user.gebruikersnaam;
        const blockDuration = 24 * 60 * 60 * 1000;
        const blockExpires = new Date(Date.now() + blockDuration);

        await collection.updateOne(
          { gebruikersnaam: gebruikersnaam },
          {
            $set: {
              blocked: true,
              blockExpires: blockExpires,
              failedAttempts: 0,
            },
          }
        );
        res.redirect("/login");
        return res.render("login", {
          status: "error",
          message: "Gebruiker is geblokkeerd voor 24 uur",
        });
      }
      return res.render("login", {
        status: "error",
        message: "Onjuist wachtwoord",
      });
    } else {
      if (!user.blocked) {
        const userEmail = user.emailadres;
        const token = generateToken();
        await sendVerificationEmail(userEmail, token, gebruikersnaam);
      } else {
        return res.render("login", {
          status: "error",
          message: "Gebruiker is geblokkeerd voor 24 uur",
        });
      }
      const loggedInUser = await collection.findOne({
        gebruikersnaam: gebruikersnaam,
      });
      req.session.username = user.voornaam;
      req.session.lastName = user.achternaam;

      if (
        loggedInUser &&
        loggedInUser.blocked &&
        Date.now() > loggedInUser.blockExpires
      ) {
        await collection.updateOne(
          { gebruikersnaam: gebruikersnaam },
          { $set: { blocked: false, blockExpires: null, failedAttempts: 0 } }
        );
      } else {
        await collection.updateOne(
          { gebruikersnaam: gebruikersnaam },
          { $set: { failedAttempts: 0 } }
        );
      }
      return res.redirect("/verify");
    }
  } catch (e) {
    console.log(e);
    console.log("Fout tijdens het inloggen:", e);
    return res.render("login", {
      status: "error",
      message: "Er is een fout opgetreden tijdens het inloggen",
    });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

app.get("/", (req, res) => {
  const username = req.session.username;
  const user = {
    username: username,
    lastName: req.session.lastName,
  };
  res.render("index", { user });
});

app.get("/verify", (req, res) => {
  res.render("verify", {
    status: req.query.status,
    message: req.query.error,
  });
});

async function verifyToken(token) {
  const db = await connection();
  const collection = db.collection("users");

  const user = await collection.findOne({ token: token });

  if (user && user.token === token) {
    return true;
  }
  return false;
}

app.post("/verify", async (req, res) => {
  const { token } = req.body;
  const isValidToken = await verifyToken(token);

  if (isValidToken) {
    res.redirect("/");
  } else {
    return res.render("verify", {
      status: "error",
      message: "Invalid token",
    });
  }
});

app.listen(3000, () => console.log("Server started on port 3000"));
