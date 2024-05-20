import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";

import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import serviceAccountKey from "./workout-project-88ceb-firebase-adminsdk-8jbyg-eb74a35d2d.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";

import User from "./Schema/User.js";
// import Blog from "./Schema/Blog.js";
//to generate byte string for encryption
//type 'node' in terminal
// Run 'node' in the terminal to generate byte string for encryption
//  openssl rand -base64 32
//require('crypto').randomBytes(64).toString('hex');

const app = express();
const port = 4000;

app.use(express.json());
app.use(cors());
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token === null) {
    return res
      .status(401)
      .json({ message: "Unauthorized, access token is not present" });
  }
  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid" });
    }
    req.user = user.id; //{ id: user._id } from jwt sign
    next();
  });
};

//google authentication
app.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;
  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;
      picture = picture.replace("s96-c", "s384-c"); //convert picture to high resolution

      //checking if user in database
      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
          //google auth in used instead of password auth you will find it in database schema
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });

      if (user) {
        //if the user does not have google auth and is a member
        if (!user.google_auth) {
          return res.status(403).json({
            error:
              "This email was signed up without google. Please log in wih password to access the account",
          });
        }
      } else {
        //if user is signing up
        let username = await generateUsername(email);
        user = new User({
          personal_info: {
            fullname: name,
            email: email,
            profile_img: picture,
            username: username,
          },
          google_auth: true,
        });
        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      return res.status(500).json({
        error:
          "Failed to authenticate you with google credentials. Please try again later.",
      });
    });
});
app.post("/signup", (req, res) => {
  console.log(req.body);

  debugger;
  let { fullname, email, password } = req.body;
  //  validate the data
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Fullname must be at least 3 characters long" });
  }

  if (!email.length) {
    //run on false
    return res.status(403).json({ error: "Please enter Email" });
  }

  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is invalid" });
  }

  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let username = await generateUsername(email);
    let user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });
    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      }) //saving the data
      .catch((err) => {
        if (err.code == 11000) {
          return res.status(403).json({ error: "Email already exists" });
        } else {
          return res.status(500).json({ error: err.message });
        }
      });
  });

  //   return res.status(200).json({ status: "okay" });
});

app.post("/signin", (req, res) => {
  debugger;
  let { email, password } = req.body;
  if (!email.length) {
    //run on false
    return res.status(403).json({ error: "Please enter Email" });
  }

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }
      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res
              .status(403)
              .json({ error: "Error occurred please try again" });
          }

          if (!result) {
            return res.status(403).json({ error: "Incorrect password" });
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error:
            "Account was created using google, please try logging in with google",
        });
      }

      console.log(user);
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ error: err.message });
    });
});

app.post("/update-personal-details", verifyJWT, (req, res) => {
  debugger;
  let authorId = req.user; //from middleware
  let { weight, weightGoal, height, gender, age, preference } = req.body;
  // return res.json(authorId);
  const updateFields = {};

  // Conditionally add fields to update object if they are provided

  if (weight) updateFields["personal_info.weight"] = weight;
  if (weightGoal) updateFields["personal_info.weightGoal"] = weightGoal;
  if (height) updateFields["personal_info.height"] = height;
  if (gender) updateFields["personal_info.gender"] = gender;
  if (age) updateFields["personal_info.age"] = age;
  if (preference) updateFields["personal_info.preference"] = preference;
  User.findOneAndUpdate(
    { _id: authorId },
    {
      $set: updateFields,
    },
    { new: true }
  )
    .then((user) => {
      debugger;
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      debugger;
      return res
        .status(500)
        .json({ error: "Failed to update personal details" });
    });
});

const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  debugger;
  return {
    access_token,
    personal_info: user.personal_info,
    fullname: user.fullname,
    username: user.username,
  };
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];
  let isUsernameTaken = await User.exists({
    "personal_info.username": username,
  }).then((result) => result); // check if username is available

  return isUsernameTaken ? username + nanoid().substring(0, 5) : username;
};
app.use(express.json());
app.use(cors());
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

app.listen(port, () => {
  console.log("listening on port " + port);
});
