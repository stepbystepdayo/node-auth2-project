const bcrypt = require("bcryptjs");
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { jwtSecret } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");
const jwt = require("jsonwebtoken");

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = req.body;
  // console.log("this is user:", user);
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  // console.log("this is rounds", rounds);
  const hash = bcrypt.hashSync(user.password, rounds);
  // console.log(hash);

  user.password = hash;
  // console.log("this is user.password", user.password);
  Users.add(user)
    .then((saved) => {
      res.status(201).json(saved);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  const { username, password } = req.body;
  // console.log("this is username", username);
  // console.log("this is password", password);
  // console.log("this is role_name:", role_name);
  Users.findBy({ username }).then(([user]) => {
    // console.log("this is user:", user);
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = makeToken(user);
      // console.log("this is token", token);
      res.status(200).json({
        message: `${user.username} is back`,
        token,
      });
    } else {
      res.status(401).json({ message: "Invalid Credentials" });
    }
  });
});

const makeToken = (user) => {
  const options = {
    expiresIn: "1d",
  };
  // console.log(options);
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  // console.log(payload);
  return jwt.sign(payload, jwtSecret, options);
};

module.exports = router;
