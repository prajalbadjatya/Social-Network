const express = require("express");
const router = express.Router();
const auth = require("../../middleware/auth");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

//get api/auth
//access public
router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.log(err.message);
    res.status(500).send("Server Error");
  }
});

//POST api/auth
//Authenticate User and get Token
//access: public
router.post(
  "/",
  [

    check("email", "Please include a valid Email !").isEmail(),

    check(
      "password", "Password is required"
    ).exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      //see if user exists

      let user = await User.findOne({ email });
      // if not a user then send back error
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid Credentials" }] });
      }

      const isMatch = await bcrypt.compare(password,user.password);

      if(!isMatch)
      {
          return res.status(400).json({errors : [{ msg:'Invalid Credentials' }]});
      }
    
      const payload = {
        user: {
          id: user.id,
        },
      };
      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
