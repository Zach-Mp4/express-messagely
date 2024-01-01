const express = require("express");
const router = new express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user")
const ExpressError = require("../expressError");
const db = require("../db");
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try {
      const { username, password } = req.body;
      const result = await db.query(
        "SELECT password FROM users WHERE username = $1",
        [username]);
      let user = result.rows[0];
  
      if (user) {
        if (await bcrypt.compare(password, user.password) === true) {
          let token = jwt.sign({ username }, SECRET_KEY);
          return res.json({ token });
        }
      }
      throw new ExpressError("Invalid user/password", 400);
    } catch (err) {
      return next(err);
    }
  });


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async function (req, res, next) {
    console.log('hi');
    console.log(User);
    try {
      const { username, password, first_name, last_name, phone } = req.body;
        let user = await User.register({
            username,
            password,
            first_name,
            last_name,
            phone
        });
        if (user) {
            let token = await jwt.sign({ username: user.username }, SECRET_KEY);
            return res.json({ token });
        }
    } catch (err) {
      return next(err);
    }
  });
module.exports = router;
