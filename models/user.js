/** User class for message.ly */

const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureAdmin } = require("../middleware/auth");


/** User of the site. */
class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  constructor({ username, password, first_name, last_name, phone, join_at, last_login_at }){
    this.username = username;
    this.password = password;
    this.first_name = first_name;
    this.last_name = last_name;
    this.phone = phone;
    this.join_at = join_at;
    this.last_login_at = last_login_at;
  }

  static async register({username, password, first_name, last_name, phone}) {
    try{
      if (!username || !password) {
        throw new ExpressError("Username and password required", 400);
      }
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      // save to db
      const date = new Date();
      const timestamp = date.toISOString();
      const results = await db.query(`
        INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone, timestamp, timestamp]);

        let user =  results.rows.map(c => new User(c));
        return user[0];
    }
    catch (e){
      if (e.code === '23505') {
        return new ExpressError("Username taken. Please pick another!", 400);
      }
      throw new Error(e); 
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try {
      if (!username || !password) {
        throw new ExpressError("Username and password required", 400);
      }
      const results = await db.query(
        `SELECT username, password 
         FROM users
         WHERE username = $1`,
        [username]);
      const user = results.rows[0];
      if (user) {
        if (await bcrypt.compare(password, user.password)) {
          return true;
        }
      }
      return false;
    } catch (e) {
      throw new Error(e);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    try{
      if (!username) {
        throw new ExpressError("Username required", 400);
      }
      const date = new Date();
      const timestamp = date.toISOString();

      const result = await db.query(
        `UPDATE users
        SET last_login_at = $1
        WHERE username = $2 
        RETURNING last_login_at`,
        [timestamp, username]
      );
      const login = result.rows[0];
      return login;
    }
    catch (e){
      throw new Error(e);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    try{
      const result = await db.query(
        `SELECT username, first_name, last_name, phone
        FROM users`
      );
  
      const users = result.rows.map(c => new User(c));
      return users;
    }
    catch (e){
      throw new Error(e);
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    try{
      const result = await db.query(
        `SELECT username, first_name, last_name, phone, last_login_at, join_at FROM users WHERE username = $1`,
        [username]
      );
      if (result.rows.length < 1){
        return null;
      }
      let user = result.rows.map(c => new User(c));
      return user[0];
    }
    catch (e){
      return new Error(e);
    }
  }
  

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    try{
      let messages = await db.query(`
      SELECT body, id, read_at, sent_at, to_username
      FROM messages
      WHERE from_username = $1`, [username]);
      for (let message of messages.rows){
        let user = await db.query(`
        SELECT first_name, last_name, phone, username
        FROM users WHERE username = $1
        `, [message.to_username]);
        user = user.rows[0];
        message.to_user = user;
        delete message.to_username;
      }
      return messages.rows;
    }
    catch (e){
      throw new Error(e);
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    try{
      let messages = await db.query(`
      SELECT body, id, read_at, sent_at, from_username
      FROM messages
      WHERE to_username = $1`, [username]);
      for (let message of messages.rows){
        let user = await db.query(`
        SELECT first_name, last_name, phone, username
        FROM users WHERE username = $1
        `, [message.from_username]);
        user = user.rows[0];
        message.from_user = user;
        delete message.from_username;
      }
      return messages.rows;
    }
    catch (e){
      throw new Error(e);
    }
  }
}


module.exports = User;