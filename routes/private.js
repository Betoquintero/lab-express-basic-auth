const express = require("express");
const router = express.Router();
const User = require("../models/User");
const isLoggedIn = require("../middlewares");


router.get("/", isLoggedIn, (req, res, next) => {
  res.render("private");
});

module.exports = router;