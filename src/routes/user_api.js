const express = require("express");
const router = express.Router();
const handleAsyncError = require("express-async-wrap");
const userHandler = require("../handler/user_handler");

router.post("/signup", handleAsyncError(userHandler.registerNewUser));
router.post("/login", handleAsyncError(userHandler.login));

module.exports = router;
