const jwt = require("express-jwt");
const secret = require("../../config/jwt").secret;

function getTokenFromHeader(req) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.split(" ")[0] === "Bearer") {
    return authHeader.split(" ")[1];
  }

  return null;
}

module.exports = {
  required: jwt({
    secret: secret,
    userProperty: "user",
    getToken: getTokenFromHeader
  })
};
