const User = require("../model/user");
const status = require("http-status");

async function registerNewUser(req, res) {
  var user = new User();

  user.username = req.body.user.username;
  user.email = req.body.user.email;
  user.setPassword(req.body.user.password);

  await user.save();
  return res.json({ user: { username: user.username, email: user.email } });
}

async function login(req, res) {
  const email = req.body.user.email;
  const password = req.body.user.password;

  let user = await User.findOne({ email: email });
  if (!user || !user.validPassword(password)) {
    return res.status(status.UNAUTHORIZED).json({
      error: { message: "email or password is invalid" }
    });
  }

  const token = user.generateJWT();
  return res.json({
    user: { username: user.username, email: user.email, token: token }
  });
}

module.exports = {
  registerNewUser,
  login
};
