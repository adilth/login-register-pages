const LocalStregy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

function initialize(passport, getUserByEmail, getUserById) {
  const authenticateUser = async (email, password, dane) => {
    const user = getUserByEmail(email);
    if (user == null) {
      return dane(null, false, { message: "no user with that email" });
    }
    try {
      if (await bcrypt.compare(password, user.password)) {
        return dane(null, user);
      } else {
        return dane(user, false, { message: "Password mismatch" });
      }
    } catch (e) {
      return dane(e);
    }
  };
  passport.use(new LocalStregy({ usernameField: "email" }, authenticateUser));
  passport.serializeUser((user, dane) => dane(null, user.id));
  passport.deserializeUser((id, dane) => {
    return dane(null, getUserById(id));
  });
}

module.exports = initialize;
