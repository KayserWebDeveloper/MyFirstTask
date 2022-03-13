const jwt = require("jsonwebtoken");

function jwtGenerator(email) {
  const payload = {
    user: email
  };
  const access_token = jwt.sign(payload, "cat123");
  return access_token;
}

module.exports =  jwtGenerator
