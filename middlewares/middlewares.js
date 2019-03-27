const jwt = require("jsonwebtoken");

const User = require("../users/userModel");
const config = require("../config");

const authenticate = async (req, res, next) => {
	const token = req.get("Authorization");
	const username = req.get("username");
	const password = req.get("password");
	try {
		if (token) {
			token = token.replace("Bearer ", "");
			jwt.verify(token, config.secret, (err, decoded) => {
				if (err) return res.status(422).json(err);
				req.decoded = decoded;
				next();
			});
		} else if (username && password) {
			const user = await User.findOne({ username });
			if (user && user.validatePassword(password)) {
				req.decoded = {
					username: user.username,
					id: user._id
				};
				next();
			} else {
				res.status(422).json({ error: "Invalid Credentials." });
			}
		} else {
			console.log("Repelled Invader", token);
			return res.status(403).json({
				error: "You're not allowed in here!"
			});
		}
	} catch {
		res.status(500).json("Encountered an error.");
	}
};

module.exports = {
	authenticate
};
