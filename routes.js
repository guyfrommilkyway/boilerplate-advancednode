const passport = require('passport');
const bcrypt = require('bcrypt');

module.exports = function (app, myDataBase) {
	function ensureAuthenticated(req, res, next) {
		if (req.isAuthenticated()) {
			return next();
		}

		res.redirect('/');
	}

	// Be sure to change the title
	app.route('/').get((req, res) => {
		// Change the response to render the Pug template
		res.render('index', {
			title: 'Connected to Database',
			message: 'Please login',
			showLogin: true,
			showRegistration: true,
			showSocialAuth: true,
		});
	});

	app.route('/profile').get(ensureAuthenticated, (req, res) => {
		res.render('profile', {
			username: req.user.username,
		});
	});

	app.post(
		'/login',
		passport.authenticate('local', { failureRedirect: '/' }),
		(req, res) => {
			res.redirect('/profile');
		}
	);

	app.get('/logout', (req, res) => {
		req.logout();
		res.redirect('/');
	});

	app.route('/register').post(
		(req, res, next) => {
			myDataBase.findOne({ username: req.body.username }, (err, user) => {
				if (err) {
					next(err);
				} else if (user) {
					res.redirect('/');
				} else {
					myDataBase.insertOne(
						{
							username: req.body.username,
							password: bcrypt.hashSync(req.body.password, 12),
						},
						(err, doc) => {
							if (err) {
								res.redirect('/');
							} else {
								next(null, doc.ops[0]);
							}
						}
					);
				}
			});
		},
		passport.authenticate('local', { failureRedirect: '/' }),
		(req, res) => {
			res.redirect('/profile');
		}
	);

	app.route('/auth/github').get(passport.authenticate('github'));

	app.get(
		'/auth/github/callback',
		passport.authenticate('github', { failureRedirect: '/' }),
		(req, res) => {
			res.redirect('/profile');
		}
	);

	app.use((req, res, next) => {
		res.status(404).type('text').send('Not Found');
	});
};
