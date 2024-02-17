'use strict';
require('dotenv').config();
const express = require('express');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const passportSocketIo = require('passport.socketio');
const MongoStore = require('connect-mongo')(session);
const store = new MongoStore({ url: process.env.MONGO_URI });

const routes = require('./routes.js');
const auth = require('./auth.js');

const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set('view engine', 'pug');
app.set('views', './views/pug');

app.use(
	session({
		key: 'express.sid',
		secret: process.env.SESSION_SECRET,
		resave: true,
		saveUninitialized: true,
		cookie: { secure: false },
		store,
	})
);

function onAuthorizeSuccess(data, accept) {
	console.log('successful connection to socket.io');

	accept(null, true);
}

function onAuthorizeFail(data, message, error, accept) {
	if (error) throw new Error(message);
	console.log('failed connection to socket.io:', message);
	accept(null, false);
}

io.use(
	passportSocketIo.authorize({
		cookieParser,
		key: 'express.sid',
		secret: process.env.SESSION_SECRET,
		store,
		success: onAuthorizeSuccess,
		fail: onAuthorizeFail,
	})
);

myDB(async (client) => {
	const myDataBase = await client.db('database').collection('users');

	auth(app, myDataBase);
	routes(app, myDataBase);

	let currentUsers = 0;

	io.on('connection', (socket) => {
		++currentUsers;

		io.emit('user count', currentUsers);

		console.log('A user has connected');

		socket.on('disconnect', () => {
			console.log('A user has disconnected');

			--currentUsers;

			io.emit('user count', currentUsers);
		});
	});
}).catch((e) => {
	app.route('/').get((req, res) => {
		res.render('index', { title: e, message: 'Unable to connect to database' });
	});
});

const PORT = process.env.PORT || 3000;

http.listen(PORT, () => {
	console.log('Listening on port ' + PORT);
});
