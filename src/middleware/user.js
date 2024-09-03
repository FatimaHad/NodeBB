'use strict';

const winston = require('winston');
const passport = require('passport');
const util = require('util');
const plugins = require('../plugins');
const helpers = require('./helpers');
const auth = require('../routes/authentication');
const writeRouter = require('../routes/write');

const controllers = {
	helpers: require('../controllers/helpers'),
	authentication: require('../controllers/authentication'),
};

// Assuming middleware needs to be declared and used across various functions
const middleware = {};

const passportAuthenticateAsync = (req, res) => new Promise((resolve, reject) => {
	passport.authenticate('core.api', (err, user) => {
		if (err) {
			reject(err);
		} else {
			resolve(user);
			res.on('finish', writeRouter.cleanup.bind(null, req));
		}
	})(req, res);
});

const finishLogin = async (req, user) => {
	const loginAsync = util.promisify(req.login).bind(req);
	await loginAsync(user, { keepSessionInfo: true });
	await controllers.authentication.onSuccessfulLogin(req, user.uid, false);
	req.uid = parseInt(user.uid, 10);
	req.loggedIn = req.uid > 0;
	return true;
};

const handleAuthentication = async (req, res) => {
	if (res.locals.isAPI && (req.loggedIn || !req.headers.hasOwnProperty('authorization'))) {
		await middleware.applyCSRFasync(req, res);
	}

	if (req.loggedIn) return true;

	if (req.headers.hasOwnProperty('authorization')) {
		const user = await passportAuthenticateAsync(req, res);
		if (!user) return true;

		if (user.hasOwnProperty('uid')) {
			return await finishLogin(req, user);
		}
		if (user.hasOwnProperty('master') && user.master === true) {
			if (req.body.hasOwnProperty('_uid') || req.query.hasOwnProperty('_uid')) {
				user.uid = req.body._uid || req.query._uid;
				delete user.master;
				return await finishLogin(req, user);
			}
			throw new Error('[[error:api.master-token-no-uid]]');
		}
		winston.warn('[api/authenticate] Unable to find user after verifying token');
		return true;
	}

	await plugins.hooks.fire('response:middleware.authenticate', { req, res, next: () => {} });
	if (!res.headersSent) {
		auth.setAuthVars(req);
	}
	return !res.headersSent;
};

const shouldSkip = async () => false;// Removed unused 'req' parameter

middleware.authenticateRequest = helpers.try(async (req, res, next) => {
	if (await shouldSkip()) return next();// Adjusted call to `shouldSkip`
	if (!await handleAuthentication(req, res)) return;
	next();
});

// Define any other necessary functions or middleware as needed
