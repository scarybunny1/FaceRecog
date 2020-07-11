const mongoose = require('mongoose');

const passport = require('passport');
const localStrategy = require('passport-local').Strategy;

var User = mongoose.model('user');

passport.use(
    new localStrategy({ usernameField: 'email' },
        (username, password, done) => {
            User.findOne({ email: username },
                (err, user)=> {
                    if (err)
                        return done(err);
                    else if (!user)
                        return done(null, false, { message: 'Email is not registered.' });
                    else if(!user.verifyPassword(password))
                        return done(null, false, { message: 'Wrong Password.' });
                    else
                        return done(null, user);
                });
        })
);
