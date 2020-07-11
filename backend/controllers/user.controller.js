const mongoose = require('mongoose');
const passport = require('passport');
const _ = require('lodash');
var async = require("async");
var nodemailer = require("nodemailer");
var crypto = require("crypto");
const appmail = require('../config/appmail')
const User = mongoose.model('user');


module.exports.register = (req,res,next) => {
    var user = new User();
    user.fullName = req.body.fullName;
    user.email = req.body.email;
    user.password = req.body.password;
    user.save((err,doc) => {
        if(!err)
            res.send(doc);
        else{
            if (err.code == 11000)
                res.status(422).send(['Duplicate email address found']);
            else
                return next(err);
        }
        
    });
}
 
module.exports.authenticate = (req, res, next)=> {
    passport.authenticate('local', (err, user, info)=> {
        if (err)
            return res.status(400).json(err);
        else if(user)
            return res.status(200).json({'token': user.generateJwt()});
        else
            return res.status(404).json(info);
    })(req,res);
}

module.exports.userProfile = (req, res, next) => {
    User.findOne({ _id: req._id}, (err, user)=>{
        if(!user)
            return res.status(404).json({status: false, message: 'User record not found'});
        else
            return res.status(200).json({status: true, user: _.pick(user, ['fullName','email','_id'] )});
    })
}

module.exports.forgot = (req, res, next) => {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          console.log(token);
          done(err, token);
        });
      },  
      function(token, done) {
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            console.log("User not found");
            return res.status(404).send(['Email does not exist.']);
          }
            
          user.resetPasswordToken = token;

          console.log(JSON.stringify(user));
  
          user.save(function(err) {
            console.log("saved");
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: 'Gmail', 
          auth: {
            user: appmail.id,
            pass: appmail.password
          }
        });
        var mailOptions = {
          to: user.email,
          from: appmail.id,
          subject: 'FaceRecog Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://localhost:4200/#/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          if(!err) console.log('mail sent');

          done(err, 'done');
        });
      }
    ], function(err) {
      if (err) return next(err);
    });
  };

module.exports.reset = (req, res, next) => {
  User.findOne({resetPasswordToken: req.params.token}, (err, user) => {
    if(!user)
      return res.status(404).send(['Password reset token invalid.']);
    return res.status(200).json({"success":"ok"});
  });
}

module.exports.resetPassword = (req, res, next) => {
  async.waterfall([
    function(done){
      User.findOne({ resetPasswordToken: req.params.token }, function(err, user){
        if(!user)
          return res.status(404).send(['Password RESET TOKEN is invalid.']);
        if(req.body.newPassword === req.body.confirmPassword){
            user.password = req.body.newPassword;
            user.resetPasswordToken = undefined;
            user.save(function(err){
              done(err, user); 
          });
        }
      })
    },
    function(user, done){
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth:  {
          user: appmail.id,
          pass: appmail.password
        }
      });
      var mailOptions = {
        to: user.email,
        from: appmail.id,
        subject: 'Your password has been changed',
        text: 'Hello '+ user.fullName +',\n\n'+'This is a confirmation that the password for your account with '+user.email+' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err){
        done(err);
      });
    }
  ], function(err){
    if(err)
      return next(err);
    return res.status(200).json({"success":"ok"});
  });
}