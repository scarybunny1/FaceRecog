const express = require('express');
const router = express.Router();


const jwtVerify = require('../config/jwtHelper');
const passport = require('passport');
const ctrlUser = require('../controllers/user.controller');
const _ = require('lodash');


router.post('/register', ctrlUser.register);
 
router.post('/login', ctrlUser.authenticate);

router.post('/forgot', ctrlUser.forgot);

router.get('/reset/:token', ctrlUser.reset);
router.post('/reset/:token', ctrlUser.resetPassword);

router.get('/user-profile', jwtVerify.verifyJwtToken, ctrlUser.userProfile);




module.exports = router;
