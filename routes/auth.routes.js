const mongoose = require('mongoose')
const { Router } = require('express');
const User = require('../models/User.model');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const salt = bcryptjs.genSaltSync(saltRounds);


/* ----------------------- GET SIGN UP -------------------------------*/

router.get('/sign-up', (req, res,) => 
  res.render('sign-up'));


/* -----------------------POST SIGN UP -------------------------------*/

router.post('/sign-up', (req, res, next) => {
  
  const {username, password} = req.body;
  console.log('The form data: ', req.body)
  
  if (!username || !password) {
    res.render('sign-up', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('sign-up', { errorMessage: 'Password needs to have at least 6 characters and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }
  const hashedPassword = bcryptjs.hashSync(password, salt);
  console.log(`Password hash: ${hashedPassword}`);
  
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username, password: hashedPassword
      })
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect('/');
  })
  .catch(error => {
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(500).render('sign-up', { errorMessage: error.message });
    } else if (error.code === 11000) {
      res.status(500).render('sign-up', {
         errorMessage: 'Username and email need to be unique. Either username or email is already used.'
      });
    } else {
      next(error);
    }
  }); 
});

/* ------------------------ GET Log In ------------------------- */

router.get('/login', (req, res, next) => 
     res.render('login'));

/* ------------------------ POST Log In ------------------------- */

router.post('/login', (req, res, next) => {
  //console.log('SESSION =====> ', req.session);
  const { username, password } = req.body;
  if (username === '' || password === '') {
    res.render('login', {
      errorMessage: 'Please enter email and password to login.'
    });
    return;
  }
  //const hashedPassword = bcryptjs.hashSync(password, salt);
  User.findOne({ username })
    .then(user => {
     
      if (!user) {
        return res.render('index', { errorMessage: 'Cannot find username' });
      } else if (bcryptjs.compareSync(password, user.password)) {
        return req.session.currentUser = user;
      } else {
        res.render('index', { errorMessage: 'Incorrect password' });
      }
      return;
    })
    .then(()=>{
      console.log("User logged-in:");
      console.log(req.session.currentUser);
      // res.render('user-profile', { user });
      return res.redirect('/userProfile');
    })
    .catch(error => 
    next(error));
});

/* ------------------------ POST Log Out ------------------------- */

router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;
