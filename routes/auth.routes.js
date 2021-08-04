const { Router } = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('../models/User.model');

// .get() route ==> to display the signup form to users
router.get('/sign-up', (req, res) => res.render('sign-up'));

// .post() route ==> to process form data

router.post('/sign-up', (req, res, next) => {
  const { username, password } = req.body;
   
    if (!username || !password) {
      res.render('sign-up', { errorMessage: 'All fields are mandatory. Please provide your username and password.' });
      return;
    }
    

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        passwordHash: hashedPassword
      });
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect('/user-profile');
    })
    .catch(error => next(error));
});

router.get('/login', (req, res) => res.render('login'));

router.post('/login', (req,res, next) => {
const {username, password} = req.body;
    if (!username || !password) {
        res.render('login', { errorMessage: 'All fields are mandatory. Please provide username and password' });
        return;
    }
    
    User.findOne({username})
        .then((userFromDB)=> {
            if (userFromDB) {
                if (bcryptjs.compareSync(password, userFromDB.passwordHash)) {
                    req.session.currentUser = userFromDB;
                    res.render('user-profile', {userFromDB, logIn: true});
                } else {
                    res.render('login', {errorMessage: 'Username and password do not match.'});
                }

            }
        })
        .catch(err => next(err))
});


router.get('/user-profile', (req, res) => res.render('user-profile'));


router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});



router.get('/main', (req,res) => {
  res.render('main')
});

module.exports = router;