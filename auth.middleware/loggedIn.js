const LoggedIn = (req, res, next) => {
    if (req.session.currentUser) {
      return next();
    }
    return res.redirect('/login');
  };
  
  module.exports = LoggedIn;