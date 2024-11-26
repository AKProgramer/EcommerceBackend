const {Router} = require('express');
const authController = require('../controllers/authController')
const passport = require('passport');
const multer = require('multer');
const router = Router();
//multer starts here
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './uploads/users')
    },
    filename: function (req, file, cb) {
        cb(null,Date.now() + '-' + file.originalname);
    }
  });
  const upload = multer({ storage: storage });
//multer ends here
//auth routes
router.post('/login', authController.login_post);
router.post('/signup', authController.signup_post);
router.post('/upload/image',upload.single('image'),authController.upload_image);
router.get('/user/:userId', authController.get_user_by_id);
//google auth routes
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/auth/google/callback',passport.authenticate('google', { failureRedirect: '/login' }),authController.google_auth_callback);
//admin side routes
router.get('/totalUserCount', authController.getTotalUserCount);
router.get('/getAllUsers', authController.getAllUsers);
router.delete('/user/delete/:userId', authController.deleteUser);
module.exports = router;