const {Router} = require('express');
const brandController = require('../controllers/brandController')
const router = Router();
const multer = require('multer')
//multer starts here
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './uploads/brands')
    },
    filename: function (req, file, cb) {
        cb(null,Date.now() + '-' + file.originalname);
    }
  });
  const upload = multer({ storage: storage });
  //multer ends here
router.post('/brand/create',upload.single('image'),brandController.createBrand);
router.delete('/brand/delete/:id',brandController.deleteBrand);
router.get('/getAllBrands',brandController.getAllBrands);
router.get('/brand/:id',brandController.getBrandById);

module.exports=router;
