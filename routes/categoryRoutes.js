const {Router} = require('express');
const categoryController = require('../controllers/categoryController')
const router = Router();
const multer = require('multer')
//multer starts here
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './uploads/categories')
    },
    filename: function (req, file, cb) {
        cb(null,Date.now() + '-' + file.originalname);
    }
  });
  const upload = multer({ storage: storage });
  //multer ends here
router.post('/category/create',upload.single('image'),categoryController.createCategory);
router.delete('/category/delete/:id',categoryController.deleteCategory);
router.get('/getAllCategories',categoryController.getAllCategories);
router.get('/category/:name',categoryController.getCategoryById);

module.exports=router;
