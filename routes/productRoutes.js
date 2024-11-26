const {Router} = require('express');
const productController = require('../controllers/productController')
const multer = require('multer')
const router = Router();
//multer starts here
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './uploads/products')
    },
    filename: function (req, file, cb) {
        cb(null,Date.now() + '-' + file.originalname);
    }
  });
  const upload = multer({ storage: storage });
//multer ends here
router.post('/product/create',upload.array('images',10) ,productController.createProduct);
//error in this api
router.put('/product/update/:name',upload.single('images'), productController.updateProductByName);
router.delete('/product/delete/:id',productController.deleteProductById);
router.get('/products',productController.getAllProductsOnQuery);
router.get('/product/:name',productController.getProductByName);
router.get('/product/category/:category',productController.getProductsByCategoryName);
router.get('/newArrivals',productController.getNewArrivals);
//admin side routes
router.get('/totalProducts',productController.getTotalProducts);
router.get('/totalCategories',productController.getTotalCategories);
router.get('/getAllProducts',productController.getAllProducts);


module.exports=router;
