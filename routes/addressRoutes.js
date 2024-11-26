const {Router} = require('express');
const addressController = require('../controllers/addressController')
const router = Router();
router.post('/address/create',addressController.createAddress);
router.delete('/address/delete/:addressId',addressController.deleteAddress);
router.get('/address/:userId',addressController.getAllUserAddressByUserId);
router.get('/defaultAddress/:userId',addressController.getDefaultAddressByUserId);
router.post('/setDefaultAddress/',addressController.setDefaultAddress);
module.exports=router;

