const {Router} = require('express');
const cartController = require('../controllers/cartController');
const router = Router();

router.post('/cart/add',cartController.addItemToCart);
router.delete('/cart/remove',cartController.removeItemFromCart);
router.delete('/cart/removeAll',cartController.removeAllItemsFromCart);
router.get('/cart/:userId',cartController.getCartByUserId);
router.get('/itemsInCart',cartController.getItemsinCart)

module.exports=router;
