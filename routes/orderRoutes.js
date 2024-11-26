const {Router} = require('express');
const orderController = require('../controllers/orderController')
const router = Router();
router.post('/order/create',orderController.createOrder);
router.get('/order/:userId',orderController.getOrderByUserId);
router.get('/orders',orderController.getAllOrders);
router.get('/bestSeller',orderController.getBestSeller);
//admin side routes
router.get('/totalSales',orderController.getTotalSales);
router.get('/totalOrders',orderController.getTotalOrders);
router.get('/totalOrdersByStatus',orderController.getTotalOrdersByStatus);
router.get('/salesOverviewByMonth',orderController.getSalesOverviewByMonth);
router.get('/salesOverviewByWeek',orderController.getSalesOverviewByWeek);
router.get('/topProductsBySales',orderController.getTopProductsBySales);
module.exports = router;
