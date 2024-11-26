const Order=require('../models/Order');
const Product=require('../models/Product');
const moment = require('moment');
module.exports.createOrder=(req,res)=>{
    
    const {addressId, items,email, totalCost, status, paymentMethod}=req.body;
    console.log(req.body)
    const order=new Order({
        addressId,
        items,
        email,
        totalCost,
        status,
        paymentMethod
    });
    order.save()
    .then(order=>{
        res.status(201).json({order})
    })
    .catch(err=>{
        res.status(400).json({error:err})
    })
}
module.exports.getOrderByUserId=(req,res)=>{
    const {userId}=req.params;
    Order.find({userId})
    .then(orders=>{
        res.status(200).json({orders})
    })
    .catch(err=>{
        res.status(400).json({error:err})
    })
}
module.exports.getAllOrders = async (req, res) => {
  try {
    // Retrieve orders and populate necessary fields
    const orders = await Order.find()
      .populate('addressId', 'province city area fullName');

    // Extract necessary information from the orders
    const necessaryInfo = orders.map(order => ({
      username: order.addressId.fullName,
      address: `${order.addressId.area}, ${order.addressId.city}, ${order.addressId.province}`,
      totalCost: order.totalCost,
      status : order.status,
      date: order.createdAt,
      paymentMethod: order.paymentMethod
    }));

    res.status(200).json(necessaryInfo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

module.exports.getBestSeller = async (req, res) => {
    try {
      // Step 1: Aggregate the orders to find the most sold products
      const bestSellers = await Order.aggregate([
        { $unwind: "$items" },
        { 
          $group: { 
            _id: "$items.productId", 
            totalQuantity: { $sum: "$items.quantity" } 
          } 
        },
        { $sort: { totalQuantity: -1 } },
        { $limit: 10 } 
      ]);
      
      // Step 2: Populate the product details
      const bestSellerProducts = await Product.find({ 
        _id: { $in: bestSellers.map(item => item._id) }
      });
  
      res.status(200).json(bestSellerProducts);
    } catch (error) {
      console.error('Error fetching best sellers:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  };
  module.exports.getTotalSales = async (req, res) => {
    try {
      const totalSales = await Order.aggregate([
        { $group: { _id: null, totalSales: { $sum: "$totalCost" } } }
      ]);
      if(totalSales==0)
        {
          return res.status(200).json({ totalSales: 0 });
        }
      res.status(200).json(totalSales[0]);
    } catch (error) {
      console.error('Error fetching total sales:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  }
  module.exports.getTotalOrders = async (req, res) => {
    try {
      const totalOrders = await Order.countDocuments();
      if(totalOrders==0)
      {
        return res.status(200).json({ totalOrders:0 });
      }
      res.status(200).json({ totalOrders });
    } catch (error) {
      console.error('Error fetching total orders:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  }
  module.exports.getTotalOrdersByStatus = async (req, res) => {
    try {
      let allStatuses = ['PENDING', 'CONFIRMED', 'READY', 'CANCELLED'];
  
      const totalOrdersByStatus = await Order.aggregate([
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 }
          }
        },
        {
          $project: {
            _id: 0,
            status: "$_id",
            count: 1
          }
        },
        {
          $addFields: {
            status: {
              $cond: {
                if: { $in: ["$status", allStatuses] },
                then: "$status",
                else: "UNKNOWN"
              }
            }
          }
        }
      ]);
  
      const statusCountMap = totalOrdersByStatus.reduce((acc, { status, count }) => {
        acc[status] = count;
        return acc;
      }, {});
      //allStatuses = ['PEND', 'CONF', 'REF', 'CANC'];
      const result = allStatuses.map(status => ({
        status,
        count: statusCountMap[status] || 0
      }));
      
      res.status(200).json(result);
    } catch (error) {
      console.error('Error fetching total orders by status:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  };
  module.exports.getSalesOverviewByMonth = async (req, res) => {
    try {
      const salesOverviewByMonth = await Order.aggregate([
        {
          $group: {
            _id: { month: { $month: "$createdAt" }, year: { $year: "$createdAt" } },
            totalSales: { $sum: "$totalCost" }
          }
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } }
      ]);
  
      const formattedResults = salesOverviewByMonth.map(item => {
        const month = moment(`${item._id.month}`, 'MM').format('MMMM');
        return {
          month: `${month} ${item._id.year}`,
          totalSales: item.totalSales
        };
      });
  
      res.status(200).json(formattedResults);
    } catch (error) {
      console.error('Error fetching sales overview by month:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  }
  module.exports.getSalesOverviewByWeek = async (req, res) => {
    try {
      const salesOverviewByWeek = await Order.aggregate([
        {
          $group: {
            _id: { week: { $week: "$createdAt" }, year: { $year: "$createdAt" } },
            totalSales: { $sum: "$totalCost" },
            startDate: { $first: "$createdAt" },
            endDate: { $last: "$createdAt" }
          }
        },
        { $sort: { "_id.year": 1, "_id.week": 1 } }
      ]);
  
      const formattedResults = salesOverviewByWeek.map(item => {
        const startDate = moment(item.startDate).format('DD MMM YYYY');
        const endDate = moment(item.endDate).format('DD MMM YYYY');
        return {
          week: `${startDate} - ${endDate}`,
          totalSales: item.totalSales
        };
      });
  
      res.status(200).json(formattedResults);
    } catch (error) {
      console.error('Error fetching sales overview by week:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  };
  module.exports.getTopProductsBySales = async (req, res) => {
    try {
      const topProductsBySales = await Order.aggregate([
        { $unwind: "$items" },
        { 
          $group: { 
            _id: "$items.productId", 
            totalQuantity: { $sum: "$items.quantity" } 
          } 
        },
        { $sort: { totalQuantity: -1 } },
        { $limit: 10 } 
      ]);
  
      const topProducts = await Product.find({ 
        _id: { $in: topProductsBySales.map(item => item._id) }
      });
  
      res.status(200).json(topProducts);
    } catch (error) {
      console.error('Error fetching top products by sales:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
      });
    }
  };