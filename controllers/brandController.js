const Brand = require('../models/Brand');
const Product = require('../models/Product');
// Create a new Brand
const createBrand = async (req, res) => {
    try {
        const { name,description, image } = req.body;
        const brand = new Brand({
            name,description,image: req.file.path
        });
        await brand.save();
        res.status(201).json(brand);
    } catch (error) {
        console.log(error.message)
        res.status(500).json({ error: 'Failed to create brand' });
    }
};

const deleteBrand = async (req, res) => {
    try {
      const { id } = req.params;
  
      // Check if the brand exists
      const brand = await Brand.findById(id);
      if (!brand) return res.status(404).json({ error: 'Brand not found' });
  
      
      await Product.deleteMany({ brand: id });
  
      await Brand.findByIdAndDelete(id);
  
      res.status(200).json({ message: 'Brand and related products deleted successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Failed to delete brand and related products' });
    }
  };

const getAllBrands = async (req, res) => {
    try {
        const brands = await Brand.find();
        res.status(200).json(brands);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get brands' });
    }
};

const getBrandById = async (req, res) => {
    try {
        const { id } = req.params;
        const brand = await Brand.findOne({_id : id});
        res.status(200).json(brand);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get category' });
    }
};
module.exports = {
    createBrand,
    deleteBrand,
    getAllBrands,
    getBrandById
};