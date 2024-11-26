const Category = require('../models/Category');
const Product = require ('../models/Product');
// Create a new category
const createCategory = async (req, res) => {
    try {
        const { name,description,image } = req.body;
        const category = new Category({
            name,description,image: req.file.path
        });
        await category.save();
        res.status(201).json(category);
    } catch (error) {
        console.log(error.message)
        res.status(500).json({ error: 'Failed to create category' });
    }
};

const deleteCategory = async (req, res) => {
    try {
        const categoryId = req.params.id;
    
        // Find the category to ensure it exists
        const category = await Category.findById(categoryId);
        if (!category) return res.status(404).json({ error: 'Category not found' });
    
        // Delete all products with this category
        await Product.deleteMany({ category: categoryId });
    
        // Delete the category
        await Category.findByIdAndDelete(categoryId);
    
        res.status(200).json({ message: 'Category and related products deleted successfully' });
      } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: error.message });
      }
};

const getAllCategories = async (req, res) => {
    try {
        const categories = await Category.find();
        res.status(200).json(categories);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get categories' });
    }
};

const getCategoryById = async (req, res) => {
    try {
        const { name } = req.params;
        const category = await Category.findOne({name});
        res.status(200).json(category);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get category' });
    }
};
module.exports = {
    createCategory,
    deleteCategory,
    getAllCategories,
    getCategoryById
};