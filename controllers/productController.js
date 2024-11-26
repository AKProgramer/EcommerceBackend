const Product = require('../models/Product')
const Category = require('../models/Category');
const Brand = require('../models/Brand');
module.exports.createProduct = async (req, res) => {
    try {
      const { name, price, description, category: categoryName, stock, brand } = req.body;
      const selectedCategory = await Category.findOne({ name: categoryName });
      if (!selectedCategory) throw new Error("Category not found!");
  
      const selectedBrand = await Brand.findOne({ name: brand });
      if (!selectedBrand) throw new Error("Brand not found!");
  
      const product = await Product.create({
        name,
        price,
        images: req.files.map(file => file.path),
        description,
        category: selectedCategory._id,
        stock,
        brand: selectedBrand._id,
      });
  
      res.status(201).json({ product });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: error.message });
    }
  };
module.exports.updateProductByName=async (req,res)=>{
    try
    {
        const {name, price, description, category : categoryName, stock} = req.body;
        const {name : preName} = req.params;
        const preProduct = Product.findOneAndUpdate({name : preName},{name, price, description,categoryName, stock});
         res.status(201).json({preProduct});
    }
    catch(error)
    {
        console.log(error.message);
        res.status(500).json(error.message);
    }
}
module.exports.deleteProductById=async (req,res)=>{
    try{
        const { id } = req.params;
       const deletedProduct = await Product.findOneAndDelete({_id : id})
       if (!deletedProduct) {
        return res.status(404).json({ error: 'Product not found' });
        }
        res.status(200).json(deletedProduct);
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to delete product', message: error.message });
    }
}
module.exports.getProductByName=async(req,res)=>{
    try
    {
        const {name} = req.params;
        const product =await Product.findOne({name});
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.status(200).json(product);
    }
    catch (error) {
        
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
    
}
module.exports.getProductsByCategoryName= async (req, res) => {
    const { category : categoryName } = req.params;
  
    try {
        const category = await Category.findOne({ name: categoryName });
  
        if (!category) {
            return res.status(404).json({ message: 'Category not found' });
      }
  
      const products = await Product.find({ category: category._id }).populate('category');
      res.status(200).json(products);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
module.exports.getAllProductsOnQuery=async (req,res) => {
    const searchQuery=req.query.q;
    try{
        let products=null;
        if(searchQuery)
        {
            products = await Product.find({
                name: new RegExp(searchQuery,'i') // Case-insensitive search
            }).populate('category');
            res.status(200).json(products);
        }
        else{
                products =await Product.find();
            res.status(200).json(products);
        }
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch products' });
    }

}
module.exports.getNewArrivals=async (req,res)=>{
    try{
        const products = await Product.find().sort({createdAt : -1}).limit(10).populate('category');
        res.status(200).json(products);
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
}
module.exports.getTotalProducts=async (req,res)=>{
    try{
        const count = await Product.countDocuments();
        res.status(200).json({count});
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
}
module.exports.getTotalCategories=async (req,res)=>{
    try{
        const count = await Category.countDocuments();
        res.status(200).json({count});
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
}
module.exports.getAllProducts=async (req,res)=>{
    try{
        const products = await Product.find().populate('category');
        res.status(200).json(products);
    }
    catch(error)
    {
        console.error(error.message);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
}

    
    
    