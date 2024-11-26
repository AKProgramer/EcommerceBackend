const Address = require('../models/Address');
const User = require('../models/User');
const mongoose = require('mongoose');
const createAddress = async (req, res) => {
    try {
        const { userId, fullName, mobileNumber, province, city, area, address, landmark, label, isDefault} = req.body;
        const user = await User.find({_id : userId});
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if(isDefault){
            await Address.updateMany({ userId: userId }, { isDefault: false });
        }
        const newAddress = new Address({
           userId, fullName, mobileNumber, province, city, area, address, landmark, label, isDefault
        });
        await newAddress.save();
        res.status(201).json('Address created successfully');
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to create address' });
    }
};
const deleteAddress = async (req, res) => {
    try {
        const { addressId } = req.params;
        // Ensure addressId is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(addressId)) {
            return res.status(400).json({ error: 'Invalid addressId' });
        }
        // Find the address by addressId
        const address = await Address.findById(addressId);
        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }
        await address.deleteOne();
        res.status(200).json({ message: 'Address deleted successfully' });
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to delete address' });
    }
}

const getAllUserAddressByUserId = async (req, res) => {
    try {
        const { userId } = req.params;
        console.log("userId", userId);

        // Ensure userId is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Invalid userId' });
        }

        // Querying by userId to get all addresses
        const addresses = await Address.find({ userId: new mongoose.Types.ObjectId(userId) });

        if (!addresses.length) {
            return res.status(200).json(addresses);
        }
        res.status(200).json(addresses);
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to get addresses' });
    }
};

const getDefaultAddressByUserId = async (req, res) => {
    console.log("getDefaultAddressByUserId");
    try {
        const { userId } = req.params;
        console.log("userId", userId);
        const address = await Address
            .find({userId :  new mongoose.Types.ObjectId(userId)})
        if (!address) {
            return res.status(404).json({ error: 'User not found' });
        }
        const defaultAddress = address.find(address => address.isDefault);
        if (!defaultAddress) {
            return res.status(200).json('');
        }
        res.status(200).json(defaultAddress);
    }
    catch (error) {
        console.log("error", error);
        console.log(error.message);
        res.status(500).json({ error: 'Failed to get default address' });
    }
}
const setDefaultAddress = async (req, res) => {
    try {
        const { userId, addressId } = req.query;
            console.log(userId, addressId);
        // Ensure userId and addressId are valid Objec tId
        if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(addressId)) {
            return res.status(400).json({ error: 'Invalid userId or addressId' });
        }
        // Find the user by userId
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        // Find the address by addressId
        const address = await Address.findOne({ _id: addressId, userId: userId });
        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }
        // Unset the default address for all addresses of the user
        await Address.updateMany({ userId: userId }, { isDefault: false });

        // Set the specified address as the default
        address.isDefault = true;
        await address.save();

        res.status(200).json({ message: 'Default address set successfully' });
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to set default address' });
    }
};
module.exports = {
    createAddress,
    getAllUserAddressByUserId,
    getDefaultAddressByUserId,
    setDefaultAddress,
    deleteAddress
};