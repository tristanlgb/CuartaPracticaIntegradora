const { userService } = require('../services');

class UserController {
 

    changeUserRole = async (req, res) => {
        const { uid } = req.params;
        const user = await userService.getUser({ _id: uid });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.role = user.role === 'user' ? 'premium' : 'user';
        await user.save();

        res.status(200).json({ message: `User role changed to ${user.role}`, user });
    }
}

module.exports = new UserController();