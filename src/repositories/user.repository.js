
const UserDto = require('../dtos/userDto');

class UserRepository {
    constructor() {
        this.userDao = UserDao;
    }

    async getUsers() {
        const users = await this.userDao.getAll();
        return users.map(user => new UserDto(user));
    }

    async getUser(filter) {
        const user = await this.userDao.getBy(filter);
        return new UserDto(user);
    }

    async createUser(user) {
        const newUser = await this.userDao.create(user);
        return new UserDto(newUser);
    }

    async updateUser(uid, userToUpdate) {
        const updatedUser = await this.userDao.update(uid, userToUpdate);
        return new UserDto(updatedUser);
    }

    async deleteUser(uid) {
        await this.userDao.delete(uid);
        return { message: 'User deleted successfully' };
    }
}

module.exports = UserRepository;