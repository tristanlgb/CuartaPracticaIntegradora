import { userModel } from "./models/user.model.js";

export class UsersDaoMongo {
    constructor() {
        this.userModel = userModel;
    }

    async getAll() {
        return await this.userModel.find();
    }

    async create(newUser) {
        return await this.userModel.create(newUser);
    }

    async getBy(filter) {
        return await this.userModel.findOne(filter);
    }

    async update(uid, userToUpdate) {
        return await this.userModel.findByIdAndUpdate({ _id: uid }, userToUpdate);
    }

    async delete(uid) {
        return await this.userModel.findByIdAndDelete({ _id: uid });
    }
}