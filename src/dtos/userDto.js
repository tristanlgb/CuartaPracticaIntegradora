class UserDto {
  constructor(user) {
    this.firstname = user.firstname;
    this.lastname = user.lastname;
    this.email = user.email;
    this.password = user.password;
    this.fullname = user.fullname;
  }
}

module.exports = UserDto;
