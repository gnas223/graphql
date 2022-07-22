import { User } from "../entities/User";
import { Arg, Mutation, Resolver } from "type-graphql";
import argon2 from "argon2";
import { UserMutationResponse } from "../types/UserMutationResponse";
import { RegisterInput } from "../types/RegisterInput";
import { LoginInput } from "../types/LoginInput";
import { validateRegisterInput } from "../utils/validateRegisterInput";

@Resolver()
export class UserResolver {
  @Mutation((_return) => UserMutationResponse)
  async register(
    @Arg("registerInput") registerInput: RegisterInput
  ): Promise<UserMutationResponse> {
    const validateRegisterInputError = validateRegisterInput(registerInput);
    if (validateRegisterInputError !== null)
      return {
        code: 400,
        success: false,
        ...validateRegisterInputError,
      };
    try {
      const { username, email, password } = registerInput;
      const existingUser = await User.findOne({
        where: [{ username }, { email }],
      });
      if (existingUser)
        return {
          code: 400,
          success: false,
          message: "Duplicated username or email",
          errors: [
            {
              field: existingUser.username === username ? "username" : "email",
              message: "username or email already!!",
            },
          ],
        };

      const hashedPassword = await argon2.hash(password);

      const newUser = User.create({
        username,
        password: hashedPassword,
        email,
      });
      return {
        code: 200,
        success: true,
        message: "user registration successful",
        user: await User.save(newUser),
      };
    } catch (error) {
      return {
        code: 400,
        success: false,
        message: `Internal server error ${error}`,
      };
    }
  }

  @Mutation((_return) => UserMutationResponse)
  async login(
    @Arg("loginInput") { usernameOrEmail, password }: LoginInput
  ): Promise<UserMutationResponse> {
    try {
      const existingUser = await User.findOne({
        where: usernameOrEmail.includes("@")
          ? { email: usernameOrEmail }
          : { username: usernameOrEmail },
      });
      if (!existingUser)
        return {
          code: 400,
          success: false,
          message: `User not found`,
          errors: [
            {
              field: "usernameOrEmail",
              message: "username or email incorrect",
            },
          ],
        };
      const passwordValid = await argon2.verify(
        existingUser.password,
        password
      );
      if (!passwordValid) {
        return {
          code: 400,
          success: false,
          message: `wrong password`,
          errors: [{ field: "password", message: "wrong password" }],
        };
      }

      return {
        code: 200,
        success: true,
        message: "log in successfully",
        user: existingUser,
      };
    } catch (error) {
      return {
        code: 400,
        success: false,
        message: `Internal server error ${error}`,
      };
    }
  }
}
