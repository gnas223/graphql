import { RegisterInput } from "../types/RegisterInput";

export const validateRegisterInput = (registerInput: RegisterInput) => {
  if (!registerInput.email.includes("@")) {
    return {
      message: "Invalid email",
      error: [
        {
          field: "email",
          message: "Email must include @",
        },
      ],
    };
  }

  if (registerInput.username.length <= 2)
    return {
      message: "Invalid username",
      error: [{ field: "username", message: "Length must be greater than 2" }],
    };

  if (registerInput.username.includes("@")) {
    return {
      message: "Invalid username",
      error: [{ field: "username", message: "username cannot include @" }],
    };
  }

  if (registerInput.password.length <= 2)
    return {
      message: "Invalid password",
      error: [{ field: "password", message: "Length must be greater than 2" }],
    };

  return null;
};
