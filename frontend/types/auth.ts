export type AuthActionState = {
  kind: "idle" | "error" | "success";
  message: string;
};

export const initialAuthActionState: AuthActionState = {
  kind: "idle",
  message: "",
};

export type AuthServerAction = (
  previousState: AuthActionState,
  formData: FormData,
) => Promise<AuthActionState>;
