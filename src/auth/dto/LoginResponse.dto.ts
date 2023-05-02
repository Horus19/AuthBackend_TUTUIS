interface LoginResponseInvalid {
  ok: false;
  message: string;
}

interface LoginResponseSuccess {
  ok: true;
  id: string;
  email: string;
  fullName: string;
  isActivate: boolean;
  roles: string[];
  validationToken: string;
  isBlocked: boolean;
  token: string;
}

type LoginResponse = LoginResponseInvalid | LoginResponseSuccess;
