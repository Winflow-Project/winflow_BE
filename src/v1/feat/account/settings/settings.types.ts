export interface ISettings {
  //   loginMethods: LoginMethods[];
  multifactorAuth: MultifactorAuth;
}

export interface MultifactorAuth {
  isEnabled: boolean;
  methods: MultifactorAuthMethods[];
}

export interface MultifactorAuthMethods {
  type: MultifactorAuthMethodType;
  isEnabled: boolean;
}

export enum MultifactorAuthMethodType {
  EMAIL = 'email',
  SMS = 'sms',
  AUTHENTICATOR = 'authenticator',
}
