import { sign, verify, SignOptions, VerifyOptions } from "jsonwebtoken";

export interface SSIClientOptions {
  url?: string;
  name?: string;
}

export type SSIData = Record<string, string | number | boolean | null>;

export type SSIFunction = "verify" | "issue";

enum ResponseStatus {
  success = "succes",
  error = "error",
  cancelled = "cancelled",
}

export interface CredentialResponse {
  requestId: string;
  type: string;
  status: ResponseStatus;
  connector: string;
}

export interface CredentialVerifyResponse extends CredentialResponse {
  data: SSIData;
}

export type CredentialIssueResponse = CredentialResponse;

export default class SSIClient {
  private url = "https://ssi-provider.sensorlab.tno.nl/";
  private name = "ssi-service-provider";

  constructor(
    private clientId: string,
    private clientSecret: string,
    options?: SSIClientOptions
  ) {
    if (!options) {
      return;
    }

    if (options.url) {
      this.url = options.url;
    }

    if (options.name) {
      this.name = options.name;
    }
  }

  verifyUrl(type: string, requestId: string): string {
    const token = this.encodeJWT(
      { type },
      { subject: "credential-verify-request", jwtid: requestId }
    );
    return this.constructRequestUrl("verify", token);
  }

  issueUrl(type: string, data: SSIData, requestId: string): string {
    const token = this.encodeJWT(
      { type, data },
      { subject: "credential-issue-request", jwtid: requestId }
    );
    return this.constructRequestUrl("issue", token);
  }

  parseVerifyResponse(token: string): CredentialVerifyResponse {
    const response = this.decodeJWT(token, {
      subject: "credential-verify-response",
    }) as any;
    return {
      type: response.type,
      data: response.data,
      status: response.status,
      connector: response.connector,
      requestId: response.requestId,
    };
  }

  parseIssueResponse(token: string): CredentialIssueResponse {
    const response = this.decodeJWT(token, {
      subject: "credential-issue-response",
    }) as any;

    return {
      type: response.type,
      status: response.status,
      connector: response.connector,
      requestId: response.requestId,
    };
  }

  private constructRequestUrl(endpoint: SSIFunction, token: string) {
    const url = new URL(endpoint, this.url);
    url.search = `?token=${token}`;
    return url.toString();
  }

  private encodeJWT(
    payload: Record<string, unknown>,
    signOptions?: SignOptions
  ) {
    return sign(payload, this.clientSecret, {
      issuer: this.clientId,
      audience: this.name,
      ...signOptions,
    });
  }

  private decodeJWT(token: string, verifyOptions?: VerifyOptions) {
    // Payload cannot be a string due to the verify options passed.
    const payload = verify(token, this.clientSecret, {
      issuer: this.name,
      audience: this.clientId,
      ...verifyOptions,
    }) as Record<string, unknown>;

    return payload;
  }
}
