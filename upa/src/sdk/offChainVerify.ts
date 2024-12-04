import { jsonPostRequest } from "./offChainClient";
import { AppVkProofInputs } from "./application";

export type VerifyRequestProofType = "groth16";
export type VerifyRequestData = AppVkProofInputs[];

export class VerifyRequest {
  public readonly proof_type: VerifyRequestProofType;
  public readonly data: VerifyRequestData;

  // For now, just assemble from AppVkProofInputs
  constructor(data: AppVkProofInputs[]) {
    this.proof_type = "groth16";
    this.data = data;
  }
}

export class VerifierClient {
  constructor(public readonly url: string) {}

  public async verify(data: AppVkProofInputs[]): Promise<boolean> {
    const request = new VerifyRequest(data);
    const response = await jsonPostRequest(this.url, request);

    if (typeof response !== "boolean") {
      throw (
        `Unexpected response type: {typeof response}\n` +
        `{JSON.stringify(response)}`
      );
    }

    return response;
  }
}
