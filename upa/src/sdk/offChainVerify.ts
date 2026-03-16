import { jsonPostRequest } from "./offChainClient";
import { AppVkProofInputs } from "./application";
import { Signature, getAddress, recoverAddress } from "ethers";
import { computeCircuitId, computeProofId, computeSubmissionId } from "./utils";

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

  public async getSignature(data: AppVkProofInputs[]): Promise<Signature> {
    const request = new VerifyRequest(data);
    const response = await jsonPostRequest(this.url, request);

    if (typeof response !== "object") {
      throw (
        `Unexpected response type: {typeof response}\n` +
        `{JSON.stringify(response)}`
      );
    }

    return Signature.from(response as Signature);
  }

  public async verify(
    data: AppVkProofInputs[],
    verifierAddress?: string
  ): Promise<boolean> {
    const signature = await this.getSignature(data);

    // Verify the signature and confirm it is for expectAddress
    const proof_ids = data.map((vki) => {
      const cid = computeCircuitId(vki.vk);
      return computeProofId(cid, vki.inputs);
    });
    const submission_id = computeSubmissionId(proof_ids);
    const address = recoverAddress(submission_id, signature);

    // If verifierAddress is given, compare to the signer's address.
    // Otherwise, the verifier is trusted and the presence of a well-formed
    // signature is sufficient evidence.

    if (verifierAddress) {
      const expectAddress = getAddress(verifierAddress);
      return address == expectAddress;
    }

    return true;
  }
}
