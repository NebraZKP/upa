import { Roboto_Mono } from "next/font/google";
import { useEffect, useState } from "react";
import {
  aggregatingProofOnUpa,
  generateSolutionAndProof,
  submitProofToUpa,
  submittingToDemoApp,
} from "@/src/submit";
import { DemoAppStages } from "../lib/types";
import { SubmissionHandle, application, utils } from "@nebrazkp/upa/sdk";
import Logo from "../components/ui/Logo";
import * as ethers from "ethers";
import StageText from "../components/ui/StageText";
const roboto = Roboto_Mono({ subsets: ["latin"] });

type CircuitIdProofAndInputs = application.CircuitIdProofAndInputs;
const Proof = application.Groth16Proof;

export default function Home() {
  const [currStage, setCurrStage] = useState<DemoAppStages>(
    DemoAppStages.NotSubmitted
  );
  const [proofData, setProofData] = useState<CircuitIdProofAndInputs>({
    circuitId: utils.bigintToHex32(BigInt(0)),
    proof: new Proof(
      [0, 0],
      [
        [0, 0],
        [0, 0],
      ],
      [0, 0],
      [],
      []
    ),
    inputs: [],
  });
  const [submitToUpaResult, setSubmitToUpaResult] = useState<{
    submissionHandle: SubmissionHandle;
    txReceipt: ethers.TransactionReceipt;
  }>();
  const [provider, setProvider] = useState<ethers.BrowserProvider>();
  const [providerAvailable, setProviderAvailable] = useState<boolean>(true);

  // Per-stage text to display
  const [notSubmittedText, setNotSubmittedText] = useState<JSX.Element[]>([]);
  const [generateProofText, setGenerateProofText] = useState<JSX.Element[]>([]);
  const [submitUpaText, setSubmitUpaText] = useState<JSX.Element[]>([]);
  const [aggregateProofText, setAggregateProofText] = useState<JSX.Element[]>(
    []
  );
  const [submitDemoAppText, setSubmitDemoAppText] = useState<JSX.Element[]>([]);

  function handleSubmitProofClick() {
    setCurrStage(DemoAppStages.GeneratingProof);
    generateProofText.push(
      <span key="generatingProof">Generating Proof...</span>
    );
    setGenerateProofText(generateProofText);
  }

  // Runs when current stage is `DemoAppStages.NotSubmitted`
  useEffect(() => {
    if (currStage !== DemoAppStages.NotSubmitted) return;
    if ((window as any).ethereum) {
      const newProvider = new ethers.BrowserProvider((window as any).ethereum);
      setProvider(newProvider);
    } else {
      // Handle the absence of Ethereum provider, e.g., show a message to the user.
      setProviderAvailable(false); // Set Ethereum availability to false
      setNotSubmittedText([
        <p key="ethereumMessage">
          Ethereum provider not found. Please install MetaMask or a compatible
          Ethereum wallet.
        </p>,
      ]);
    }
    return;
  }, [currStage]);

  // Runs when current stage is `DemoAppStages.GeneratingProof`
  useEffect(() => {
    if (currStage !== DemoAppStages.GeneratingProof) return;
    const genProofData = async () => {
      const proofData = await generateSolutionAndProof();
      setProofData(proofData);
      setCurrStage(DemoAppStages.SubmittingToUpa);
    };
    genProofData().catch(console.error);
    submitUpaText.push(
      <span key="submittingToUpa">Submitting proof to UPA...</span>
    );
    setSubmitUpaText(submitUpaText);
  }, [currStage]);

  // Runs when current stage is `DemoAppStages.SubmittingToUpa`
  useEffect(() => {
    if (currStage !== DemoAppStages.SubmittingToUpa) return;
    const submitUpa = async () => {
      const submitUpaResult = await submitProofToUpa(proofData, provider!);
      const txLink = `https://sepolia.etherscan.io/tx/${submitUpaResult.txReceipt?.hash}`;
      setSubmitToUpaResult(submitUpaResult);
      const gasUsed = `${submitUpaResult.txReceipt.gasUsed}`;
      submitUpaText.push(
        <span key="submitSuccess">
          Proof successfully submitted! {gasUsed} gas used.
        </span>
      );
      submitUpaText.push(
        <u>
          <a href={txLink} target="_blank" rel="noopener noreferrer">
            View Etherscan transaction
          </a>
        </u>
      );
      setSubmitUpaText(submitUpaText);
      setCurrStage(DemoAppStages.AggregatingProof);
    };
    submitUpa().catch(console.error);
  }, [currStage]);

  // Runs when current stage is `DemoAppStages.AggregatingProof`
  useEffect(() => {
    if (currStage !== DemoAppStages.AggregatingProof) return;
    let newAggregateProofText = [
      <span key="aggregatingProof">Waiting for proof to be aggregated...</span>,
    ];

    const nebrascanLink = `https://sepolia.nebrascan.io/proofId/${submitToUpaResult?.submissionHandle.submission.proofIds[0]}`;

    newAggregateProofText.push(
      <div key="nebrascanLink">
        <u>
          <a href={nebrascanLink} target="_blank" rel="noopener noreferrer">
            View proof status on nebrascan.io
          </a>
        </u>
      </div>
    );
    setAggregateProofText(newAggregateProofText);
    const aggregate = async () => {
      await aggregatingProofOnUpa(
        proofData,
        submitToUpaResult?.submissionHandle!,
        provider!
      );
      newAggregateProofText.push(
        <span key="proofAggregated">Proof successfully aggregated!</span>
      );
      setAggregateProofText(newAggregateProofText);
      setCurrStage(DemoAppStages.SubmittingSolutionToDemoApp);
    };
    aggregate().catch(console.error);
  }, [currStage]);

  // Runs when current stage is `DemoAppStages.SubmittingSolutionToDemoApp`
  useEffect(() => {
    if (currStage !== DemoAppStages.SubmittingSolutionToDemoApp) return;
    let newSubmitDemoAppText = [
      <span key="submittingSolution">Submitting solution to Demo App...</span>,
    ];
    setSubmitDemoAppText(newSubmitDemoAppText);
    const submitSolution = async () => {
      const txReceipt = await submittingToDemoApp(proofData, provider!);
      const txLink = `https://sepolia.etherscan.io/tx/${txReceipt?.hash}`;
      const gasUsed = `${txReceipt.gasUsed}`;
      newSubmitDemoAppText.push(
        <div key="txLink">Demo App solution submitted! {gasUsed} gas used.</div>
      );
      newSubmitDemoAppText.push(
        <u>
          <a href={txLink} target="_blank" rel="noopener noreferrer">
            View Etherscan transaction
          </a>
        </u>
      );
      const finalGasTotal =
        submitToUpaResult!.txReceipt.gasUsed + txReceipt.gasUsed;
      const finalGasTotalString = `${finalGasTotal}`;
      const estimatedGasSaved = `${BigInt(270_000) - finalGasTotal!}`;
      newSubmitDemoAppText.push(
        <div key="txLink">Total: {finalGasTotalString} gas used.</div>
      );
      newSubmitDemoAppText.push(
        <div key="txLink">
          Estimated gas saved using UPA: {estimatedGasSaved}
        </div>
      );
      setSubmitDemoAppText(newSubmitDemoAppText);
      setCurrStage(DemoAppStages.DemoComplete);
    };
    submitSolution().catch(console.error);
  }, [currStage]);

  return (
    <main
      className={`flex min-h-screen flex-col items-center justify-between p-24 ${roboto.className}`}
    >
      <div className="h-screen items-center">
        <Logo width={100} height={100} />
        <h1 className="text-3xl text-center font-semibold py-4">
          DEMO APP{" "}
          <span className="text-xl font-semibold">
            (back to{" "}
            <a href="https://demo.nebra.one/" target="_blank">
              <span className="text-xl text-indigo-500">DOCS</span>
            </a>
            )
          </span>
        </h1>
        <div className="border-solid border-2 border-indigo-500 rounded-md py-4 inline-block my-6">
          <p className="text-sm text-center font-semibold ml-8 mr-10">
            Submits solutions{" "}
            <span className=" text-indigo-500">(c,d,e,f)</span> for equation:{" "}
            <span className="text-indigo-500">a*b = c*d + e + f</span>.
          </p>
        </div>
        <table className="table-auto text-xl">
          <tbody className="border-y-2 border-indigo-500">
            <tr>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                Generating Proof
              </td>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                <span className="text-xl text-indigo-500">
                  <StageText
                    stage={DemoAppStages.GeneratingProof}
                    currStage={currStage}
                  />
                </span>
              </td>
            </tr>
            <tr>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                Submitting to NEBRA UPA
              </td>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                <span className="text-xl text-indigo-500">
                  <StageText
                    stage={DemoAppStages.SubmittingToUpa}
                    currStage={currStage}
                  />
                </span>
              </td>
            </tr>
            <tr>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                Aggregating Proof
              </td>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                <span className="text-xl text-indigo-500">
                  <StageText
                    stage={DemoAppStages.AggregatingProof}
                    currStage={currStage}
                  />
                </span>
              </td>
            </tr>
            <tr>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                Submitting Solution to Demo App
              </td>
              <td className="border-y-2 border-indigo-500 px-5 py-5">
                <span className="text-xl text-indigo-500">
                  <StageText
                    stage={DemoAppStages.SubmittingSolutionToDemoApp}
                    currStage={currStage}
                  />
                </span>
              </td>
            </tr>
          </tbody>
        </table>
        {currStage === DemoAppStages.NotSubmitted ? (
          <button
            onClick={handleSubmitProofClick}
            className={`h-24 w-full my-20 text-2xl text-indigo-100 transition-colors duration-150 rounded-lg focus:shadow-outline ${providerAvailable ? "hover:bg-indigo-800 bg-indigo-700" : "bg-gray-400 cursor-not-allowed"}`}
            disabled={!providerAvailable}
          >
            {providerAvailable ? "Submit Proof" : "No Wallet Found"}
          </button>
        ) : (
          <div className="h-24 w-full my-20 py-6 text-2xl text-center align-middle text-indigo-700">
            {notSubmittedText.map((text, index) => {
              return <div key={index}>{text}</div>;
            })}
            {generateProofText.map((text, index) => {
              return <div key={index}>{text}</div>;
            })}
            {submitUpaText.map((text, index) => {
              return <div key={index}>{text}</div>;
            })}
            {aggregateProofText.map((text, index) => {
              return <div key={index}>{text}</div>;
            })}
            {submitDemoAppText.map((text, index) => {
              return <div key={index}>{text}</div>;
            })}
          </div>
        )}
      </div>
    </main>
  );
}
