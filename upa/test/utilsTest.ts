import { expect } from "chai";
import { versionStringToUint, versionUintToString } from "../src/sdk/utils";

function testVersion(str: string, num: bigint) {
  let strToNum = versionStringToUint(str);
  expect(strToNum).equals(num);
  let strToNumToStr = versionUintToString(strToNum);
  expect(strToNumToStr).equals(str);
}

describe("Utils", () => {
  it("version passing", async function() {
     testVersion("1.2.3", 10203n);
     testVersion("31.2.0", 310200n);
     testVersion("1.21.50", 12150n);
     testVersion("0.0.0", 0n);
     testVersion("32.54.76", 325476n);
  });
});
