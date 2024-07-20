pragma circom 2.0.0;

include "comparators.circom";

// Toy hash function: a*x+b
template ToyHash() {
    signal input value;
    signal output hashedValue;

    var a = 1234;
    var b = 2468;

    hashedValue <== a * value + b;
}

// Checks that this transaction is valid
template ValidateTx() {
    signal input oldSourceCoinBalance;
    signal input oldSourceCoinBalanceHash;
    signal input newSourceCoinBalance;
    signal input newSourceCoinBalanceHash;

    signal input oldTargetCoinBalance;
    signal input oldTargetCoinBalanceHash;
    signal input newTargetCoinBalance;
    signal input newTargetCoinBalanceHash;

    signal input transferAmount;
    signal input transferAmountHash;

    // Check that each hash is correct
    component oldSourceCoinBalanceHasher = ToyHash();
    oldSourceCoinBalanceHasher.value <== oldSourceCoinBalance;
    oldSourceCoinBalanceHash === oldSourceCoinBalanceHasher.hashedValue;

    component newSourceCoinBalanceHasher = ToyHash();
    newSourceCoinBalanceHasher.value <== newSourceCoinBalance;
    newSourceCoinBalanceHash === newSourceCoinBalanceHasher.hashedValue;

    component oldTargetCoinBalanceHasher = ToyHash();
    oldTargetCoinBalanceHasher.value <== oldTargetCoinBalance;
    oldTargetCoinBalanceHash === oldTargetCoinBalanceHasher.hashedValue;

    component newTargetCoinBalanceHasher = ToyHash();
    newTargetCoinBalanceHasher.value <== newTargetCoinBalance;
    newTargetCoinBalanceHash === newTargetCoinBalanceHasher.hashedValue;

    component transferAmountHasher = ToyHash();
    transferAmountHasher.value <== transferAmount;
    transferAmountHash === transferAmountHasher.hashedValue;

    // Check that sourcecoin has enough funds
    component sufficientBalance = LessEqThan(32);
    sufficientBalance.in[0] <== transferAmount;
    sufficientBalance.in[1] <== oldSourceCoinBalance;
    sufficientBalance.out === 1;

    // Check that the new balances are correct
    oldSourceCoinBalance - newSourceCoinBalance === transferAmount;
    newTargetCoinBalance - oldTargetCoinBalance === transferAmount;
}

component main {public [oldSourceCoinBalanceHash, newSourceCoinBalanceHash, oldTargetCoinBalanceHash, newTargetCoinBalanceHash, transferAmountHash]} = ValidateTx();
