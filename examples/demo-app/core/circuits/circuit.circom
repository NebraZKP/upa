pragma circom 2.0.0;

template Arithmetic() {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal input e;
    signal input f;

    signal cTimesD;
    cTimesD <== c * d;
    a*b === cTimesD + e + f;
}

component main {public [c,d,e,f]} = Arithmetic();
