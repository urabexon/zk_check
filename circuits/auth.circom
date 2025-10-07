pragma circom 2.0.0;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";

template AuthCircuit() {
    signal input password;
    signal input expectedHash;
    signal output isValid;
    
    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== password;
    
    component eq = IsEqual();
    eq.in[0] <== poseidon.out;
    eq.in[1] <== expectedHash;
    
    isValid <== eq.out;
}

component main = AuthCircuit();