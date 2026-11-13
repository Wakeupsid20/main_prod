pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
template SessionAuth() {
 signal input credential;
 signal input commitment;
 signal input challenge;
 signal output response;
 component identity = Poseidon(1);
 identity.inputs[0] <== credential;
 commitment === identity.out;
 component session = Poseidon(2);
 session.inputs[0] <== credential;
 session.inputs[1] <== challenge;
 response <== session.out;
}
component main {public [commitment, challenge]} = SessionAuth();
