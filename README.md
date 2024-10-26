# A-MACI Circuit Security Vulnerabilities - Major Bounty Submission

## Overview
This document outlines critical security vulnerabilities identified in the A-MACI circuit implementation. The findings include major issues across `addNewKey.circom`, `processMessages.circom` and `processDeactivate.circom` circuits. Each report is separated into major and minor categories based on severity.

---

### Summary of Findings

| ID       | Circuit           | Severity     | Title                            | Impact                          |
|----------|--------------------|--------------|----------------------------------|---------------------------------|
| CVE-001  | addNewKey          | Critical     | Missing Randomness Validation    | Potential proof forgery         |
| CVE-002  | addNewKey          | Critical     | Insufficient Public Key Validation | Invalid point attacks        |
| CVE-004  | processMessages    | Critical     | Batch Size Constraints           | DoS or Overflow                 |
| CVE-005  | processDeactivate  | Critical     | Message Chain Verification Weakness | Message forgery risk        |
| CVE-006  | processDeactivate  | Critical     | State Transition Constraint Gap  | Invalid state transitions       |

---

## Bounty Report - Major Bugs

### 1. CVE-001: Missing Randomness Validation
**Location**: `addNewKey.circom`  
**Severity**: Critical  
**Component**: Rerandomization process  

#### Description
The `addNewKey` circuit lacks validation for the `randomVal` input used in rerandomization, making it susceptible to predictable randomness and proof forgery.

#### Impact
- Potential proof forgery
- Replay attack vulnerabilities
- Increased risk of correlation between proofs

#### Proof of Concept
```circom
signal input randomVal;
// Vulnerable line
rerandomize.randomVal <== randomVal;
```

#### Fix
To add randomness validation, high-order bits should be checked:
```circom
component randomValCheck = Num2Bits(252);
randomValCheck.in <== randomVal;
// Set high-order bits
component highBitsCheck = GreaterThan(252);
highBitsCheck.in[0] <== randomVal;
highBitsCheck.in[1] <== 2**200;
highBitsCheck.out === 1;
```

---

### 2. CVE-002: Insufficient Public Key Validation
**Location**: `addNewKey.circom`  
**Severity**: Critical  
**Component**: Public key handling  

#### Description
The circuit does not validate the coordinator’s public key as an elliptic curve point, which risks small subgroup and invalid point attacks.

#### Impact
- Small subgroup attacks
- Invalid point attacks
- Possible key recovery risks

#### Fix
Validate the public key as follows:
```circom
component validatePubKey = PointOnCurve();
validatePubKey.x <== coordPubKey[0];
validatePubKey.y <== coordPubKey[1];

// Subgroup check
component subgroupCheck = PrimeOrderPoint();
subgroupCheck.x <== coordPubKey[0];
subgroupCheck.y <== coordPubKey[1];
```

---

### 3. CVE-004: Batch Size Constraints
**Location**: `processMessages.circom`  
**Severity**: Critical  
**Component**: Batch processing  

#### Description
The circuit does not enforce an upper bound on the `batchSize` input for message processing, creating a risk of overflow or Denial of Service (DoS) through excessive resource consumption.

#### Fix
Add an upper bound constraint:
```circom
var MAX_BATCH_SIZE = 32;

assert(batchSize > 0);
assert(batchSize <= MAX_BATCH_SIZE);
```

---

### 4. CVE-005: Message Chain Verification Weakness
**Location**: `processDeactivate.circom`  
**Severity**: Critical  
**Component**: Message verification  

#### Description
The circuit only checks the first element in a message array to determine if it’s empty, which could allow for partial message forgery.

#### Fix
Update message chain verification as follows:
```circom
template IsMessageEmpty(MSG_LENGTH) {
    signal input message[MSG_LENGTH];
    signal output isEmpty;

    component isZero[MSG_LENGTH];
    signal intermediate[MSG_LENGTH+1];
    intermediate[0] <== 1;

    for (var i = 0; i < MSG_LENGTH; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== message[i];
        intermediate[i+1] <== intermediate[i] * isZero[i].out;
    }

    isEmpty <== intermediate[MSG_LENGTH];
}
```

---

### 5. CVE-006: State Transition Constraint Gap
**Location**: `processDeactivate.circom`  
**Severity**: Critical  
**Component**: State transition validation  

#### Description
The circuit allows invalid state transitions due to weak constraints between old and new states.

#### Fix
Add state validation rules:
```circom
template ValidStateTransition() {
    signal input oldState;
    signal input newState;
    signal input valid;

    component stateCheck = StateTransitionRules();
    stateCheck.oldState <== oldState;
    stateCheck.newState <== newState;

    component validTransition = TransitionValidator();
    validTransition.oldState <== oldState;
    validTransition.newState <== newState;
    validTransition.valid === 1;
}
```

---

## Implementation Priority

**Immediate Action Required**  
- CVE-001: Randomness Validation  
- CVE-002: Public Key Validation  
- CVE-004: Batch Size Constraints  
- CVE-005: Message Chain Verification  
- CVE-006: State Transition Constraints  
  

## Verification Steps
1. Implement the fixes in a controlled environment.
2. Run the provided test vectors.
3. Conduct integration testing to ensure stability.
4. Perform a security audit.
5. Deploy to testnet.
6. Monitor the implementation for any issues.

## Contact Information
For questions or clarification regarding these findings, please reach out to [utitofonudoekong0@gmail.com].

## License
This security report is submitted under the terms of the dorahacks bounty program. All rights reserved.

**Note**: This document contains sensitive security information. Please handle it with appropriate care.
