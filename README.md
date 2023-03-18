# Secure Blind Payment System with Zero-Knowledge Proof

This secure, anonymous payment system uses blind signatures, RSA, and the Fiat-Shamir heuristic for zero-knowledge proofs to ensure that the payer's identity remains hidden during transactions. The purpose of this system is to enhance the privacy and security of online payments.

## Why Blind Signatures?

Blind signatures provide a way to create a digital signature for a message without revealing the message's content to the signer. For example, the bank signs the blinded payment message in this system, ensuring it cannot see the transaction details. This helps maintain the payer's anonymity.

TODO: Provide references

## Why RSA?

RSA (Rivest-Shamir-Adleman) is a widely-used public-key cryptosystem that provides strong security when implemented correctly. It is chosen for this system because it supports blind signatures and is well-studied and widely accepted as a secure encryption scheme.

TODO: Provide references

## Why Fiat-Shamir Zero-Knowledge Proof?

The Fiat-Shamir heuristic is a technique for transforming an interactive zero-knowledge proof into a non-interactive one. In this payment system, we use the Fiat-Shamir heuristic to generate a non-interactive zero-knowledge proof that the payer possesses a valid signature without revealing the signer's identity. This further enhances the payer's anonymity and ensures the transaction remains secure.

TODO: Provide references

This experimental payment system is designed to prioritize privacy and security. Combining blind signatures, RSA, and the Fiat-Shamir heuristic for zero-knowledge proofs ensures that payer identity is protected during transactions.

## Contributing

Contributions are welcome! If you'd like to report a bug, request a feature, or submit a pull request, please feel free to open an issue or create a pull request on this repository.

## Note

This implementation is  only experimental purposes and should be used at your own risk. The code is not audited.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.