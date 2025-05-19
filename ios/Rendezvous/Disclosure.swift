//
//  Disclosure.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import Foundation
import CryptoKit
import SwiftySSS

struct Disclosure: Codable {
    var id = UUID()
    let text: String
    let author: String
    var organization: String?
    
    func encryptedVerifiableShares(recipient: Recipient, numberOfShares: Int, recoveryThreshold: Int) throws -> [VerifiableShare] {
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey
        let symmetricKey = try symmetricKey(using: ephemeralKey, publicKey: recipient.publicKey)

        let plaintext = try JSONEncoder().encode(self)
        let ciphertext = try AES.GCM.seal(plaintext, using: symmetricKey).combined!

        let secret = try Secret(
            data: ciphertext,
            threshold: recoveryThreshold,
            shares: numberOfShares
        )
        let shares = try secret.split()
        return shares.map { share in
            let commitment = VerifiableShare.Commitment(id: id, symmetricKey: symmetricKey, share: share.data)
            return VerifiableShare(data: share.data, commitment: commitment, ephemeralKey: ephemeralPublicKey)
        }
    }
    
    struct Encrypted: Codable {
        let ciphertext: Data
        
        func decrypt(
            using privateKey: Curve25519.KeyAgreement.PrivateKey,
            ephemeralKey: Curve25519.KeyAgreement.PublicKey
        ) throws -> Disclosure {
            let symmetricKey = try symmetricKey(using: privateKey, publicKey: ephemeralKey)
            let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
            let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)

            return try JSONDecoder().decode(Disclosure.self, from: decrypted)
        }
        
        static func reconstruct(from shares: [VerifiableShare]) throws -> Self {
            return .init(ciphertext: try Secret.combine(shares: shares.map { try Secret.Share(data: $0.data) }))
        }
    }
    
    struct VerifiableShare: Codable {
        let data: Data
        let commitment: Commitment
        let ephemeralKey: Curve25519.KeyAgreement.PublicKey

        init(data: Data, commitment: Commitment, ephemeralKey: Curve25519.KeyAgreement.PublicKey) {
            self.data = data
            self.commitment = commitment
            self.ephemeralKey = ephemeralKey
        }

        enum CodingKeys: String, CodingKey {
            case data
            case commitment
            case ephemeralKey
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.data = try container.decode(Data.self, forKey: .data)
            self.commitment = Commitment(data: try container.decode(Data.self, forKey: .commitment))

            let keyData = try container.decode(Data.self, forKey: .ephemeralKey)
            self.ephemeralKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(data, forKey: .data)
            try container.encode(commitment.data, forKey: .commitment)
            try container.encode(ephemeralKey.rawRepresentation, forKey: .ephemeralKey)
        }

        func verify(id: UUID, privateKey: Curve25519.KeyAgreement.PrivateKey) -> Bool {
            guard let symmetricKey = try? symmetricKey(using: privateKey, publicKey: ephemeralKey) else { return false }
            let ourCommitment = Commitment(id: id, symmetricKey: symmetricKey, share: data)
            return ourCommitment == commitment
        }

        struct Commitment: Codable, Equatable {
            let data: Data

            init(data: Data) {
                self.data = data
            }

            init(id: UUID, symmetricKey: SymmetricKey, share: Data) {
                var mac = HMAC<SHA256>(key: symmetricKey)
                withUnsafeBytes(of: id) { mac.update(data: Data($0)) }
                mac.update(data: share)
                self.data = Data(mac.finalize())
            }

            static func == (lhs: Self, rhs: Self) -> Bool {
                return lhs.data.withUnsafeBytes { lhsBytes in
                    rhs.data.withUnsafeBytes { rhsBytes in
                        return !lhsBytes.elementsEqual(rhsBytes, by: { $0 ^ $1 != 0 })
                    }
                }
            }
        }
    }
}

private func symmetricKey(
    using privateKey: Curve25519.KeyAgreement.PrivateKey,
    publicKey: Curve25519.KeyAgreement.PublicKey
) throws -> SymmetricKey {
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: "disclosure-encryption".data(using: .utf8)!,
        outputByteCount: 32
    )
}
