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
    let text: String
    let author: String
    var organization: String?
    
    func encrypt(recipient: Recipient) throws -> Encrypted {
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipient.publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        let plaintext = try JSONEncoder().encode(self)
        let ciphertext = try AES.GCM.seal(plaintext, using: symmetricKey).combined!
        return .init(
            ciphertext: ciphertext,
            ephemeralKey: ephemeralPublicKey
        )
    }
    
    struct Encrypted: Codable {
        let ciphertext: Data
        let ephemeralKey: Curve25519.KeyAgreement.PublicKey
        
        init(ciphertext: Data, ephemeralKey: Curve25519.KeyAgreement.PublicKey) {
            self.ciphertext = ciphertext
            self.ephemeralKey = ephemeralKey
        }
        
        enum CodingKeys: String, CodingKey {
            case ciphertext
            case ephemeralKey
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.ciphertext = try container.decode(Data.self, forKey: .ciphertext)

            let keyData = try container.decode(Data.self, forKey: .ephemeralKey)
            self.ephemeralKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(ciphertext, forKey: .ciphertext)
            try container.encode(ephemeralKey.rawRepresentation, forKey: .ephemeralKey)
        }
        
        func makeShares(_ numberOfShares: Int, recoveryThreshold: Int) throws -> [Share] {
            let secret = try Secret(
                data: try JSONEncoder().encode(self),
                threshold: recoveryThreshold,
                shares: numberOfShares
            )
            let shares = try secret.split()
            return shares.map { .init(data: $0.data) }
        }
        
        func decrypt(using privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Disclosure {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: Data(),
                outputByteCount: 32
            )
            
            let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
            let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)

            return try JSONDecoder().decode(Disclosure.self, from: decrypted)
        }
        
        static func reconstruct(from shares: [Share]) throws -> Self {
            let serializedContent = try Secret.combine(shares: shares.map { try Secret.Share(data: $0.data) })
            return try JSONDecoder().decode(Self.self, from: serializedContent)
        }
    }
    
    struct Share: Codable {
        let data: Data
    }
}
