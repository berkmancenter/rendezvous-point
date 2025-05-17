//
//  Recipient.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import Foundation
import CryptoKit

struct Recipient: Codable, Hashable {
    let name: String
    let publicKey: Curve25519.KeyAgreement.PublicKey
    
    init(name: String, publicKey: Curve25519.KeyAgreement.PublicKey) {
        self.name = name
        self.publicKey = publicKey
    }
    
    enum CodingKeys: String, CodingKey {
        case name
        case publicKey
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)

        let keyData = try container.decode(Data.self, forKey: .publicKey)
        self.publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(publicKey.rawRepresentation, forKey: .publicKey)
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey.rawRepresentation)
    }

    static func == (lhs: Recipient, rhs: Recipient) -> Bool {
        lhs.publicKey.rawRepresentation == rhs.publicKey.rawRepresentation
    }
}
