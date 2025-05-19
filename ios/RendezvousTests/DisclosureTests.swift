//
//  DisclosureTests.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import XCTest
import CryptoKit
@testable import Rendezvous // or your module name

final class DisclosureTests: XCTestCase {
    
    func testEncryptionAndDecryptionRoundTrip() throws {
        let message = "The password is swordfish"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let verifiableShares = try disclosure.encryptedVerifiableShares(recipient: recipient, numberOfShares: 3, recoveryThreshold: 3)
        for share in verifiableShares {
            XCTAssertTrue(share.verify(id: disclosure.id, privateKey: recipientKey))
        }
        let encrypted = try Disclosure.Encrypted.reconstruct(from: verifiableShares)
        let decrypted = try encrypted.decrypt(using: recipientKey, ephemeralKey: verifiableShares.first!.ephemeralKey)

        XCTAssertEqual(decrypted.text, message)
    }

    func testShareSplitAndReconstruction() throws {
        let message = "Top secret"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let verifiableShares = try disclosure.encryptedVerifiableShares(recipient: recipient, numberOfShares: 5, recoveryThreshold: 3)
        XCTAssertEqual(verifiableShares.count, 5)

        // Take 3 random shares to reconstruct
        let selectedShares = Array(verifiableShares.shuffled().prefix(3))
        let reconstructed = try Disclosure.Encrypted.reconstruct(from: selectedShares)

        let decrypted = try reconstructed.decrypt(using: recipientKey, ephemeralKey: selectedShares.first!.ephemeralKey)
        XCTAssertEqual(decrypted.text, message)
    }

    func testShareReconstructionFailsWithTooFewShares() throws {
        let message = "Too few"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let verifiableShares = try disclosure.encryptedVerifiableShares(recipient: recipient, numberOfShares: 5, recoveryThreshold: 4)

        // Only use 2 shares (below threshold)
        let fewShares = Array(verifiableShares.prefix(2))

        let encrypted = try Disclosure.Encrypted.reconstruct(from: fewShares)
        XCTAssertThrowsError(try encrypted.decrypt(using: recipientKey, ephemeralKey: fewShares.first!.ephemeralKey))
    }
}
