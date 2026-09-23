import Alamofire
import CryptoKit
import Security

enum PinningError: Error { case noMatchingPin }

final class SPKIHashTrustEvaluator: ServerTrustEvaluating {
    private let pinnedHashes: Set<String>
    init(pinnedHashes: Set<String>) { self.pinnedHashes = pinnedHashes }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        try trust.af.performDefaultValidation(forHost: host) // chain + hostname
        let serverHashes = trust.af.publicKeys.compactMap(Self.spkiHash)
        guard serverHashes.contains(where: pinnedHashes.contains) else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .customEvaluationFailed(error: PinningError.noMatchingPin))
        }
    }

    /// Base64 SHA-256 of the key's SubjectPublicKeyInfo (same as the openssl output)
    static func spkiHash(_ key: SecKey) -> String? {
        guard let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attrs[kSecAttrKeyType] as? String,
              let bits = attrs[kSecAttrKeySizeInBits] as? Int,
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let spki = spkiDER(type: type, bits: bits, raw: [UInt8](raw)) else {
            assertionFailure("Unsupported key for SPKI pinning")
            return nil
        }
        return Data(SHA256.hash(data: spki)).base64EncodedString()
    }

    // MARK: - SPKI construction

    private static func spkiDER(type: String, bits: Int, raw: [UInt8]) -> [UInt8]? {
        let algorithmID: [UInt8]

        switch type {
        case kSecAttrKeyTypeRSA as String:
            // AlgorithmIdentifier { rsaEncryption, NULL } — any key size
            algorithmID = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]

        case kSecAttrKeyTypeECSECPrimeRandom as String:
            // raw must be an uncompressed point: 0x04 || X || Y
            guard raw.first == 0x04 else { return nil }
            let ecPublicKeyOID: [UInt8] = [0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]
            let curveOID: [UInt8]
            switch bits {
            case 256: curveOID = [0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07] // P-256
            case 384: curveOID = [0x06,0x05,0x2b,0x81,0x04,0x00,0x22]                // P-384
            case 521: curveOID = [0x06,0x05,0x2b,0x81,0x04,0x00,0x23]                // P-521
            default: return nil
            }
            algorithmID = tlv(0x30, ecPublicKeyOID + curveOID)

        default:
            return nil
        }

        let subjectPublicKey = tlv(0x03, [0x00] + raw) // BIT STRING, 0 unused bits
        return tlv(0x30, algorithmID + subjectPublicKey)
    }

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + derLength(content.count) + content
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        guard length >= 0x80 else { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
