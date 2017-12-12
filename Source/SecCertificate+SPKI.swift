//
//  DispatchQueue+Alamofire.swift
//
//  Copyright (c) 2014-2017 Alamofire Software Foundation (http://alamofire.org/)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
import Security

fileprivate let rsa4096SpkiHeader: [UInt8] = [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d,
                                              0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                              0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                              0x00, 0x03, 0x82, 0x02, 0x0f, 0x00]

fileprivate let rsa2048SpkiHeader: [UInt8] = [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
                                              0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                              0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                              0x00, 0x03, 0x82, 0x01, 0x0f, 0x00]

fileprivate let ecDsaSecp256r1SpkiHeader: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
                                                     0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                                     0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                                     0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                                     0x42, 0x00]

fileprivate let ecDsaSecp384r1SpkiHeader: [UInt8] = [0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
                                                     0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                                     0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
                                                     0x00, 0x22, 0x03, 0x62, 0x00]

extension SecCertificate {
    
    var data: Data {
        return SecCertificateCopyData(self) as Data
    }
    
    var publicKey: SecKey? {
        
        let policy: SecPolicy = SecPolicyCreateBasicX509()
        var uTrust: SecTrust?
        
        let status = SecTrustCreateWithCertificates([self] as CFArray, policy, &uTrust)
        
        guard status == errSecSuccess else { return nil }
        
        if let trust = uTrust {
            return SecTrustCopyPublicKey(trust)
        } else {
            return nil
        }
    }
    
    var publicKeyData: Data? {
        
        guard let publicKey = publicKey else { return nil }
        
        if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *), #available(macOS 10.12, *) {
            
            var error: Unmanaged<CFError>? = nil
            let data = SecKeyCopyExternalRepresentation(publicKey, &error)
            guard let unwrappedData = data as Data? else {
                return nil
            }
            return unwrappedData
            
        } else {
            
            let temporaryTag = UUID().uuidString
            let addParams: [CFString: Any] = [
                kSecValueRef: publicKey,
                kSecReturnData: true,
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: temporaryTag
            ]
            
            var data: AnyObject?
            let _ = SecItemAdd(addParams as CFDictionary, &data)
            guard let unwrappedData = data as? Data else {
                return nil
            }
            
            let deleteParams: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: temporaryTag
            ]
            
            _ = SecItemDelete(deleteParams as CFDictionary)
            
            return unwrappedData
        }
    }
    
    var spki: Data? {
        
        guard let publicKeyData = publicKeyData else { return nil }
        
        var spkiHeader: [UInt8] = []
        switch publicKeyData.count {
            
        case 526:
            spkiHeader = rsa4096SpkiHeader
            
        case 270:
            spkiHeader = rsa2048SpkiHeader
            
        case 65:
            spkiHeader = ecDsaSecp256r1SpkiHeader
            
        case 97:
            spkiHeader = ecDsaSecp384r1SpkiHeader
            
        default:
            return nil
        }
        
        var spki: Data = Data()
        
        spki.append(contentsOf: spkiHeader)
        spki.append(publicKeyData)
        
        return spki
    }
}
