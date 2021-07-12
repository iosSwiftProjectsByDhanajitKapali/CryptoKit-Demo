//
//  ViewController.swift
//  CryptoKit Demo
//
//  Created by unthinkable-mac-0025 on 09/07/21.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {

    var data : Data?
    
    var albusPrivateKey : Curve25519.KeyAgreement.PrivateKey!
    var albusPublicKeyData : Data!
    var harryPrivateKey : Curve25519.KeyAgreement.PrivateKey!
    var harryPublicKeyData : Data!
    var protocolSalt : Data!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        //get the data of the pdf file
        data = getData(for: "paper", of: "pdf")
        
        //publicKeyCrypto()
        
        //Simulating :- Creation of Private keys and transfer of Public keys
        albusPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        albusPublicKeyData = albusPrivateKey.publicKey.rawRepresentation
        print(albusPublicKeyData)
        
        harryPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        harryPublicKeyData = harryPrivateKey.publicKey.rawRepresentation
        print(harryPublicKeyData)
        
        //creation of salt, known by both parties
        protocolSalt = "Voldemort's Horcruxes".data(using: .utf8)!

       //albus will enrypt the data and pass it to harry
        albus(data: data!)
       
    }
    
    func getData(for item: String, of type: String) -> Data {
      let filePath = Bundle.main.path(forResource: item, ofType: type)!
        //print(filePath)
      return FileManager.default.contents(atPath: filePath)!
    }

    
    ///Albus has access to only public key of harry and the agreement salt
    func albus(data: Data){
        print("from albus->  \(data)")
        
        //create the symmetric key
        let harryPublicKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: harryPublicKeyData)
        let ADsharedSecret = try! albusPrivateKey.sharedSecretFromKeyAgreement(with: harryPublicKey)
        let ADsymmetricKey = ADsharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self, salt: protocolSalt,
          sharedInfo: Data(), outputByteCount: 32)
        
        //encrypt the data
        let sealedBoxData = try! ChaChaPoly.seal(data, using: ADsymmetricKey).combined
        
        //send data to harry
        harry(encryptedData: sealedBoxData)
    }
    
    
    ///Harry has access to only public key of harry and the agreement salt
    func harry(encryptedData : Data){
        //create the symmetric key here also
        let albusPublicKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: albusPublicKeyData)
        let HPsharedSecret = try! harryPrivateKey.sharedSecretFromKeyAgreement(with: albusPublicKey)
        let HPsymmetricKey = HPsharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self, salt: protocolSalt,
          sharedInfo: Data(), outputByteCount: 32)
        
        // Harry receives sealed box data, then extracts the sealed box
        let sealedBox = try! ChaChaPoly.SealedBox(combined: encryptedData)
        // Harry decrypts data with the same key
        let decryptedData = try! ChaChaPoly.open(sealedBox, using: HPsymmetricKey)

 
        print("from harry->  \(decryptedData)")
    }


}

extension ViewController{
    
    ///Function to simuate public-key cryptography, Data is not encrypted. Only authenticity and integrity of data is checked here
    func publicKeyCrypto(){
        //Senders Private key created
        let albusSigningPrivateKey = Curve25519.Signing.PrivateKey()
        print("The Private key is")
        print(albusSigningPrivateKey)
        
        //Save the private key in secure location : TO-DO
        
        //Senders Public Key Data created
        let albusSigningPublicKeyData = albusSigningPrivateKey.publicKey.rawRepresentation
        
        
        //Sender signs the data with private key
        let signatureForData = try! albusSigningPrivateKey.signature(for: data!)
        
        /// Signing a digest of the data is faster:
        //Sender signs the digest of data with private key
        let digest512 = SHA512.hash(data: data!)
        let signatureForDigest = try! albusSigningPrivateKey.signature(for: Data(digest512))
        

        //Transmit Public key to Reciever, TO_DO
        
        //Reciever generates the Public key from Public Key data
        let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: albusSigningPublicKeyData)
        
        //Validating the authenticity of data, data is NOT encrypted
        if publicKey.isValidSignature(signatureForData, for: data!) {
          print("Dumbledore sent this data.")
            
        }
        //Validating the intergrity of data
        if publicKey.isValidSignature(signatureForDigest, for: Data(digest512)) {
          print("Data received == data sent.")
            //UIImage(data: data!)
            print(data)
        }
    }
}
