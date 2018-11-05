const
  crypto = require('crypto'),
  fs = require('fs'),
  pem = require('pem');

const
  file = fs.readFileSync('sample.pdf', 'utf-8');


pem.createCertificate({
  days: 1,
  selfSigned: true
}, function (err, keys) {
  if (err) {
    throw err
  }
  // console.log('Private Key ---> ', keys)
  fs.writeFile("private-key.pem", keys.serviceKey, function (err) {
    if (err) {
      return console.log(err);
    }
    pem.getPublicKey(keys.serviceKey, (err, result) => {
      // console.log('Public key ---> ', result)
      fs.writeFile("public-key.pem", result.publicKey, function (err) {
        if (err) {
          return console.log(err);
        }
        // console.log("The file was saved!");
        const
          private_key = fs.readFileSync('private-key.pem', 'utf-8'),
          public_key = fs.readFileSync('public-key.pem', 'utf-8');

        const
          signer = crypto.createSign('sha256');

        signer.update(file);
        signer.end();

        const
          signature = signer.sign(private_key),
          signature_hex = signature.toString('hex');

        const
          verifier = crypto.createVerify('sha256');

        verifier.update(file);
        verifier.end();

        const
          verified = verifier.verify(public_key, signature);

        console.log(JSON.stringify({
          signature: signature_hex,
          verified: verified,
        }, null, 2));
      });
    })
  });

});
