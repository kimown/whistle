'use strict';

var crypto = require('crypto');
var fs = require('fs');
var os = require('os');
var path = require('path');
var net = require('net');
var childProcess = require('child_process');

function parseRoot(keyPem, certPem) {
  var key = crypto.createPrivateKey(keyPem);
  var cert = new crypto.X509Certificate(certPem);
  if (key.asymmetricKeyType !== 'ec' || cert.publicKey.asymmetricKeyType !== 'ec' || !cert.ca) {
    throw new Error('Expected an EC certificate authority');
  }
  var publicKey = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  var certKey = cert.publicKey.export({ type: 'spki', format: 'der' });
  if (!publicKey.equals(certKey)) {
    throw new Error('EC CA certificate and private key do not match');
  }
  var now = Date.now();
  if (Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now) {
    throw new Error('EC CA certificate is not currently valid');
  }
  return cert;
}

function validateChain(certPem, chainPem) {
  if (!chainPem || !chainPem.trim()) {
    return '';
  }
  var blocks = chainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || chainPem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim()) {
    throw new Error('Invalid intermediate.crt certificate chain');
  }
  var child = new crypto.X509Certificate(certPem);
  blocks.forEach(function (block) {
    var parent = new crypto.X509Certificate(block);
    if (!parent.ca || !child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      throw new Error('Intermediate CA chain does not match the signing certificate');
    }
    child = parent;
  });
  return blocks.join('\n') + '\n';
}

function createCertificate(hostname, keyPem, certPem, intermediatePem) {
  // Hostnames are written to an OpenSSL extension file; reject configuration injection.
  if (typeof hostname !== 'string' || hostname.length > 253 ||
      !hostname || /[\r\n\[\]=,]/.test(hostname)) {
    throw new Error('Invalid certificate hostname');
  }
  var ip = net.isIP(hostname);
  if (!ip && !/^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$/i.test(hostname)) {
    throw new Error('Invalid certificate hostname');
  }
  parseRoot(keyPem, certPem);
  var chain = validateChain(certPem, intermediatePem);
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-ec-ca-'));
  try {
    var leafKey = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    }).privateKey;
    fs.writeFileSync(path.join(tmp, 'root.key'), keyPem, { mode: 0o600 });
    fs.writeFileSync(path.join(tmp, 'root.crt'), certPem);
    fs.writeFileSync(path.join(tmp, 'leaf.key'), leafKey, { mode: 0o600 });
    fs.writeFileSync(path.join(tmp, 'extensions.cnf'),
      '[v3_leaf]\nbasicConstraints=critical,CA:FALSE\n' +
      'keyUsage=critical,digitalSignature,keyEncipherment\n' +
      'extendedKeyUsage=serverAuth,clientAuth\n' +
      'subjectAltName=' + (ip ? 'IP:' : 'DNS:') + hostname + '\n');
    var exec = function (args) {
      childProcess.execFileSync('openssl', args, { cwd: tmp, stdio: 'pipe', timeout: 15000 });
    };
    exec(['req', '-new', '-sha256', '-key', 'leaf.key', '-out', 'leaf.csr',
      '-subj', '/CN=whistle-leaf']);
    exec(['x509', '-req', '-sha256', '-in', 'leaf.csr',
      '-CA', 'root.crt', '-CAkey', 'root.key',
      '-set_serial', '0x' + crypto.randomBytes(16).toString('hex'),
      '-days', '30', '-extfile', 'extensions.cnf', '-extensions', 'v3_leaf',
      '-out', 'leaf.crt']);
    return { key: leafKey, cert: fs.readFileSync(path.join(tmp, 'leaf.crt'), 'utf8') + '\n' + certPem.trim() + '\n' + chain };
  } finally {
    fs.readdirSync(tmp).forEach(function (name) {
      fs.unlinkSync(path.join(tmp, name));
    });
    fs.rmdirSync(tmp);
  }
}

exports.parseRoot = parseRoot;
exports.createCertificate = createCertificate;
