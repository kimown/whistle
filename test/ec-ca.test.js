'use strict';

var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var os = require('os');
var path = require('path');
var childProcess = require('child_process');
var ecCA = require('../lib/https/ec-ca');

var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-ec-test-'));
function openssl(args) {
  return childProcess.execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
}
try {
  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'root.key']);
  openssl(['req', '-new', '-x509', '-sha256', '-days', '365', '-key', 'root.key',
    '-out', 'root.crt', '-subj', '/CN=Whistle EC Test CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  var key = fs.readFileSync(path.join(dir, 'root.key'), 'utf8');
  var cert = fs.readFileSync(path.join(dir, 'root.crt'), 'utf8');
  assert(ecCA.parseRoot(key, cert).ca);
  ['example.com', '*.example.com', '127.0.0.1', '::1'].forEach(function (host) {
    var leaf = ecCA.createCertificate(host, key, cert);
    var x509 = new crypto.X509Certificate(leaf.cert);
    assert(x509.verify(new crypto.X509Certificate(cert).publicKey));
    assert(x509.subjectAltName);
    assert(crypto.createPrivateKey(leaf.key));
    assert(!x509.ca);
  });
  assert.throws(function () { ecCA.createCertificate('example.com\nCA:TRUE', key, cert); });
  var wrong = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey
    .export({ type: 'sec1', format: 'pem' });
  assert.throws(function () { ecCA.parseRoot(wrong, cert); });
  process.stdout.write('EC CA tests passed\n');
} finally {
  fs.readdirSync(dir).forEach(function (file) { fs.unlinkSync(path.join(dir, file)); });
  fs.rmdirSync(dir);
}
