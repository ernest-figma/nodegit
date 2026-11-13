'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createRequire } = require('module');
const { spawnSync } = require('child_process');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

if (process.env.RELEASE_PROOF_PRELOAD === '1') {
  const record = event => fs.appendFileSync(process.env.RELEASE_PROOF_EVENTS, JSON.stringify(event) + '\n');
  const deny = () => {
    record({ type: 'network-attempt' });
    throw new Error('Release proof blocked a network attempt');
  };
  for (const name of ['http', 'https']) {
    const module = require(name);
    module.request = deny;
    module.get = deny;
  }
  const net = require('net');
  net.connect = deny;
  net.createConnection = deny;
  net.Socket.prototype.connect = deny;
  require('tls').connect = deny;
  global.fetch = deny;

  const originalLstat = fs.lstat;
  fs.lstat = function (file, ...args) {
    const callback = args.pop();
    return originalLstat.call(this, file, ...args, (error, stat) => {
      if (path.resolve(String(file)) === process.env.RELEASE_PROOF_DELAY_PATH) {
        record({ type: 'forced-stat-delay', file: String(file) });
        setTimeout(() => callback(error, stat), 20);
      } else callback(error, stat);
    });
  };

  const Module = require('module');
  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request !== 'aws-sdk') return originalLoad.call(this, request, parent, isMain);
    const resolved = Module._resolveFilename(request, parent);
    assert.equal(fs.realpathSync(resolved), process.env.RELEASE_PROOF_AWS);
    return {
      config: { update(config) { record({ type: 'aws-config', config }); } },
      S3: class {
        headObject(options, callback) {
          record({ type: 'headObject', ...options });
          callback(Object.assign(new Error('Mock object absent'), { code: 'NotFound' }));
        }
        putObject(options, callback) {
          const chunks = [];
          options.Body.on('data', chunk => chunks.push(chunk));
          options.Body.on('error', callback);
          options.Body.on('end', () => {
            const archive = Buffer.concat(chunks);
            record({ type: 'mock-publish', Bucket: options.Bucket, Key: options.Key,
              ACL: options.ACL, bytes: archive.length, sha256: sha256(archive) });
            callback(null, { mock: true });
          });
        }
      }
    };
  };
} else if (require.main === module) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
}

async function main() {
  const repo = fs.realpathSync(process.argv[2] || process.cwd());
  const oldRoot = fs.realpathSync(process.argv[3] || path.join(process.env.RUNNER_TEMP, 'old-packager'));
  const output = path.resolve(process.env.RELEASE_PROOF_OUTPUT || path.join(process.env.RUNNER_TEMP || '/tmp', 'release-proof'));
  fs.mkdirSync(output, { recursive: true });
  const localRequire = createRequire(path.join(repo, 'package.json'));
  const oldRequire = createRequire(path.join(oldRoot, 'package.json'));
  const fixedRoot = path.dirname(localRequire.resolve('@mapbox/node-pre-gyp/package.json'));
  const fixedRequire = createRequire(path.join(fixedRoot, 'package.json'));
  const oldToolRoot = path.dirname(oldRequire.resolve('@mapbox/node-pre-gyp/package.json'));
  const oldToolRequire = createRequire(path.join(oldToolRoot, 'package.json'));
  assert.equal(localRequire('@mapbox/node-pre-gyp/package.json').version, '1.0.8');
  assert.equal(fixedRequire('tar/package.json').version, '6.2.1');
  assert.equal(oldRequire('@mapbox/node-pre-gyp/package.json').version, '2.0.3');
  assert.equal(oldToolRequire('tar/package.json').version, '7.5.23');
  const aws = fs.realpathSync(localRequire.resolve('aws-sdk'));
  assert(aws.startsWith(fs.realpathSync(path.join(repo, 'node_modules')) + path.sep), 'AWS SDK must be local');

  const workflow = fs.readFileSync(path.join(repo, '.github/workflows/tests.yml'), 'utf8');
  const deploys = [...workflow.matchAll(/^      - name: Deploy\n(?:        .*\n)*?        run: \|\n((?:          .*(?:\n|$))+)/gm)]
    .map(match => match[1].split('\n').filter(Boolean).map(line => line.slice(10)).join('\n'));
  assert.equal(deploys.length, 2, 'Expected both production Deploy bodies');
  assert.equal(deploys[0], deploys[1], 'Deploy bodies differ');
  assert.deepEqual(deploys[0].split('\n'), [
    'node lifecycleScripts/clean',
    'rm -f build/Release/obj.target/nodegit.node',
    './node_modules/.bin/node-pre-gyp package',
    './node_modules/.bin/node-pre-gyp publish'
  ], 'Unexpected production Deploy commands');
  fs.writeFileSync(path.join(output, 'actual-deploy.sh'), 'set -eu\n' + deploys[0] + '\n');

  const binary = fs.readFileSync(path.join(repo, 'build/Release/nodegit.node'));
  assert(binary.length > 0, 'Compiled module is empty');
  const binaryHash = sha256(binary);
  const eventsFile = path.join(output, 'events.jsonl');
  fs.writeFileSync(eventsFile, '');
  const childEnv = { ...process.env,
    RELEASE_PROOF_PRELOAD: '1', RELEASE_PROOF_EVENTS: eventsFile, RELEASE_PROOF_AWS: aws,
    AWS_EC2_METADATA_DISABLED: 'true', AWS_SHARED_CREDENTIALS_FILE: path.join(output, 'no-credentials'),
    AWS_CONFIG_FILE: path.join(output, 'no-config'), AWS_SDK_LOAD_CONFIG: '0',
    NODE_OPTIONS: '--require=' + JSON.stringify(__filename)
  };
  for (const key of Object.keys(childEnv)) {
    if (/^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN|PROFILE|DEFAULT_PROFILE|WEB_IDENTITY_TOKEN_FILE|ROLE_ARN|CONTAINER_CREDENTIALS.*)$/.test(key)) delete childEnv[key];
  }
  delete childEnv.node_pre_gyp_mock_s3;

  for (const protocol of ['http', 'https']) {
    const guard = run('network-guard-' + protocol, process.execPath,
      ['-e', `require('${protocol}').get('${protocol}://127.0.0.1:9/')`], repo, childEnv, false);
    assert.notEqual(guard.status, 0, protocol + ' guard did not fail');
    assert.match(guard.stderr, /Release proof blocked a network attempt/);
  }
  const guardEvents = fs.readFileSync(eventsFile, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.equal(guardEvents.filter(event => event.type === 'network-attempt').length, 2);
  fs.renameSync(eventsFile, path.join(output, 'network-guard-events.jsonl'));
  fs.writeFileSync(eventsFile, '');

  const fixture = path.join(output, 'hardlink-fixture');
  fs.mkdirSync(path.join(fixture, 'lifecycleScripts'), { recursive: true });
  fs.copyFileSync(path.join(repo, 'package.json'), path.join(fixture, 'package.json'));
  fs.copyFileSync(path.join(repo, 'lifecycleScripts/clean.js'), path.join(fixture, 'lifecycleScripts/clean.js'));
  const fixtureModules = path.join(fixture, 'node_modules');
  if (!fs.existsSync(fixtureModules)) fs.symlinkSync(path.join(repo, 'node_modules'), fixtureModules, 'dir');
  const first = restoreHardlinks(fixture);
  const raceEnv = { ...childEnv, RELEASE_PROOF_DELAY_PATH: first };
  const old = run('negative-control', process.execPath, [path.join(oldToolRoot, 'bin/node-pre-gyp'), 'package'], fixture, raceEnv, false);
  assert.notEqual(old.status, 0, 'Negative control unexpectedly passed');
  assert.match(old.stdout + old.stderr, /ZlibError: zlib: stream error/, 'Wrong negative-control error');
  const negativeEvents = readEvents();
  assert(negativeEvents.some(event => event.type === 'forced-stat-delay'), 'Negative control did not force stat timing');
  assert(!negativeEvents.some(event => event.type === 'network-attempt'), 'Negative control attempted network access');
  fs.renameSync(eventsFile, path.join(output, 'negative-control-events.jsonl'));

  const pkg = localRequire('./package.json');
  const expectedName = `nodegit-v${pkg.version}-node-v${process.versions.modules}-${process.platform}-${process.arch}.tar.gz`;
  const archiveRelative = path.join('build/stage', expectedName);
  const passes = [];
  for (const [timing, cwd] of [['FORCEDTIMING', fixture], ['NORMALTIMING', repo]]) {
    const primary = restoreHardlinks(cwd);
    fs.writeFileSync(eventsFile, '');
    const env = { ...childEnv };
    delete env.RELEASE_PROOF_DELAY_PATH;
    if (timing === 'FORCEDTIMING') env.RELEASE_PROOF_DELAY_PATH = primary;
    run('actual-deploy-' + timing, 'bash', [path.join(output, 'actual-deploy.sh')], cwd, env);
    assert(!fs.existsSync(path.join(cwd, 'build/Release/obj.target/nodegit.node')), timing + ' retained the intermediate alias');
    assert.equal(sha256(fs.readFileSync(primary)), binaryHash, timing + ' changed the primary binary');
    const archivePath = path.join(cwd, archiveRelative);
    await checkArchive(archivePath, path.join(output, 'release-extract-' + timing));
    const archive = fs.readFileSync(archivePath);
    const events = readEvents();
    assert(!events.some(event => event.type === 'network-attempt'), timing + ' attempted network access');
    assert.equal(events.some(event => event.type === 'forced-stat-delay'), timing === 'FORCEDTIMING', timing + ' stat timing mismatch');
    const heads = events.filter(event => event.type === 'headObject');
    const puts = events.filter(event => event.type === 'mock-publish');
    assert.equal(heads.length, 1);
    assert.equal(puts.length, 1);
    assert.equal(heads[0].Bucket, 'figma-nodegit');
    assert.equal(heads[0].Key, expectedName);
    assert.equal(puts[0].Bucket, heads[0].Bucket);
    assert.equal(puts[0].Key, expectedName);
    assert.equal(puts[0].ACL, 'public-read');
    assert.equal(puts[0].sha256, sha256(archive));
    assert.equal(puts[0].bytes, archive.length);
    fs.renameSync(eventsFile, path.join(output, 'events-' + timing + '.jsonl'));
    passes.push({ timing, extraction: 'passed', binarySha256: binaryHash,
      intermediateAliasRemoved: true, ...puts[0] });
  }
  const commit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
  assert.equal(commit.status, 0);
  const diagnostic = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: path.dirname(__filename), encoding: 'utf8' });
  const diagnosticCommit = diagnostic.status === 0 ? diagnostic.stdout.trim() : process.env.RELEASE_PROOF_DIAGNOSTIC_COMMIT;
  assert.match(diagnosticCommit || '', /^[0-9a-f]{40}$/);
  if (process.env.GITHUB_SHA) assert.equal(diagnosticCommit, process.env.GITHUB_SHA);
  const report = { productCommit: commit.stdout.trim(), diagnosticCommit, networkGuardSelfTest: 'HTTP and HTTPS blocked', node: process.version, abi: process.versions.modules,
    platform: process.platform, arch: process.arch, binarySha256: binaryHash, archiveName: expectedName,
    fixedTool: '1.0.8', fixedTar: '6.2.1', negativeTool: '2.0.3', negativeTar: '7.5.23',
    negativeControl: 'expected ZlibError under forced stat timing',
    actualDeployBodySha256: sha256(Buffer.from(deploys[0])),
    publish: 'LOCAL MOCK ONLY', networkAttempts: 0, passes };
  fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));

  function restoreHardlinks(cwd) {
    const release = path.join(cwd, 'build/Release');
    fs.mkdirSync(path.join(release, 'obj.target'), { recursive: true });
    const primary = path.join(release, 'nodegit.node');
    const alias = path.join(release, 'obj.target/nodegit.node');
    if (fs.existsSync(alias)) fs.unlinkSync(alias);
    fs.writeFileSync(primary, binary);
    fs.linkSync(primary, alias);
    assert.equal(fs.statSync(primary).ino, fs.statSync(alias).ino);
    assert.equal(sha256(fs.readFileSync(alias)), binaryHash);
    return primary;
  }
  function readEvents() {
    return fs.readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  }
  function run(label, command, args, cwd, env, mustPass = true) {
    const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    fs.writeFileSync(path.join(output, label + '.log'), String(result.stdout || '') + String(result.stderr || ''));
    if (result.error) throw result.error;
    if (mustPass) assert.equal(result.status, 0, label + ' failed. See ' + output);
    return result;
  }
  async function checkArchive(file, extract) {
    assert(fs.existsSync(file), 'Wrong or missing archive filename');
    fs.rmSync(extract, { recursive: true, force: true });
    fs.mkdirSync(extract, { recursive: true });
    await fixedRequire('tar').x({ file, cwd: extract });
    assert.equal(sha256(fs.readFileSync(path.join(extract, 'Release/nodegit.node'))), binaryHash, 'Packed binary differs');
  }
}
